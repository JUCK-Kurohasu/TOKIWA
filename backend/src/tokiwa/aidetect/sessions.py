"""In-memory actor-session tracker (bounded, synchronous, no I/O).

Session key = ``source_ip`` + client fingerprint (UA + stable header names, see :mod:`fingerprints`). A session
ends after ``idle_timeout_s`` of *event time* without activity (event time, not wall clock, so replayed datasets
sessionize the same way as live traffic).

Bounds (memory is O(max_sessions * max_obs) small records):
- at most ``max_sessions`` live sessions (LRU eviction; dirty evicted sessions are kept until the next flush);
- at most ``max_obs`` request observations per session (sliding window — features describe recent behaviour,
  counters such as ``request_count`` are whole-session);
- at most ``max_endpoints`` endpoints remembered for mutation analysis, 10k path hashes for ``unique_paths``.

Scores are recomputed once per touched session per batch (not per event). Large sessions receiving a trickle of
events are rescored at most every ``RESCORE_MIN_INTERVAL_S`` and always before persistence.

``ai_score`` is the session's *peak* score and an ``ai_agent`` verdict is sticky: an agent that slows down later
does not lose its attribution. The current-window score is kept in ``features["ai_score_current"]``.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from tokiwa.aidetect.features import RequestObs, SessionExtras, annotate, compute_features, observe_http
from tokiwa.aidetect.fingerprints import ClientFamily, FingerprintInfo, fingerprint_info
from tokiwa.aidetect.scoring import DEFAULT_AI_THRESHOLD, score_features
from tokiwa.schemas.common import ActorType
from tokiwa.schemas.events import Event, EventKind
from tokiwa.util import new_id

RESCORE_BIG_SESSION = 128
RESCORE_MIN_NEW_OBS = 8
RESCORE_MIN_INTERVAL_S = 2.0
MAX_PATH_HASHES = 10_000
RECENT_EVENT_IDS = 64
LLM_APP_FINGERPRINT = "llm_app"


@dataclass(slots=True)
class LiveSession:
    id: str
    key: str
    source_ip: str
    fp: FingerprintInfo
    user_agent: str | None
    first_seen: datetime
    last_seen: datetime
    max_obs: int
    request_count: int = 0
    error_count: int = 0
    path_hashes: set[int] = field(default_factory=set)
    obs: deque[RequestObs] = field(default_factory=deque)
    last_by_endpoint: OrderedDict[str, RequestObs] = field(default_factory=OrderedDict)
    recent_event_ids: deque[str] = field(default_factory=lambda: deque(maxlen=RECENT_EVENT_IDS))
    extras: SessionExtras = field(default_factory=SessionExtras)
    features: dict[str, Any] = field(default_factory=dict)
    ai_score: float = 0.0  # peak
    ai_score_current: float = 0.0
    classification: ActorType = ActorType.UNKNOWN
    indicators: list[dict[str, Any]] = field(default_factory=list)
    version: int = 0
    dirty: bool = True
    stale: bool = False
    new_since_rescore: int = 0
    last_rescore_mono: float = 0.0

    @property
    def unique_paths(self) -> int:
        return len(self.path_hashes)


@dataclass(frozen=True, slots=True)
class SessionSnapshot:
    """Persistable view (matches ``ActorSessionRow`` minus ``incident_id``, which correlate owns)."""

    id: str
    source_ip: str
    client_fingerprint: str
    user_agent: str | None
    first_seen: datetime
    last_seen: datetime
    request_count: int
    error_count: int
    unique_paths: int
    features: dict[str, Any]
    ai_score: float
    classification: str

    @classmethod
    def of(cls, s: LiveSession) -> SessionSnapshot:
        return cls(
            id=s.id,
            source_ip=s.source_ip,
            client_fingerprint=s.fp.fingerprint,
            user_agent=s.user_agent[:1024] if s.user_agent else None,
            first_seen=s.first_seen,
            last_seen=s.last_seen,
            request_count=s.request_count,
            error_count=s.error_count,
            unique_paths=s.unique_paths,
            features=s.features,
            ai_score=s.ai_score,
            classification=str(s.classification),
        )


class SessionTracker:
    def __init__(
        self,
        *,
        idle_timeout_s: float = 1800.0,
        threshold: float = DEFAULT_AI_THRESHOLD,
        max_sessions: int = 4096,
        max_obs: int = 256,
        max_endpoints: int = 128,
    ) -> None:
        self.idle_timeout_s = float(idle_timeout_s)
        self.threshold = threshold
        self.max_sessions = max_sessions
        self.max_obs = max_obs
        self.max_endpoints = max_endpoints
        self._by_key: OrderedDict[str, LiveSession] = OrderedDict()
        self._by_id: dict[str, LiveSession] = {}
        self._by_ip: dict[str, set[str]] = {}
        self._pending: dict[str, SessionSnapshot] = {}
        self.max_event_ts = 0.0
        self.significant_change = False
        self.stats = {"created": 0, "evicted": 0, "expired": 0, "rescored": 0}

    # ------------------------------------------------------------------ lookup
    def __len__(self) -> int:
        return len(self._by_key)

    def get(self, session_id: str | None) -> LiveSession | None:
        return self._by_id.get(session_id) if session_id else None

    def sessions(self) -> list[LiveSession]:
        return list(self._by_key.values())

    @property
    def dirty_count(self) -> int:
        return len(self._pending) + sum(1 for s in self._by_key.values() if s.dirty)

    # ------------------------------------------------------------------ lifecycle
    def _create(self, key: str, ip: str, fp: FingerprintInfo, ua: str | None, ts: datetime) -> LiveSession:
        s = LiveSession(
            id=new_id(),
            key=key,
            source_ip=ip,
            fp=fp,
            user_agent=ua,
            first_seen=ts,
            last_seen=ts,
            max_obs=self.max_obs,
        )
        s.obs = deque(maxlen=self.max_obs)
        self._by_key[key] = s
        self._by_id[s.id] = s
        self._by_ip.setdefault(ip, set()).add(key)
        self.stats["created"] += 1
        while len(self._by_key) > self.max_sessions:
            _, old = next(iter(self._by_key.items()))
            self._finalize(old)
            self.stats["evicted"] += 1
        return s

    def _finalize(self, s: LiveSession) -> None:
        if s.dirty or s.stale:
            if s.stale or s.new_since_rescore:
                self._rescore(s, force=True)
            self._pending[s.id] = SessionSnapshot.of(s)
        self._by_key.pop(s.key, None)
        self._by_id.pop(s.id, None)
        keys = self._by_ip.get(s.source_ip)
        if keys is not None:
            keys.discard(s.key)
            if not keys:
                self._by_ip.pop(s.source_ip, None)

    def expire_idle(self) -> int:
        cutoff = self.max_event_ts - self.idle_timeout_s
        expired = [s for s in self._by_key.values() if s.last_seen.timestamp() < cutoff]
        for s in expired:
            self._finalize(s)
        self.stats["expired"] += len(expired)
        return len(expired)

    # ------------------------------------------------------------------ observation
    def _session_for_http(self, e: Event) -> LiveSession | None:
        ip = e.source_ip
        h = e.http
        if not ip or h is None:
            return None
        ua = h.user_agent or (h.headers or {}).get("user-agent")
        fp = fingerprint_info(ua, h.headers, scheme=h.scheme, header_order=h.header_order)
        key = f"{ip}|{fp.fingerprint}"
        s = self._by_key.get(key)
        ts = e.timestamp
        if s is not None and ts.timestamp() - s.last_seen.timestamp() > self.idle_timeout_s:
            self._finalize(s)
            s = None
        if s is None:
            s = self._create(key, ip, fp, ua, ts)
        else:
            self._by_key.move_to_end(key)
            if fp.anomalies != s.fp.anomalies and len(fp.anomalies) > len(s.fp.anomalies):
                s.fp = fp  # richer header capture later in the session
        return s

    def _recent_for_ip(self, ip: str, ts: float) -> LiveSession | None:
        best: LiveSession | None = None
        for key in self._by_ip.get(ip, ()):
            s = self._by_key.get(key)
            if s is None or ts - s.last_seen.timestamp() > self.idle_timeout_s:
                continue
            if best is None or s.last_seen > best.last_seen:
                best = s
        return best

    def _add_obs(self, s: LiveSession, o: RequestObs) -> None:
        prev = s.last_by_endpoint.get(o.endpoint)
        annotate(prev, o)
        if prev is not None:
            prev.payload_sig = ""  # only the latest request per endpoint needs its payload signature
        s.last_by_endpoint[o.endpoint] = o
        s.last_by_endpoint.move_to_end(o.endpoint)
        while len(s.last_by_endpoint) > self.max_endpoints:
            _, dropped = s.last_by_endpoint.popitem(last=False)
            dropped.payload_sig = ""
        if s.obs and o.t < s.obs[-1].t:
            # late event: insert in time order (scan a few positions from the end; otherwise append)
            idx = len(s.obs)
            steps = 0
            while idx > 0 and s.obs[idx - 1].t > o.t and steps < 16:
                idx -= 1
                steps += 1
            if len(s.obs) == s.obs.maxlen and idx == 0:
                return  # older than everything in a full window
            if len(s.obs) == s.obs.maxlen:
                s.obs.popleft()
                idx -= 1
            s.obs.insert(max(idx, 0), o)
        else:
            s.obs.append(o)

    def _observe_http(self, e: Event) -> LiveSession | None:
        s = self._session_for_http(e)
        if s is None:
            return None
        e.session_id = s.id
        h = e.http
        assert h is not None
        if e.timestamp > s.last_seen:
            s.last_seen = e.timestamp
        s.request_count += 1
        if h.status is not None and h.status >= 400:
            s.error_count += 1
        if len(s.path_hashes) < MAX_PATH_HASHES:
            s.path_hashes.add(hash((h.path or "/").split("?", 1)[0]))
        o = observe_http(e)
        if o is not None:
            self._add_obs(s, o)
        s.recent_event_ids.append(e.id)
        s.dirty = True
        s.new_since_rescore += 1
        return s

    def _observe_other(self, e: Event) -> LiveSession | None:
        ip = e.source_ip
        if not ip:
            return None
        ts = e.timestamp
        s = self._recent_for_ip(ip, ts.timestamp())
        if s is None and e.kind == EventKind.LLM_APP:
            key = f"{ip}|{LLM_APP_FINGERPRINT}"
            s = self._by_key.get(key)
            if s is not None and ts.timestamp() - s.last_seen.timestamp() > self.idle_timeout_s:
                self._finalize(s)
                s = None
            if s is None:
                fp = FingerprintInfo(LLM_APP_FINGERPRINT, ClientFamily.UNKNOWN, None, False, (), (), ())
                s = self._create(key, ip, fp, None, ts)
        if s is None:
            return None
        e.session_id = s.id
        if ts > s.last_seen:
            s.last_seen = ts
        if e.kind == EventKind.DECEPTION:
            kind = (e.deception.asset_kind if e.deception else None) or "unknown"
            if kind == "ai_canary":
                s.extras.canary_hits += 1
            else:
                s.extras.decoy_hits += 1
            if len(s.extras.deception_kinds) < 16:
                s.extras.deception_kinds.append(kind)
        elif e.kind == EventKind.LLM_APP:
            s.extras.llm_app_prompts += 1
        s.recent_event_ids.append(e.id)
        s.dirty = True
        s.new_since_rescore += 1
        return s

    def observe_batch(self, events: Iterable[Event]) -> list[LiveSession]:
        """Assign ``session_id`` to every event that has a source IP and rescore touched sessions once."""
        evs = list(events)
        self.significant_change = False
        touched: dict[str, LiveSession] = {}
        # HTTP first (they create sessions), then other kinds that attach to the most recent session of the IP.
        http = sorted((e for e in evs if e.kind == EventKind.HTTP), key=lambda e: e.timestamp)
        other = sorted((e for e in evs if e.kind != EventKind.HTTP), key=lambda e: e.timestamp)
        for e in http:
            self.max_event_ts = max(self.max_event_ts, e.timestamp.timestamp())
            s = self._observe_http(e)
            if s is not None:
                touched[s.id] = s
        for e in other:
            self.max_event_ts = max(self.max_event_ts, e.timestamp.timestamp())
            s = self._observe_other(e)
            if s is not None:
                touched[s.id] = s
        for s in touched.values():
            if s.id in self._by_id:  # may have been evicted within this batch
                self._rescore(s)
        return [s for s in touched.values() if s.id in self._by_id]

    # ------------------------------------------------------------------ scoring
    def _tool_fingerprints(self, s: LiveSession) -> int:
        fps: set[str] = set()
        ref = s.last_seen.timestamp()
        for key in self._by_ip.get(s.source_ip, ()):
            o = self._by_key.get(key)
            if o is None or abs(ref - o.last_seen.timestamp()) > self.idle_timeout_s:
                continue
            if (
                o.fp.family not in (ClientFamily.BROWSER, ClientFamily.BOT)
                and o.fp.fingerprint != LLM_APP_FINGERPRINT
            ):
                fps.add(o.fp.fingerprint)
        return max(1, len(fps))

    def _rescore(self, s: LiveSession, *, force: bool = False) -> None:
        now = time.monotonic()
        if (
            not force
            and len(s.obs) >= RESCORE_BIG_SESSION
            and s.new_since_rescore < RESCORE_MIN_NEW_OBS
            and now - s.last_rescore_mono < RESCORE_MIN_INTERVAL_S
        ):
            s.stale = True
            return
        s.extras.ip_tool_fingerprints = self._tool_fingerprints(s)
        s.extras.request_count_total = s.request_count
        s.extras.unique_paths_total = s.unique_paths
        feats = compute_features(list(s.obs), fp=s.fp, extras=s.extras)
        res = score_features(feats, threshold=self.threshold)
        prev_cls = s.classification
        s.ai_score_current = res.ai_score
        if res.ai_score >= s.ai_score:
            s.ai_score = res.ai_score
            s.indicators = res.indicators
        cls = ActorType.AI_AGENT if s.ai_score >= self.threshold else res.classification
        s.classification = cls
        feats.update(res.as_features())
        feats["ai_score_current"] = res.ai_score
        feats["ai_score_peak"] = s.ai_score
        feats["request_count_total"] = s.request_count
        feats["unique_paths_total"] = s.unique_paths
        if s.ai_score > res.ai_score + 0.1:
            feats["peak_indicators"] = s.indicators
        s.features = feats
        s.version += 1
        s.dirty = True
        s.stale = False
        s.new_since_rescore = 0
        s.last_rescore_mono = now
        self.stats["rescored"] += 1
        if cls != prev_cls:
            self.significant_change = True

    # ------------------------------------------------------------------ persistence hand-off
    def drain_dirty(self) -> list[SessionSnapshot]:
        """Snapshots of everything that changed since the last drain (rescoring stale sessions first)."""
        self.expire_idle()
        out = dict(self._pending)
        self._pending.clear()
        for s in self._by_key.values():
            if s.stale:
                self._rescore(s, force=True)
            if s.dirty:
                out[s.id] = SessionSnapshot.of(s)
                s.dirty = False
        return list(out.values())

    def requeue(self, snaps: Iterable[SessionSnapshot]) -> None:
        """Put snapshots back after a failed persistence attempt (newer live state wins)."""
        for snap in snaps:
            live = self._by_id.get(snap.id)
            if live is not None:
                live.dirty = True
            else:
                self._pending.setdefault(snap.id, snap)


_current: SessionTracker | None = None


def current_tracker() -> SessionTracker | None:
    """The tracker owned by the active sessionizer enricher (``None`` when the sessionizer is not loaded)."""
    return _current


def set_current_tracker(tracker: SessionTracker | None) -> None:
    global _current
    _current = tracker
