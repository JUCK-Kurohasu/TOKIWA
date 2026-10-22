"""Labelled datasets: generation (offline simulator), JSONL I/O, ground truth extraction.

Format: one :class:`~tokiwa.schemas.events.Event` per line (``model_dump(mode="json", exclude_none=True)``). Ground
truth lives in ``event.labels``::

    {"actor": "ai_agent", "profile": "ai_agent", "session": "ai_agent-01", "attack": "sqli", "phase": "exploit"}

``actor`` uses :class:`tokiwa.schemas.common.ActorType` values; ``attack == "none"`` marks non-malicious requests.
A sidecar ``<name>.meta.json`` records how the file was produced (seed, mix, generator version) for reproducibility.

The harness strips labels before replay (:func:`split_truth`) so detectors and the LLM never see them.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from tokiwa import __version__
from tokiwa.eval.profiles import DEFAULT_MIX
from tokiwa.eval.sim import DEFAULT_START, build_plans, exchanges_to_events, simulate_offline
from tokiwa.eval.virtual import VirtualLab
from tokiwa.schemas.events import Event

GENERATOR_VERSION = "1"
LABEL_KEYS = ("actor", "profile", "session", "attack", "phase")
# Tags that may carry ground truth and must not reach the pipeline
_TRUTH_TAG_PREFIXES = ("sim:", "label:", "truth:")


async def generate_events(
    mix: dict[str, int] | None = None,
    *,
    seed: int = 1,
    start: datetime = DEFAULT_START,
    spread_seconds: float = 1800.0,
    canary: bool = True,
    max_requests_per_session: int = 400,
) -> list[Event]:
    """Run the offline simulator and return labelled events (deterministic for a given seed/start/mix)."""
    plans = build_plans(dict(mix or DEFAULT_MIX), seed=seed, spread_seconds=spread_seconds)
    exchanges = await simulate_offline(
        plans, start=start, lab=VirtualLab(canary=canary), max_requests_per_session=max_requests_per_session
    )
    return exchanges_to_events(exchanges, seed=seed)


def write_dataset(path: Path, events: Iterable[Event], meta: dict[str, Any] | None = None) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    events = list(events)
    with path.open("w", encoding="utf-8") as fh:
        for e in events:
            fh.write(
                json.dumps(e.model_dump(mode="json", exclude_none=True), ensure_ascii=False, sort_keys=True)
            )
            fh.write("\n")
    info = {
        "generator_version": GENERATOR_VERSION,
        "tokiwa_version": __version__,
        **(meta or {}),
        "summary": dataset_summary(events),
    }
    meta_path(path).write_text(json.dumps(info, ensure_ascii=False, indent=2, sort_keys=True) + "\n", "utf-8")
    return info


def meta_path(path: Path) -> Path:
    return path.with_name(path.name.removesuffix(".jsonl") + ".meta.json")


def read_dataset(path: Path) -> list[Event]:
    events: list[Event] = []
    with path.open(encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(Event.model_validate_json(line))
            except ValueError as exc:
                raise ValueError(f"{path}:{n}: invalid event: {exc}") from exc
    return events


@dataclass
class SessionTruth:
    session: str
    actor: str
    profile: str
    event_ids: list[str] = field(default_factory=list)
    source_ips: set[str] = field(default_factory=set)
    attacks: Counter[str] = field(default_factory=Counter)

    @property
    def is_attack(self) -> bool:
        return self.actor != "benign"

    @property
    def is_ai(self) -> bool:
        return self.actor == "ai_agent"


@dataclass
class Truth:
    """Ground truth extracted from labels, indexed for the metric computations."""

    by_event: dict[str, dict[str, str]]
    sessions: dict[str, SessionTruth]

    @classmethod
    def from_events(cls, events: Iterable[Event]) -> Truth:
        by_event: dict[str, dict[str, str]] = {}
        sessions: dict[str, SessionTruth] = {}
        for e in events:
            labels = {k: v for k, v in e.labels.items() if k in LABEL_KEYS}
            if not labels:
                continue
            labels.setdefault("actor", "unknown")
            labels.setdefault("attack", "none")
            sess_id = labels.get("session") or f"ip:{e.source_ip or '-'}"
            labels["session"] = sess_id
            by_event[e.id] = labels
            st = sessions.get(sess_id)
            if st is None:
                st = sessions[sess_id] = SessionTruth(
                    session=sess_id, actor=labels["actor"], profile=labels.get("profile", labels["actor"])
                )
            st.event_ids.append(e.id)
            if e.source_ip:
                st.source_ips.add(e.source_ip)
            st.attacks[labels["attack"]] += 1
        return cls(by_event=by_event, sessions=sessions)

    def session_of(self, event_id: str) -> SessionTruth | None:
        labels = self.by_event.get(event_id)
        return self.sessions.get(labels["session"]) if labels else None

    def sessions_by_ip(self) -> dict[str, list[SessionTruth]]:
        out: dict[str, list[SessionTruth]] = defaultdict(list)
        for st in self.sessions.values():
            for ip in st.source_ips:
                out[ip].append(st)
        return out


def split_truth(events: Iterable[Event]) -> tuple[list[Event], Truth]:
    """Return (label-free deep copies for replay, ground truth)."""
    originals = list(events)
    truth = Truth.from_events(originals)
    clean: list[Event] = []
    for e in originals:
        c = e.model_copy(deep=True)
        c.labels = {}
        c.tags = [t for t in c.tags if not t.startswith(_TRUTH_TAG_PREFIXES)]
        clean.append(c)
    return clean, truth


def dataset_summary(events: Iterable[Event]) -> dict[str, Any]:
    events = list(events)
    truth = Truth.from_events(events)
    by_profile: Counter[str] = Counter()
    by_attack: Counter[str] = Counter()
    for labels in truth.by_event.values():
        by_profile[labels.get("profile", labels.get("actor", "unknown"))] += 1
        by_attack[labels.get("attack", "none")] += 1
    sessions_by_profile = Counter(st.profile for st in truth.sessions.values())
    ts = [e.timestamp for e in events]
    return {
        "events": len(events),
        "labelled_events": len(truth.by_event),
        "sessions": len(truth.sessions),
        "events_by_profile": dict(sorted(by_profile.items())),
        "events_by_attack": dict(sorted(by_attack.items())),
        "sessions_by_profile": dict(sorted(sessions_by_profile.items())),
        "first": min(ts).isoformat() if ts else None,
        "last": max(ts).isoformat() if ts else None,
    }
