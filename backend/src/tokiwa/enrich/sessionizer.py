"""Sessionizer enricher: assigns ``event.session_id`` and maintains actor-session features / AI scores.

Fast path (inside ``enrich``, no I/O): :class:`tokiwa.aidetect.sessions.SessionTracker` assigns sessions and rescores
touched sessions once per batch. Persistence to ``actor_sessions`` is *batched*: one upsert transaction when
``flush_interval_seconds`` elapsed, ``flush_max_dirty`` sessions are dirty, or a session's classification changed;
plus a periodic job (``aidetect.sessions_flush``), a shutdown hook, and an explicit ``flush_current()`` that the
sessions API calls before reading (read-your-writes for the UI).

The ``incident_id`` column is owned by correlate and is never overwritten here.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence

from sqlalchemy import select

from tokiwa.aidetect.sessions import SessionSnapshot, SessionTracker, set_current_tracker
from tokiwa.config import get_settings
from tokiwa.db.models.telemetry import ActorSessionRow
from tokiwa.db.session import session_scope
from tokiwa.enrich.base import Enricher, register_enricher
from tokiwa.runtime import on_shutdown, periodic
from tokiwa.schemas.events import Event

log = logging.getLogger(__name__)

_UPSERT_CHUNK = 400


async def persist_snapshots(snaps: Sequence[SessionSnapshot]) -> int:
    """Upsert session snapshots in one transaction (chunked IN-queries). Returns rows written."""
    if not snaps:
        return 0
    async with session_scope() as db:
        for i in range(0, len(snaps), _UPSERT_CHUNK):
            chunk = snaps[i : i + _UPSERT_CHUNK]
            ids = [s.id for s in chunk]
            rows = (
                (await db.execute(select(ActorSessionRow).where(ActorSessionRow.id.in_(ids)))).scalars().all()
            )
            existing = {r.id: r for r in rows}
            for s in chunk:
                row = existing.get(s.id)
                if row is None:
                    db.add(
                        ActorSessionRow(
                            id=s.id,
                            source_ip=s.source_ip,
                            client_fingerprint=s.client_fingerprint,
                            user_agent=s.user_agent,
                            first_seen=s.first_seen,
                            last_seen=s.last_seen,
                            request_count=s.request_count,
                            error_count=s.error_count,
                            unique_paths=s.unique_paths,
                            features=s.features,
                            ai_score=s.ai_score,
                            classification=s.classification,
                        )
                    )
                else:
                    row.user_agent = s.user_agent
                    row.first_seen = min(row.first_seen, s.first_seen)
                    row.last_seen = max(row.last_seen, s.last_seen)
                    row.request_count = s.request_count
                    row.error_count = s.error_count
                    row.unique_paths = s.unique_paths
                    row.features = s.features
                    row.ai_score = max(row.ai_score or 0.0, s.ai_score)
                    row.classification = s.classification
        await db.flush()
    return len(snaps)


@register_enricher
class Sessionizer(Enricher):
    id = "sessionizer"
    order = 50
    # Tunables (class attributes so tests can override without touching shared config). ``max_sessions`` None ->
    # ``detection.max_live_sessions``.
    max_sessions: int | None = None
    max_obs = 256
    flush_interval_seconds = 1.0
    flush_max_dirty = 256
    # Eviction-pressure warning (audit #88): evictions counted over this window; warn at most every interval.
    eviction_window_seconds = 60.0
    eviction_warn_interval_seconds = 300.0

    def __init__(self) -> None:
        det = get_settings().detection
        self.tracker = SessionTracker(
            idle_timeout_s=det.session_idle_timeout_seconds,
            threshold=det.ai_agent_threshold,
            max_sessions=self.max_sessions if self.max_sessions is not None else det.max_live_sessions,
            max_obs=self.max_obs,
            max_future_skew_s=det.max_future_skew_seconds,
        )
        self._lock = asyncio.Lock()
        self._last_flush = time.monotonic()
        self._evict_mark = (
            self._last_flush,
            0,
            0,
        )  # (window start, evicted, evicted_valuable) at window start
        self._last_evict_warn = float("-inf")
        set_current_tracker(self.tracker)

    def check_eviction_pressure(self, now: float | None = None) -> bool:
        """Warn when the live-session table is being churned (a flood of one-shot clients, or an undersized limit).

        Returns True when a warning was logged. Evictions themselves are expected under load; what matters is the
        rate and whether sessions with evidence had to go (``evicted_valuable``), which is how a flood would erase
        an agent's accumulated features (audit #88).
        """
        now = time.monotonic() if now is None else now
        start, ev0, val0 = self._evict_mark
        if now - start < self.eviction_window_seconds:
            return False
        stats = self.tracker.stats
        evicted, valuable = stats["evicted"] - ev0, stats["evicted_valuable"] - val0
        self._evict_mark = (now, stats["evicted"], stats["evicted_valuable"])
        limit = self.tracker.max_sessions
        if (evicted < max(64, limit // 4) and valuable == 0) or (
            now - self._last_evict_warn < self.eviction_warn_interval_seconds
        ):
            return False
        self._last_evict_warn = now
        log.warning(
            "actor-session table under pressure: %d sessions evicted in the last %.0fs (%d with >= 5 requests or "
            "AI/canary/decoy evidence; detection.max_live_sessions=%d). A flood of one-request clients can reset "
            "session features; raise the limit if this is normal load.",
            evicted,
            now - start,
            valuable,
            limit,
        )
        return True

    async def enrich(self, events: list[Event]) -> None:
        self.tracker.observe_batch(events)
        if (
            self.tracker.significant_change
            or self.tracker.dirty_count >= self.flush_max_dirty
            or time.monotonic() - self._last_flush >= self.flush_interval_seconds
        ):
            await self.flush()

    async def flush(self) -> int:
        async with self._lock:
            snaps = self.tracker.drain_dirty()
            self._last_flush = time.monotonic()
            self.check_eviction_pressure(self._last_flush)
            if not snaps:
                return 0
            try:
                return await persist_snapshots(snaps)
            except Exception:
                log.exception("failed to persist %d actor sessions (will retry)", len(snaps))
                self.tracker.requeue(snaps)
                return 0


def current_sessionizer() -> Sessionizer | None:
    """The sessionizer instance owned by the ingest pipeline (follows ``reset_enrichers()``)."""
    from tokiwa.pipeline.service import get_enrichers

    for e in get_enrichers():
        if isinstance(e, Sessionizer):
            return e
    return None


async def flush_current() -> int:
    """Persist pending session state now (used by the sessions API, the periodic job and shutdown)."""
    s = current_sessionizer()
    if s is None:
        return 0
    return await s.flush()


@periodic("aidetect.sessions_flush", every_seconds=5.0, initial_delay=5.0)
async def _periodic_flush() -> None:
    await flush_current()


@on_shutdown
async def _flush_on_shutdown() -> None:
    try:
        await flush_current()
    except Exception:
        log.exception("final actor-session flush failed")
