"""Ingest pipeline: enrich -> store -> detect -> persist alerts -> publish.

Processing is inline (the ingest request returns after detection) which keeps behaviour deterministic and is
fast enough at lab scale. If throughput becomes a problem, put a queue in front of ``process_events``.
"""

from __future__ import annotations

import logging

from sqlalchemy import select

from tokiwa.bus import bus
from tokiwa.db.models.telemetry import EventRow
from tokiwa.db.session import session_scope
from tokiwa.detect.engine import get_detection_engine
from tokiwa.enrich.base import Enricher, registered_enrichers
from tokiwa.pipeline.store import store_events
from tokiwa.schemas.events import Event, IngestResult
from tokiwa.util import new_id, utcnow

EVENT_ID_MAX = 64  # events.id is String(64)

log = logging.getLogger(__name__)

_enrichers: list[Enricher] | None = None


def get_enrichers() -> list[Enricher]:
    global _enrichers
    if _enrichers is None:
        from tokiwa.plugins import import_submodules

        import_submodules("tokiwa.enrich")
        _enrichers = []
        for cls in registered_enrichers():
            try:
                _enrichers.append(cls())
            except Exception:
                log.exception("failed to instantiate enricher %s", cls.id)
    return _enrichers


def reset_enrichers() -> None:
    global _enrichers
    _enrichers = None


async def process_events(events: list[Event]) -> IngestResult:
    if not events:
        return IngestResult(accepted=0, alerts=0)
    received = len(events)
    events = await _new_events(events)
    duplicates = received - len(events)
    if not events:
        return IngestResult(accepted=0, alerts=0, duplicates=received)
    now = utcnow()
    for e in events:
        e.ingested_at = now
    for enricher in get_enrichers():
        try:
            await enricher.enrich(events)
        except Exception:
            log.exception("enricher %s failed", enricher.id)

    engine = get_detection_engine()
    drafts = await engine.run(events)
    async with session_scope() as session:
        rejected = set(await store_events(session, events))
        created, updated = await engine.persist(session, drafts)
    if rejected:
        events = [e for e in events if e.id not in rejected]
    await bus.publish("event.ingested", events)
    await engine.publish(created, updated)
    ids = [a.id for a in created] + [a.id for a in updated]
    # accepted: stored events, including those the enrichers derived (e.g. PORT_CHANGE from a snapshot).
    return IngestResult(accepted=len(events), alerts=len(created), alert_ids=ids, duplicates=duplicates)


async def _new_events(events: list[Event]) -> list[Event]:
    """Valid ids, each event once, none already stored (audit #25).

    A sensor that timed out waiting for the response re-sends a batch the server may already have committed;
    before, the repeated primary key failed the whole batch (500) and the sensor retried it forever. Repeats are
    dropped before detection so they neither fail the insert nor count twice. An id that cannot be a key
    (longer than the column) is replaced, keeping the original (cut) in a label.
    """
    for e in events:
        if not e.id or len(e.id) > EVENT_ID_MAX:
            e.labels["ingest.original_id"] = e.id[:128]
            e.id = new_id()
    unique = list({e.id: e for e in reversed(events)}.values())[::-1]  # first occurrence wins
    existing: set[str] = set()
    async with session_scope() as session:
        ids = [e.id for e in unique]
        for i in range(0, len(ids), 500):
            res = await session.execute(select(EventRow.id).where(EventRow.id.in_(ids[i : i + 500])))
            existing.update(res.scalars())
    if existing:
        log.info("ingest: skipped %d events already stored (sensor retry)", len(existing))
    return [e for e in unique if e.id not in existing]
