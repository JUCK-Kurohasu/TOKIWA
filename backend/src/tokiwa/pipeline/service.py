"""Ingest pipeline: enrich -> store -> detect -> persist alerts -> publish.

Processing is inline (the ingest request returns after detection) which keeps behaviour deterministic and is
fast enough at lab scale. If throughput becomes a problem, put a queue in front of ``process_events``.
"""

from __future__ import annotations

import logging

from tokiwa.bus import bus
from tokiwa.db.session import session_scope
from tokiwa.detect.engine import get_detection_engine
from tokiwa.enrich.base import Enricher, registered_enrichers
from tokiwa.pipeline.store import store_events
from tokiwa.schemas.events import Event, IngestResult
from tokiwa.util import utcnow

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
        await store_events(session, events)
        created, updated = await engine.persist(session, drafts)
    await bus.publish("event.ingested", events)
    await engine.publish(created, updated)
    ids = [a.id for a in created] + [a.id for a in updated]
    return IngestResult(accepted=len(events), alerts=len(created), alert_ids=ids)
