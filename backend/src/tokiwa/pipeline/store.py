"""Event <-> row conversion and storage helpers."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.db.models.telemetry import EventRow
from tokiwa.schemas.events import Event


def event_to_row(e: Event) -> EventRow:
    h = e.http
    return EventRow(
        id=e.id,
        timestamp=e.timestamp,
        ingested_at=e.ingested_at,
        kind=e.kind,
        dataset=e.dataset,
        sensor_id=e.sensor_id,
        host_name=e.host.name if e.host else None,
        source_ip=e.source.ip if e.source else None,
        source_port=e.source.port if e.source else None,
        dest_ip=e.destination.ip if e.destination else None,
        dest_port=e.destination.port if e.destination else None,
        http_method=h.method if h else None,
        http_host=h.host if h else None,
        http_path=h.path if h else None,
        http_status=h.status if h else None,
        user_agent=h.user_agent if h else None,
        session_id=e.session_id,
        asset_id=e.asset_id,
        tags=e.tags,
        data=e.model_dump(mode="json", exclude_none=True),
    )


def row_to_event(row: EventRow) -> Event:
    ev = Event.model_validate(row.data)
    # Columns may have been updated after insert (e.g. session_id back-filled)
    ev.session_id = row.session_id
    ev.asset_id = row.asset_id
    return ev


async def store_events(session: AsyncSession, events: Sequence[Event]) -> None:
    session.add_all([event_to_row(e) for e in events])
    await session.flush()


async def get_events(session: AsyncSession, ids: Sequence[str]) -> list[Event]:
    if not ids:
        return []
    rows = (await session.execute(select(EventRow).where(EventRow.id.in_(list(ids))))).scalars().all()
    by_id = {r.id: row_to_event(r) for r in rows}
    return [by_id[i] for i in ids if i in by_id]
