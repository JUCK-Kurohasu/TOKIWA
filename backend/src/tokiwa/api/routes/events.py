"""Event search and event-volume timeline (any logged-in user).

The timeline is aggregated in Python instead of SQL because time-bucketing functions differ between SQLite
(``strftime``) and PostgreSQL (``date_trunc``). The window is capped at 7 days and rows are streamed in
partitions so memory stays bounded; :class:`BucketRange` / :func:`scan_rows` are reused by routes/dashboard.py.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import Select, or_, select
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.api.deps import CurrentUser, DbSession
from tokiwa.api.pagination import PageParams, paginate
from tokiwa.db.models.telemetry import EventRow
from tokiwa.pipeline.store import row_to_event
from tokiwa.schemas.common import Page
from tokiwa.schemas.dashboard import EventTimeline, EventTimelineBucket
from tokiwa.schemas.events import Event, EventKind
from tokiwa.util import ensure_utc, utcnow

router = APIRouter(prefix="/api/v1/events", tags=["events"])

MAX_TIMELINE_HOURS = 24 * 7
MAX_BUCKETS = 2000
_SCAN_PARTITION = 5000


@dataclass(frozen=True, slots=True)
class BucketRange:
    """``count`` contiguous buckets of ``size`` aligned to the epoch; the last one contains ``now``.

    Epoch alignment keeps bucket edges stable between refreshes (the UI does not "shift" every poll).
    """

    start: datetime
    size: timedelta
    count: int

    @classmethod
    def build(cls, hours: int, bucket_minutes: int, now: datetime | None = None) -> BucketRange:
        size_s = bucket_minutes * 60
        now_s = (now or utcnow()).timestamp()
        current = math.floor(now_s / size_s) * size_s
        count = max(1, math.ceil(hours * 3600 / size_s))
        start = datetime.fromtimestamp(current - (count - 1) * size_s, tz=UTC)
        return cls(start=start, size=timedelta(seconds=size_s), count=count)

    @property
    def end(self) -> datetime:
        return self.start + self.size * self.count

    def starts(self) -> list[datetime]:
        return [self.start + self.size * i for i in range(self.count)]

    def index(self, ts: datetime | None) -> int | None:
        if ts is None:
            return None
        i = int((ensure_utc(ts) - self.start) // self.size)
        return i if 0 <= i < self.count else None


async def scan_rows[*Ts](session: AsyncSession, stmt: Select[*Ts]) -> AsyncIterator[Row[*Ts]]:
    """Stream result rows in partitions (bounded memory for multi-day scans)."""
    result = await session.stream(stmt.execution_options(yield_per=_SCAN_PARTITION))
    async for partition in result.partitions():
        for row in partition:
            yield row


def validate_buckets(hours: int, bucket_minutes: int) -> None:
    if math.ceil(hours * 60 / bucket_minutes) > MAX_BUCKETS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"too many buckets (max {MAX_BUCKETS}); increase bucket_minutes",
        )


@router.get("", response_model=Page[Event])
async def list_events(
    session: DbSession,
    user: CurrentUser,
    page: PageParams,
    kind: EventKind | None = None,
    dataset: str | None = None,
    source_ip: str | None = None,
    session_id: str | None = None,
    host: str | None = None,
    q: Annotated[
        str | None, Query(max_length=512, description="Substring of HTTP path or User-Agent")
    ] = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> Page[Event]:
    stmt = select(EventRow)
    if kind is not None:
        stmt = stmt.where(EventRow.kind == kind)
    if dataset:
        stmt = stmt.where(EventRow.dataset == dataset)
    if source_ip:
        stmt = stmt.where(EventRow.source_ip == source_ip)
    if session_id:
        stmt = stmt.where(EventRow.session_id == session_id)
    if host:
        stmt = stmt.where(EventRow.host_name == host)
    if q:
        stmt = stmt.where(
            or_(
                EventRow.http_path.icontains(q, autoescape=True),
                EventRow.user_agent.icontains(q, autoescape=True),
            )
        )
    if since is not None:
        stmt = stmt.where(EventRow.timestamp >= ensure_utc(since))
    if until is not None:
        stmt = stmt.where(EventRow.timestamp <= ensure_utc(until))
    stmt = stmt.order_by(EventRow.timestamp.desc(), EventRow.id.desc())
    return await paginate(session, stmt, page, row_to_event)


@router.get("/stats/timeline", response_model=EventTimeline)
async def event_timeline(
    session: DbSession,
    user: CurrentUser,
    hours: Annotated[int, Query(ge=1, le=MAX_TIMELINE_HOURS)] = 24,
    bucket_minutes: Annotated[int, Query(ge=1, le=1440)] = 60,
) -> EventTimeline:
    validate_buckets(hours, bucket_minutes)
    rng = BucketRange.build(hours, bucket_minutes)
    totals = [0] * rng.count
    kinds: list[Counter[str]] = [Counter() for _ in range(rng.count)]
    stmt = select(EventRow.timestamp, EventRow.kind).where(
        EventRow.timestamp >= rng.start, EventRow.timestamp < rng.end
    )
    async for ts, kind in scan_rows(session, stmt):
        i = rng.index(ts)
        if i is not None:
            totals[i] += 1
            kinds[i][str(kind)] += 1
    return EventTimeline(
        bucket_minutes=bucket_minutes,
        buckets=[
            EventTimelineBucket(ts=ts, total=totals[i], by_kind=dict(kinds[i]))
            for i, ts in enumerate(rng.starts())
        ],
    )


@router.get("/{event_id}", response_model=Event)
async def get_event(event_id: str, session: DbSession, user: CurrentUser) -> Event:
    row = await session.get(EventRow, event_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "event not found")
    return row_to_event(row)
