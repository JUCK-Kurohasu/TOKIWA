"""Actor sessions (AI-agent attribution) — docs/api-contract.md「アクターセッション」.

``GET /sessions`` lists sessions ordered by AI score (then recency). ``GET /sessions/{id}`` returns the session, its
latest events (max 200, chronological) and a timeline whose ``gap_ms`` (inter-arrival time between successive HTTP
requests) lets the UI plot the "burst -> think" rhythm. Pending in-memory session state is flushed before reading.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from tokiwa.aidetect.features import BURST_GAP_S, THINK_MAX_S, THINK_MIN_S
from tokiwa.api.deps import CurrentUser, DbSession
from tokiwa.db.models.telemetry import ActorSessionRow, EventRow
from tokiwa.enrich.sessionizer import flush_current
from tokiwa.pipeline.store import row_to_event
from tokiwa.schemas.alerts import ActorSession
from tokiwa.schemas.common import ActorType, Page
from tokiwa.schemas.events import Event, EventKind

router = APIRouter(prefix="/api/v1/sessions", tags=["sessions"])

MAX_DETAIL_EVENTS = 200


class TimelinePoint(BaseModel):
    t: datetime
    path: str | None = None
    status: int | None = None
    # Milliseconds since the previous HTTP request of the session (None for the first one / non-HTTP events)
    gap_ms: float | None = None
    method: str | None = None
    kind: str = EventKind.HTTP.value
    event_id: str
    error: bool = False
    # Rhythm bands used by the scorer (see aidetect.features): burst < 0.3 s, think 1-60 s
    band: str | None = None


class SessionDetail(BaseModel):
    session: ActorSession
    events: list[Event] = Field(default_factory=list)
    timeline: list[TimelinePoint] = Field(default_factory=list)


def _band(gap_s: float) -> str:
    if gap_s < BURST_GAP_S:
        return "burst"
    if gap_s < THINK_MIN_S:
        return "mid"
    if gap_s <= THINK_MAX_S:
        return "think"
    return "long"


def build_timeline(events: list[Event]) -> list[TimelinePoint]:
    out: list[TimelinePoint] = []
    prev_http: datetime | None = None
    for e in events:
        if e.kind == EventKind.HTTP and e.http is not None:
            gap = (e.timestamp - prev_http).total_seconds() if prev_http is not None else None
            prev_http = e.timestamp
            out.append(
                TimelinePoint(
                    t=e.timestamp,
                    path=(e.http.path or "/")[:300],
                    status=e.http.status,
                    gap_ms=round(gap * 1000, 1) if gap is not None else None,
                    method=e.http.method,
                    kind=e.kind.value,
                    event_id=e.id,
                    error=e.http.status is not None and e.http.status >= 400,
                    band=_band(gap) if gap is not None else None,
                )
            )
        else:
            path = None
            if e.deception is not None:
                path = e.deception.asset_kind
            elif e.llm_app is not None:
                path = e.llm_app.app
            out.append(TimelinePoint(t=e.timestamp, path=path, kind=e.kind.value, event_id=e.id))
    return out


@router.get("", response_model=Page[ActorSession])
async def list_sessions(
    session: DbSession,
    _user: CurrentUser,
    min_ai_score: float | None = Query(None, ge=0.0, le=1.0),
    classification: ActorType | None = None,
    source_ip: str | None = Query(None, max_length=64),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page[ActorSession]:
    await flush_current()
    stmt = select(ActorSessionRow)
    if min_ai_score is not None:
        stmt = stmt.where(ActorSessionRow.ai_score >= min_ai_score)
    if classification is not None:
        stmt = stmt.where(ActorSessionRow.classification == classification.value)
    if source_ip:
        stmt = stmt.where(ActorSessionRow.source_ip == source_ip)
    total = (await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (
        (
            await session.execute(
                stmt.order_by(ActorSessionRow.ai_score.desc(), ActorSessionRow.last_seen.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return Page[ActorSession](
        items=[ActorSession.model_validate(r) for r in rows], total=int(total), limit=limit, offset=offset
    )


@router.get("/{session_id}", response_model=SessionDetail)
async def get_session(session_id: str, session: DbSession, _user: CurrentUser) -> SessionDetail:
    await flush_current()
    row = await session.get(ActorSessionRow, session_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
    ev_rows = (
        (
            await session.execute(
                select(EventRow)
                .where(EventRow.session_id == session_id)
                .order_by(EventRow.timestamp.desc())
                .limit(MAX_DETAIL_EVENTS)
            )
        )
        .scalars()
        .all()
    )
    events = sorted((row_to_event(r) for r in ev_rows), key=lambda e: e.timestamp)
    return SessionDetail(
        session=ActorSession.model_validate(row), events=events, timeline=build_timeline(events)
    )
