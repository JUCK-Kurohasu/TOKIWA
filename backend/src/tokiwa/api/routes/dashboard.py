"""Dashboard summary and activity timeline (any logged-in user).

Reads tables owned by other modules (alerts, incidents, actor sessions, response actions, intel, LLM calls)
with plain aggregate queries only, so it returns zeros while those modules have no data yet. Results are
cached in memory for a few seconds because the UI polls this endpoint on every open dashboard.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Awaitable, Callable, Sequence
from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, ValidationError
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.api.deps import CurrentUser, DbSession
from tokiwa.api.routes.events import MAX_TIMELINE_HOURS, BucketRange, scan_rows, validate_buckets
from tokiwa.config import get_settings
from tokiwa.db.models.detection import AlertRow, IncidentRow
from tokiwa.db.models.intel import VulnMatchRow, VulnRow
from tokiwa.db.models.response import ResponseActionRow
from tokiwa.db.models.telemetry import ActorSessionRow, EventRow
from tokiwa.llm.gateway import get_gateway
from tokiwa.schemas.alerts import AlertCategory, Incident, IncidentStatus
from tokiwa.schemas.common import ActorType, Severity
from tokiwa.schemas.dashboard import (
    AlertCounts,
    DashboardBucket,
    DashboardSummary,
    DashboardTimeline,
    TopRule,
    TopSource,
)
from tokiwa.schemas.response import ActionStatus
from tokiwa.util import utcnow

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])

CACHE_TTL_SECONDS = 5.0
TOP_N = 10
RECENT_INCIDENTS = 5
_CLOSED_INCIDENT = (IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE)
# Candidate bucket sizes for the auto-sized timeline (minutes); the smallest giving <= 36 buckets wins.
_AUTO_BUCKETS = (5, 10, 15, 30, 60, 120, 180, 360, 720, 1440)
_AUTO_MAX_BUCKETS = 36

_cache: dict[tuple[Any, ...], tuple[float, BaseModel]] = {}


def clear_cache() -> None:
    """Drop cached responses (tests, or after bulk data changes)."""
    _cache.clear()


async def _cached[M: BaseModel](key: tuple[Any, ...], factory: Callable[[], Awaitable[M]]) -> M:
    # The DB URL is part of the key so separate databases (tests, multi-instance dev) never share entries.
    full_key = (get_settings().database.url, *key)
    hit = _cache.get(full_key)
    now = time.monotonic()
    if hit is not None and now - hit[0] < CACHE_TTL_SECONDS:
        return hit[1]  # type: ignore[return-value]
    value = await factory()
    _cache[full_key] = (now, value)
    return value


async def _count(session: AsyncSession, stmt: Any) -> int:
    return int((await session.execute(stmt)).scalar_one() or 0)


def _ai_alert_filter(threshold: float) -> Any:
    return or_(AlertRow.category == AlertCategory.AI_AGENT, AlertRow.ai_score >= threshold)


async def _build_summary(session: AsyncSession) -> DashboardSummary:
    settings = get_settings()
    since = utcnow() - timedelta(hours=24)
    threshold = settings.detection.ai_agent_threshold

    by_severity = {str(s): 0 for s in Severity}
    rows = await session.execute(
        select(AlertRow.severity, func.count()).where(AlertRow.last_seen >= since).group_by(AlertRow.severity)
    )
    for sev, n in rows.all():
        by_severity[str(sev)] = by_severity.get(str(sev), 0) + int(n)

    open_incidents = await _count(
        session,
        select(func.count()).select_from(IncidentRow).where(IncidentRow.status.notin_(_CLOSED_INCIDENT)),
    )
    ai_sessions = await _count(
        session,
        select(func.count())
        .select_from(ActorSessionRow)
        .where(ActorSessionRow.last_seen >= since)
        .where(
            or_(
                ActorSessionRow.classification == ActorType.AI_AGENT,
                ActorSessionRow.ai_score >= threshold,
            )
        ),
    )
    events_24h = await _count(
        session, select(func.count()).select_from(EventRow).where(EventRow.timestamp >= since)
    )
    pending_actions = await _count(
        session,
        select(func.count())
        .select_from(ResponseActionRow)
        .where(ResponseActionRow.status == ActionStatus.PROPOSED),
    )
    kev_matches = await _count(
        session,
        select(func.count())
        .select_from(VulnMatchRow)
        .join(VulnRow, VulnRow.id == VulnMatchRow.vuln_id)
        .where(VulnRow.kev.is_(True), VulnMatchRow.status == "open"),
    )

    hits = func.sum(AlertRow.count)
    top_sources = [
        TopSource(ip=ip, count=int(n or 0), ai_score=ai)
        for ip, n, ai in (
            await session.execute(
                select(AlertRow.source_ip, hits, func.max(AlertRow.ai_score))
                .where(AlertRow.last_seen >= since, AlertRow.source_ip.is_not(None))
                .group_by(AlertRow.source_ip)
                .order_by(hits.desc(), AlertRow.source_ip)
                .limit(TOP_N)
            )
        ).all()
    ]
    top_rules = [
        TopRule(rule_id=rule_id, title=title or rule_id, count=int(n or 0))
        for rule_id, title, n in (
            await session.execute(
                select(AlertRow.rule_id, func.max(AlertRow.title), hits)
                .where(AlertRow.last_seen >= since)
                .group_by(AlertRow.rule_id)
                .order_by(hits.desc(), AlertRow.rule_id)
                .limit(TOP_N)
            )
        ).all()
    ]
    recent = (
        (
            await session.execute(
                select(IncidentRow)
                .order_by(IncidentRow.last_seen.desc(), IncidentRow.id.desc())
                .limit(RECENT_INCIDENTS)
            )
        )
        .scalars()
        .all()
    )

    gateway = get_gateway()
    return DashboardSummary(
        alerts_24h=AlertCounts(total=sum(by_severity.values()), by_severity=by_severity),
        open_incidents=open_incidents,
        ai_sessions_24h=ai_sessions,
        events_24h=events_24h,
        # Same window the gateway uses to enforce the daily budget, so cost and budget are comparable.
        llm_cost_today_usd=round(await gateway.spent_today_usd(), 6),
        llm_budget_usd=gateway.llm.daily_budget_usd,
        pending_actions=pending_actions,
        kev_matches=kev_matches,
        top_sources=top_sources,
        top_rules=top_rules,
        recent_incidents=_incidents(recent),
    )


def _incidents(rows: Sequence[IncidentRow]) -> list[Incident]:
    # Incident rows are written by the correlate module; one malformed row must not break the dashboard.
    out: list[Incident] = []
    for row in rows:
        try:
            out.append(Incident.model_validate(row))
        except ValidationError:
            log.warning("skipping malformed incident %s on dashboard", row.id, exc_info=True)
    return out


def auto_bucket_minutes(hours: int) -> int:
    for minutes in _AUTO_BUCKETS:
        if math.ceil(hours * 60 / minutes) <= _AUTO_MAX_BUCKETS:
            return minutes
    return _AUTO_BUCKETS[-1]


async def _build_timeline(session: AsyncSession, hours: int, bucket_minutes: int) -> DashboardTimeline:
    threshold = get_settings().detection.ai_agent_threshold
    rng = BucketRange.build(hours, bucket_minutes)
    buckets = [DashboardBucket(ts=ts) for ts in rng.starts()]

    ev_stmt = select(EventRow.timestamp).where(EventRow.timestamp >= rng.start, EventRow.timestamp < rng.end)
    async for (ts,) in scan_rows(session, ev_stmt):
        i = rng.index(ts)
        if i is not None:
            buckets[i].events += 1

    ai_expr = _ai_alert_filter(threshold)
    al_stmt = select(AlertRow.created_at, ai_expr).where(
        AlertRow.created_at >= rng.start, AlertRow.created_at < rng.end
    )
    async for ts, is_ai in scan_rows(session, al_stmt):
        i = rng.index(ts)
        if i is not None:
            buckets[i].alerts += 1
            if is_ai:
                buckets[i].ai_alerts += 1
    return DashboardTimeline(bucket_minutes=bucket_minutes, buckets=buckets)


@router.get("/summary", response_model=DashboardSummary)
async def summary(session: DbSession, user: CurrentUser) -> DashboardSummary:
    return await _cached(("summary",), lambda: _build_summary(session))


@router.get("/timeline", response_model=DashboardTimeline)
async def timeline(
    session: DbSession,
    user: CurrentUser,
    hours: Annotated[int, Query(ge=1, le=MAX_TIMELINE_HOURS)] = 24,
    bucket_minutes: Annotated[
        int | None, Query(ge=5, le=1440, description="Default: auto (<= 36 buckets)")
    ] = None,
) -> DashboardTimeline:
    minutes = bucket_minutes or auto_bucket_minutes(hours)
    validate_buckets(hours, minutes)
    return await _cached(("timeline", hours, minutes), lambda: _build_timeline(session, hours, minutes))
