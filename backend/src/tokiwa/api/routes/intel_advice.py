"""Vulnerability matches, LLM advisories and web research (docs/api-contract.md "インテル", intel-advisor part).

The rest of /api/v1/intel (vulns, news, sources, sync) lives in ``routes/intel.py`` (intel-feeds module).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import String, case, cast, func, select

from tokiwa.api.deps import AnalystUser, CurrentUser, DbSession
from tokiwa.audit import record_audit
from tokiwa.db.models.intel import AdvisoryRow, AssetRow, ResearchReportRow, VulnMatchRow, VulnRow
from tokiwa.intel.advisor import generate_advisory
from tokiwa.intel.matcher import run_matching
from tokiwa.intel.research import ResearchError, run_research
from tokiwa.schemas.common import Page
from tokiwa.schemas.intel import Advisory, MatchStatus, Priority, ResearchReport, VulnMatch

router = APIRouter(prefix="/api/v1/intel", tags=["intel"])


class VulnMatchOut(VulnMatch):
    """VulnMatch + display fields joined from assets / vulns."""

    asset_name: str | None = None
    asset_criticality: str | None = None
    vuln_title: str | None = None
    kev: bool = False
    epss: float | None = None
    cvss_score: float | None = None


class MatchUpdate(BaseModel):
    status: MatchStatus


class RescanResult(BaseModel):
    evaluated_vulns: int
    matches: int
    new: int
    updated: int
    closed: int


class AdvisoryGenerate(BaseModel):
    vuln_id: str = Field(min_length=1, max_length=64)
    force: bool = False  # regenerate even if an equivalent advisory exists from the last 7 days


class AdvisoryUpdate(BaseModel):
    status: str = Field(pattern="^(new|acknowledged|done|dismissed)$")


class ResearchRun(BaseModel):
    topic: str | None = Field(default=None, max_length=500)


def _match_query() -> Any:
    return (
        select(
            VulnMatchRow,
            AssetRow.name,
            AssetRow.criticality,
            VulnRow.title,
            VulnRow.kev,
            VulnRow.epss,
            VulnRow.cvss_score,
        )
        .outerjoin(AssetRow, AssetRow.id == VulnMatchRow.asset_id)
        .outerjoin(VulnRow, VulnRow.id == VulnMatchRow.vuln_id)
    )


def _match_out(row: Any) -> VulnMatchOut:
    match, asset_name, criticality, title, kev, epss, cvss = row
    return VulnMatchOut(
        **VulnMatch.model_validate(match).model_dump(),
        asset_name=asset_name,
        asset_criticality=criticality,
        vuln_title=title,
        kev=bool(kev),
        epss=epss,
        cvss_score=cvss,
    )


# ---------------------------------------------------------------------------------------------------- matches


@router.get("/matches", response_model=Page[VulnMatchOut])
async def list_matches(
    session: DbSession,
    _: CurrentUser,
    status_: MatchStatus | None = Query(default=None, alias="status"),
    asset_id: str | None = None,
    vuln_id: str | None = None,
    kev: bool | None = None,
    min_confidence: float | None = Query(default=None, ge=0.0, le=1.0),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Page[VulnMatchOut]:
    stmt = _match_query()
    if status_ is not None:
        stmt = stmt.where(VulnMatchRow.status == status_.value)
    if asset_id:
        stmt = stmt.where(VulnMatchRow.asset_id == asset_id)
    if vuln_id:
        stmt = stmt.where(VulnMatchRow.vuln_id == vuln_id)
    if kev is not None:
        stmt = stmt.where(VulnRow.kev.is_(True)) if kev else stmt.where(VulnRow.kev.isnot(True))
    if min_confidence is not None:
        stmt = stmt.where(VulnMatchRow.confidence >= min_confidence)
    total = int((await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one())
    stmt = stmt.order_by(
        case((VulnRow.kev.is_(True), 0), else_=1),
        func.coalesce(VulnRow.epss, 0.0).desc(),
        VulnMatchRow.confidence.desc(),
        VulnMatchRow.created_at.desc(),
    )
    rows = (await session.execute(stmt.limit(limit).offset(offset))).all()
    return Page[VulnMatchOut](items=[_match_out(r) for r in rows], total=total, limit=limit, offset=offset)


@router.post("/matches/rescan", response_model=RescanResult)
async def rescan_matches(user: AnalystUser) -> RescanResult:
    """Re-run the matcher over all assets x vulns (also runs periodically as job ``intel.match``)."""
    summary = await run_matching()
    await record_audit(user.username, "intel.matches.rescan", details={"new": len(summary.created)})
    return RescanResult(
        evaluated_vulns=summary.evaluated_vulns,
        matches=summary.matched,
        new=len(summary.created),
        updated=summary.updated,
        closed=summary.closed,
    )


@router.patch("/matches/{match_id}", response_model=VulnMatchOut)
async def update_match(
    match_id: str, body: MatchUpdate, session: DbSession, user: AnalystUser
) -> VulnMatchOut:
    row = await session.get(VulnMatchRow, match_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "match not found")
    previous = row.status
    row.status = body.status.value
    await record_audit(
        user.username,
        "intel.match.update",
        target=match_id,
        details={"from": previous, "to": row.status, "vuln_id": row.vuln_id, "asset_id": row.asset_id},
        session=session,
    )
    await session.flush()
    result = (await session.execute(_match_query().where(VulnMatchRow.id == match_id))).one()
    return _match_out(result)


# ------------------------------------------------------------------------------------------------- advisories


@router.get("/advisories", response_model=Page[Advisory])
async def list_advisories(
    session: DbSession,
    _: CurrentUser,
    priority: Priority | None = None,
    status_: str | None = Query(default=None, alias="status", max_length=16),
    vuln_id: str | None = Query(default=None, max_length=64),
    since: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Page[Advisory]:
    stmt = select(AdvisoryRow)
    if priority is not None:
        stmt = stmt.where(AdvisoryRow.priority == priority.value)
    if status_:
        stmt = stmt.where(AdvisoryRow.status == status_)
    if since is not None:
        stmt = stmt.where(AdvisoryRow.created_at >= since)
    if vuln_id:
        # JSON containment is not portable; narrow with LIKE, confirm in Python.
        stmt = stmt.where(cast(AdvisoryRow.vuln_ids, String).contains(vuln_id, autoescape=True))
        rows_all = [r for r in (await session.execute(stmt)).scalars() if vuln_id in (r.vuln_ids or [])]
        rows_all.sort(key=lambda r: r.created_at, reverse=True)
        page = rows_all[offset : offset + limit]
        return Page[Advisory](
            items=[Advisory.model_validate(r) for r in page], total=len(rows_all), limit=limit, offset=offset
        )
    total = int((await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one())
    rows = (
        await session.execute(
            stmt.order_by(AdvisoryRow.created_at.desc(), AdvisoryRow.id.desc()).limit(limit).offset(offset)
        )
    ).scalars()
    return Page[Advisory](
        items=[Advisory.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )


@router.post("/advisories/generate", response_model=Advisory)
async def generate(body: AdvisoryGenerate, user: AnalystUser) -> Advisory:
    """Generate an advisory now (deep-tier LLM; rule-based template when no LLM). Returns the existing one when an
    equivalent advisory was generated in the last 7 days, unless ``force`` is true."""
    try:
        advisory, created = await generate_advisory(body.vuln_id.strip(), force=body.force)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "vulnerability not found") from exc
    if created:
        await record_audit(
            user.username, "intel.advisory.generate", target=advisory.id, details={"vuln_id": body.vuln_id}
        )
    return advisory


@router.get("/advisories/{advisory_id}", response_model=Advisory)
async def get_advisory(advisory_id: str, session: DbSession, _: CurrentUser) -> Advisory:
    row = await session.get(AdvisoryRow, advisory_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "advisory not found")
    return Advisory.model_validate(row)


@router.patch("/advisories/{advisory_id}", response_model=Advisory)
async def update_advisory(
    advisory_id: str, body: AdvisoryUpdate, session: DbSession, user: AnalystUser
) -> Advisory:
    row = await session.get(AdvisoryRow, advisory_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "advisory not found")
    previous = row.status
    row.status = body.status
    await record_audit(
        user.username,
        "intel.advisory.update",
        target=advisory_id,
        details={"from": previous, "to": body.status},
        session=session,
    )
    await session.flush()
    return Advisory.model_validate(row)


# --------------------------------------------------------------------------------------------------- research


@router.get("/research", response_model=Page[ResearchReport])
async def list_research(
    session: DbSession,
    _: CurrentUser,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Page[ResearchReport]:
    total = int((await session.execute(select(func.count()).select_from(ResearchReportRow))).scalar_one())
    rows = (
        await session.execute(
            select(ResearchReportRow)
            .order_by(ResearchReportRow.created_at.desc(), ResearchReportRow.id.desc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars()
    return Page[ResearchReport](
        items=[ResearchReport.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )


@router.post("/research/run", response_model=ResearchReport)
async def run_research_now(body: ResearchRun, user: AnalystUser) -> ResearchReport:
    """Run web research now (deep tier + server-side web search on trusted domains). Without a topic, all
    configured ``intel.research_topics`` are researched in one call."""
    try:
        report = await run_research(body.topic)
    except ResearchError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)[:500]) from exc
    await record_audit(
        user.username, "intel.research.run", target=report.id, details={"topic": report.topic[:200]}
    )
    return report


@router.get("/research/{report_id}", response_model=ResearchReport)
async def get_research(report_id: str, session: DbSession, _: CurrentUser) -> ResearchReport:
    row = await session.get(ResearchReportRow, report_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "research report not found")
    return ResearchReport.model_validate(row)
