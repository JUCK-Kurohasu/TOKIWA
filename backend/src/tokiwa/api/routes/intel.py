"""Intel feeds API: vulnerabilities, news, source status and manual sync (owner: intel-feeds).

``/intel/matches``, ``/intel/advisories*`` and ``/intel/research*`` live in ``routes/intel_advice.py``
(intel-advisor). ``/intel/vulns/{id}`` reads ``vuln_matches`` / ``advisories`` directly so the detail view works
regardless of which advisor features are deployed.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import String, cast, select

from tokiwa.api.deps import AnalystUser, CurrentUser, DbSession
from tokiwa.audit import record_audit
from tokiwa.db.models.intel import AdvisoryRow, VulnMatchRow
from tokiwa.intel import store
from tokiwa.intel import sync as intel_sync
from tokiwa.intel.sync import SourceStatus
from tokiwa.schemas.common import Page, Severity
from tokiwa.schemas.intel import Advisory, IntelItem, VulnMatch, VulnRecord

router = APIRouter(prefix="/api/v1/intel", tags=["intel"])

Limit = Annotated[int, Query(ge=1, le=500)]
Offset = Annotated[int, Query(ge=0)]


class VulnDetail(BaseModel):
    vuln: VulnRecord
    matches: list[VulnMatch] = Field(default_factory=list)
    advisories: list[Advisory] = Field(default_factory=list)


class SyncRequest(BaseModel):
    source: str | None = Field(
        default=None, description="Source id (kev, epss, nvd, osv, jvn, ghsa, rss); all if omitted"
    )


class SyncStarted(BaseModel):
    started: bool
    sources: list[str]


@router.get("/vulns", response_model=Page[VulnRecord])
async def list_vulns(
    session: DbSession,
    _user: CurrentUser,
    q: str | None = None,
    kev: bool | None = None,
    min_epss: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
    min_cvss: Annotated[float | None, Query(ge=0.0, le=10.0)] = None,
    matched: Annotated[bool | None, Query(description="has a non-false-positive asset match")] = None,
    source: str | None = None,
    severity: Severity | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[VulnRecord]:
    """Default order: KEV first, then EPSS, CVSS and last-modified (descending, missing values last)."""
    items, total = await store.query_vulns(
        session,
        q=q,
        kev=kev,
        min_epss=min_epss,
        min_cvss=min_cvss,
        matched=matched,
        source=source,
        severity=severity.value if severity else None,
        limit=limit,
        offset=offset,
    )
    return Page[VulnRecord](items=items, total=total, limit=limit, offset=offset)


@router.get("/vulns/{vuln_id}", response_model=VulnDetail)
async def get_vuln(vuln_id: str, session: DbSession, _user: CurrentUser) -> VulnDetail:
    """Lookup by CVE id or by an alias (GHSA / JVNDB id)."""
    row = await store.get_vuln_row(session, vuln_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "vulnerability not found")
    ids = [row.id, *(row.aliases or [])]
    matches = (
        (
            await session.execute(
                select(VulnMatchRow)
                .where(VulnMatchRow.vuln_id.in_(ids))
                .order_by(VulnMatchRow.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    advisories = (
        (
            await session.execute(
                select(AdvisoryRow)
                .where(cast(AdvisoryRow.vuln_ids, String).contains(f'"{row.id}"', autoescape=True))
                .order_by(AdvisoryRow.created_at.desc())
                .limit(50)
            )
        )
        .scalars()
        .all()
    )
    return VulnDetail(
        vuln=VulnRecord.model_validate(row),
        matches=[VulnMatch.model_validate(m) for m in matches],
        advisories=[Advisory.model_validate(a) for a in advisories],
    )


@router.get("/news", response_model=Page[IntelItem])
async def list_news(
    session: DbSession,
    _user: CurrentUser,
    source: Annotated[str | None, Query(description="exact source, or a prefix such as 'rss'")] = None,
    q: str | None = None,
    vuln_id: str | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[IntelItem]:
    items, total = await store.query_items(
        session, source=source, q=q, vuln_id=vuln_id, limit=limit, offset=offset
    )
    return Page[IntelItem](items=items, total=total, limit=limit, offset=offset)


@router.get("/sources", response_model=list[SourceStatus])
async def list_sources(_user: CurrentUser) -> list[SourceStatus]:
    return await intel_sync.source_statuses()


@router.post("/sync", response_model=SyncStarted)
async def trigger_sync(user: AnalystUser, body: Annotated[SyncRequest | None, Body()] = None) -> SyncStarted:
    """Start a sync in the background (all enabled sources, or ``source``). 409 if one is already running."""
    requested = [body.source] if body and body.source else None
    try:
        planned = intel_sync.plan_sources(requested)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc.args[0])) from exc
    if not planned:
        raise HTTPException(status.HTTP_409_CONFLICT, "no enabled intel source to sync")
    if intel_sync.is_running():
        raise HTTPException(status.HTTP_409_CONFLICT, "intel sync already running")
    ids = [s.id for s in planned]
    await record_audit(user.username, "intel.sync", target=",".join(ids), details={"requested": requested})
    intel_sync.start_background_sync(ids)
    return SyncStarted(started=True, sources=ids)
