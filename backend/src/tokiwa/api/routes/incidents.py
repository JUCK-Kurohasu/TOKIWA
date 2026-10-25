"""Incidents API (docs/api-contract.md「インシデント」). Writes require analyst; every change is audited."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import ColumnElement, func, select

from tokiwa.api.deps import AnalystUser, CurrentUser, DbSession
from tokiwa.api.routes.alerts import parse_enum_list
from tokiwa.audit import record_audit
from tokiwa.bus import bus
from tokiwa.db.models.detection import AlertRow, IncidentRow
from tokiwa.db.models.response import ResponseActionRow
from tokiwa.llm.base import LLMTier
from tokiwa.schemas.alerts import Alert, Incident, IncidentDetail, IncidentStatus, IncidentUpdate
from tokiwa.schemas.common import ActorType, Page, Severity
from tokiwa.schemas.response import ResponseAction
from tokiwa.triage.service import get_triage_service
from tokiwa.util import utcnow

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

_MAX_DETAIL_ALERTS = 500
_MAX_DETAIL_ACTIONS = 200


@router.get("", response_model=Page[Incident])
async def list_incidents(
    session: DbSession,
    _: CurrentUser,
    status_: str | None = Query(None, alias="status", description="comma-separated IncidentStatus values"),
    severity: str | None = Query(None, description="comma-separated Severity values"),
    actor_type: str | None = Query(None, description="comma-separated ActorType values"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page[Incident]:
    conds: list[ColumnElement[bool]] = []
    if statuses := parse_enum_list(status_, IncidentStatus, "status"):
        conds.append(IncidentRow.status.in_(statuses))
    if severities := parse_enum_list(severity, Severity, "severity"):
        conds.append(IncidentRow.severity.in_(severities))
    if actors := parse_enum_list(actor_type, ActorType, "actor_type"):
        conds.append(IncidentRow.actor_type.in_(actors))
    total = (await session.execute(select(func.count()).select_from(IncidentRow).where(*conds))).scalar_one()
    rows = (
        (
            await session.execute(
                select(IncidentRow)
                .where(*conds)
                .order_by(IncidentRow.last_seen.desc(), IncidentRow.id.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return Page[Incident](
        items=[Incident.model_validate(r) for r in rows], total=int(total), limit=limit, offset=offset
    )


async def _get_row(session: DbSession, incident_id: str) -> IncidentRow:
    row = await session.get(IncidentRow, incident_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    return row


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(incident_id: str, session: DbSession, _: CurrentUser) -> IncidentDetail:
    row = await _get_row(session, incident_id)
    alerts = (
        (
            await session.execute(
                select(AlertRow)
                .where(AlertRow.incident_id == incident_id)
                .order_by(AlertRow.last_seen.desc())
                .limit(_MAX_DETAIL_ALERTS)
            )
        )
        .scalars()
        .all()
    )
    actions = (
        (
            await session.execute(
                select(ResponseActionRow)
                .where(ResponseActionRow.incident_id == incident_id)
                .order_by(ResponseActionRow.created_at.desc())
                .limit(_MAX_DETAIL_ACTIONS)
            )
        )
        .scalars()
        .all()
    )
    detail = IncidentDetail.model_validate(row)
    detail.alerts = [Alert.model_validate(a) for a in alerts]
    detail.actions = [ResponseAction.model_validate(a).model_dump(mode="json") for a in actions]
    return detail


@router.patch("/{incident_id}", response_model=Incident)
async def update_incident(
    incident_id: str, body: IncidentUpdate, session: DbSession, user: AnalystUser
) -> Incident:
    row = await _get_row(session, incident_id)
    fields = body.model_fields_set
    before: dict[str, Any] = {}
    after: dict[str, Any] = {}
    if body.status is not None and body.status != row.status:
        before["status"], after["status"] = row.status, body.status.value
        row.status = body.status
    if "assignee" in fields:
        assignee = (body.assignee or "").strip() or None
        if assignee != row.assignee:
            before["assignee"], after["assignee"] = row.assignee, assignee
            row.assignee = assignee
    if body.tags is not None:
        tags = list(dict.fromkeys(t.strip() for t in body.tags if t.strip()))
        if tags != list(row.tags or []):
            before["tags"], after["tags"] = list(row.tags or []), tags
            row.tags = tags
    if not after:
        return Incident.model_validate(row)
    row.updated_at = utcnow()
    await record_audit(
        user.username, "incident.update", incident_id, {"before": before, "after": after}, session=session
    )
    await session.flush()
    incident = Incident.model_validate(row)
    await session.commit()  # make the change visible before subscribers re-read it
    await bus.publish("incident.updated", incident)
    return incident


@router.post("/{incident_id}/triage", response_model=Incident)
async def triage_incident(incident_id: str, user: AnalystUser, tier: LLMTier | None = None) -> Incident:
    """Force (re-)triage synchronously. Bypasses ``auto_triage`` / ``min_severity_for_llm``."""
    incident = await get_triage_service().triage_incident(incident_id, tier=tier, force=True)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    await record_audit(
        user.username,
        "incident.triage",
        incident_id,
        {
            "tier": tier.value if tier else None,
            "result_tier": incident.triage.tier if incident.triage else None,
        },
    )
    return incident
