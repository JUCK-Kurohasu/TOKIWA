"""Alerts API (docs/api-contract.md「アラート」). Writes require analyst; every change is audited."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import ColumnElement, func, or_, select

from tokiwa.api.deps import AnalystUser, CurrentUser, DbSession
from tokiwa.audit import record_audit
from tokiwa.bus import bus
from tokiwa.db.models.detection import AlertRow
from tokiwa.llm.base import LLMTier
from tokiwa.pipeline.store import get_events
from tokiwa.schemas.alerts import Alert, AlertCategory, AlertDetail, AlertStatus, AlertUpdate
from tokiwa.schemas.common import Page, Severity
from tokiwa.triage.service import get_triage_service
from tokiwa.util import utcnow

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

_MAX_EVIDENCE = 200


def parse_enum_list(value: str | None, enum: type[StrEnum], name: str) -> list[str]:
    """``?severity=high,critical`` -> ["high", "critical"]; unknown values -> 422."""
    if not value:
        return []
    out: list[str] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(enum(part).value)
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"invalid {name}: {part!r}") from exc
    return out


def like_pattern(q: str) -> str:
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


@router.get("", response_model=Page[Alert])
async def list_alerts(
    session: DbSession,
    _: CurrentUser,
    status_: str | None = Query(None, alias="status", description="comma-separated AlertStatus values"),
    severity: str | None = Query(None, description="comma-separated Severity values"),
    category: str | None = Query(None, description="comma-separated AlertCategory values"),
    source_ip: str | None = None,
    q: str | None = Query(None, max_length=200),
    min_ai_score: float | None = Query(None, ge=0.0, le=1.0),
    incident_id: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Page[Alert]:
    conds: list[ColumnElement[bool]] = []
    if statuses := parse_enum_list(status_, AlertStatus, "status"):
        conds.append(AlertRow.status.in_(statuses))
    if severities := parse_enum_list(severity, Severity, "severity"):
        conds.append(AlertRow.severity.in_(severities))
    if categories := parse_enum_list(category, AlertCategory, "category"):
        conds.append(AlertRow.category.in_(categories))
    if source_ip:
        conds.append(AlertRow.source_ip == source_ip)
    if min_ai_score is not None:
        conds.append(AlertRow.ai_score >= min_ai_score)
    if incident_id:
        conds.append(AlertRow.incident_id == incident_id)
    if q:
        pattern = like_pattern(q)
        conds.append(
            or_(
                AlertRow.title.ilike(pattern, escape="\\"),
                AlertRow.description.ilike(pattern, escape="\\"),
                AlertRow.rule_id.ilike(pattern, escape="\\"),
                AlertRow.source_ip.ilike(pattern, escape="\\"),
            )
        )
    total = (await session.execute(select(func.count()).select_from(AlertRow).where(*conds))).scalar_one()
    rows = (
        (
            await session.execute(
                select(AlertRow)
                .where(*conds)
                .order_by(AlertRow.last_seen.desc(), AlertRow.id.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return Page[Alert](
        items=[Alert.model_validate(r) for r in rows], total=int(total), limit=limit, offset=offset
    )


async def _get_row(session: DbSession, alert_id: str) -> AlertRow:
    row = await session.get(AlertRow, alert_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    return row


@router.get("/{alert_id}", response_model=AlertDetail)
async def get_alert(alert_id: str, session: DbSession, _: CurrentUser) -> AlertDetail:
    row = await _get_row(session, alert_id)
    detail = AlertDetail.model_validate(row)
    detail.evidence = await get_events(session, list(row.evidence_event_ids or [])[-_MAX_EVIDENCE:])
    return detail


@router.patch("/{alert_id}", response_model=Alert)
async def update_alert(alert_id: str, body: AlertUpdate, session: DbSession, user: AnalystUser) -> Alert:
    row = await _get_row(session, alert_id)
    before: dict[str, Any] = {}
    after: dict[str, Any] = {}
    if body.status is not None and body.status != row.status:
        before["status"], after["status"] = row.status, body.status.value
        row.status = body.status
    if body.tags is not None:
        tags = list(dict.fromkeys(t.strip() for t in body.tags if t.strip()))
        if tags != list(row.tags or []):
            before["tags"], after["tags"] = list(row.tags or []), tags
            row.tags = tags
    if not after:
        return Alert.model_validate(row)
    row.updated_at = utcnow()
    await record_audit(
        user.username, "alert.update", alert_id, {"before": before, "after": after}, session=session
    )
    await session.flush()
    alert = Alert.model_validate(row)
    await session.commit()  # subscribers re-read the row; make the change visible before publishing
    await bus.publish("alert.updated", alert)
    return alert


@router.post("/{alert_id}/triage", response_model=Alert)
async def triage_alert(alert_id: str, user: AnalystUser, tier: LLMTier | None = None) -> Alert:
    """Force (re-)triage synchronously. Bypasses ``auto_triage`` / ``min_severity_for_llm``."""
    alert = await get_triage_service().triage_alert(alert_id, tier=tier, force=True)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    await record_audit(
        user.username,
        "alert.triage",
        alert_id,
        {"tier": tier.value if tier else None, "result_tier": alert.triage.tier if alert.triage else None},
    )
    return alert
