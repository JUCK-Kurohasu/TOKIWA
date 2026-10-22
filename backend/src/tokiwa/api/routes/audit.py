"""Audit log viewer (admin only). Entries are written by ``tokiwa.audit.record_audit`` across modules."""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import select

from tokiwa.api.deps import AdminUser, DbSession
from tokiwa.api.pagination import PageParams, paginate
from tokiwa.db.models.core import AuditRow
from tokiwa.schemas.common import Page
from tokiwa.schemas.system import AuditEntry

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("", response_model=Page[AuditEntry])
async def list_audit(
    session: DbSession,
    admin: AdminUser,
    page: PageParams,
    action: str | None = None,
    actor: str | None = None,
) -> Page[AuditEntry]:
    stmt = select(AuditRow)
    if action:
        stmt = stmt.where(AuditRow.action == action)
    if actor:
        stmt = stmt.where(AuditRow.actor == actor)
    stmt = stmt.order_by(AuditRow.created_at.desc(), AuditRow.id.desc())
    return await paginate(session, stmt, page, AuditEntry.model_validate)
