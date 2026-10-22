"""Audit log helper. Record every security-relevant human/system decision (approvals, setting changes ...)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.db.models.core import AuditRow
from tokiwa.db.session import session_scope
from tokiwa.util import new_id, utcnow


async def record_audit(
    actor: str,
    action: str,
    target: str | None = None,
    details: dict[str, Any] | None = None,
    *,
    session: AsyncSession | None = None,
) -> None:
    row = AuditRow(
        id=new_id(), created_at=utcnow(), actor=actor, action=action, target=target, details=details or {}
    )
    if session is not None:
        session.add(row)
        return
    async with session_scope() as s:
        s.add(row)
