"""Read-access log viewer (admin only, audit #167). Rows are written by ``tokiwa.access_log``."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import select

from tokiwa.access_log import access_logger
from tokiwa.api.deps import AdminUser, DbSession
from tokiwa.api.pagination import PageParams, paginate
from tokiwa.db.models.access import AccessLogRow
from tokiwa.schemas.access import AccessLogEntry
from tokiwa.schemas.common import Page
from tokiwa.util import ensure_utc

router = APIRouter(prefix="/api/v1/audit/access", tags=["audit"])


@router.get("", response_model=Page[AccessLogEntry])
async def list_access(
    session: DbSession,
    admin: AdminUser,
    page: PageParams,
    actor: Annotated[str | None, Query(max_length=128)] = None,
    route: Annotated[
        str | None, Query(max_length=128, description="exact, or a prefix ending with '*'")
    ] = None,
    target: Annotated[str | None, Query(max_length=256)] = None,
    since: datetime | None = None,
) -> Page[AccessLogEntry]:
    await access_logger.flush(session)  # write merged counters first so hits/items are current
    await session.flush()
    stmt = select(AccessLogRow)
    if actor:
        stmt = stmt.where(AccessLogRow.actor == actor)
    if route:
        if route.endswith("*"):
            stmt = stmt.where(AccessLogRow.route.startswith(route[:-1], autoescape=True))
        else:
            stmt = stmt.where(AccessLogRow.route == route)
    if target:
        stmt = stmt.where(AccessLogRow.target == target)
    if since is not None:
        stmt = stmt.where(AccessLogRow.last_at >= ensure_utc(since))
    stmt = stmt.order_by(AccessLogRow.created_at.desc(), AccessLogRow.id.desc())
    return await paginate(session, stmt, page, AccessLogEntry.model_validate)
