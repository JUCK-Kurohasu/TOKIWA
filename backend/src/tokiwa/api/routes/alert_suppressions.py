"""Alert suppressions (audit #166 / #173): list, declare an allowlist, lift.

Separate prefix (``/api/v1/alert-suppressions``) because ``GET /api/v1/alerts/{alert_id}`` would capture
``/alerts/suppressions`` (routers are registered in file order). False-positive rows are created by
``PATCH /api/v1/alerts/{id}``; allowlists silence detection for a source range, so creating one needs admin.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from tokiwa.api.deps import AnalystUser, CurrentUser, DbSession
from tokiwa.config import get_settings
from tokiwa.detect import suppress
from tokiwa.schemas.alert_suppressions import AlertSuppression, AlertSuppressionIn, AlertSuppressionKind
from tokiwa.schemas.common import Page
from tokiwa.schemas.system import Role

router = APIRouter(prefix="/api/v1/alert-suppressions", tags=["alerts"])


@router.get("", response_model=Page[AlertSuppression])
async def list_alert_suppressions(
    session: DbSession,
    _: CurrentUser,
    active: bool = True,
    kind: AlertSuppressionKind | None = None,
    source_alert_id: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Page[AlertSuppression]:
    """Suppressions in force (``active=false``: also expired / lifted ones)."""
    return await suppress.list_suppressions(
        session, active_only=active, kind=kind, source_alert_id=source_alert_id, limit=limit, offset=offset
    )


@router.post("", response_model=AlertSuppression)
async def create_alert_suppression(
    body: AlertSuppressionIn, session: DbSession, user: AnalystUser
) -> AlertSuppression:
    """Declare an allowlist (authorised scan / load test: source CIDR + hours, admin) or a false-positive rule."""
    if body.kind == AlertSuppressionKind.ALLOWLIST and user.role != Role.ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "creating an allowlist requires the admin role")
    try:
        out = await suppress.create_suppression(session, body, actor=user.username, settings=get_settings())
    except suppress.SuppressionError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None
    await session.commit()
    return out


@router.post("/{suppression_id}/lift", response_model=AlertSuppression)
async def lift_alert_suppression(
    suppression_id: str, session: DbSession, user: AnalystUser
) -> AlertSuppression:
    try:
        out = await suppress.lift_suppression(session, suppression_id, actor=user.username)
    except suppress.SuppressionNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "suppression not found") from None
    except suppress.SuppressionStateError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    await session.commit()
    return out
