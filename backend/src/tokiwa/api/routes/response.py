"""Response actions (FR-12): list, propose, approve, reject, revert; suppressions (audit #63).

Writes require analyst or admin."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import Field

from tokiwa.api.deps import AnalystUser, CurrentUser
from tokiwa.respond import service, suppress
from tokiwa.schemas.common import Page
from tokiwa.schemas.response import ActionProposal, ActionProposer, ActionStatus, ResponseAction
from tokiwa.schemas.suppressions import ResponseSuppression, ResponseSuppressionIn, SuppressOptions

router = APIRouter(prefix="/api/v1/response", tags=["response"])


class RejectRequest(SuppressOptions):
    """``suppress_hours`` / ``suppress_permanent``: do not re-propose this type + target (audit #63)."""

    reason: str | None = Field(default=None, max_length=2000)


class RevertRequest(SuppressOptions):
    reason: str | None = Field(default=None, max_length=2000)


def _http(exc: Exception) -> HTTPException:
    if isinstance(exc, service.ActionNotFound):
        return HTTPException(status.HTTP_404_NOT_FOUND, "action not found")
    if isinstance(exc, service.ActionStateError):
        return HTTPException(status.HTTP_409_CONFLICT, str(exc))
    if isinstance(exc, service.ActionValidationError):
        return HTTPException(422, str(exc))
    if isinstance(exc, service.ActionExecutionError):
        return HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))
    if isinstance(exc, suppress.SuppressionNotFound):
        return HTTPException(status.HTTP_404_NOT_FOUND, "suppression not found")
    if isinstance(exc, suppress.SuppressionStateError):
        return HTTPException(status.HTTP_409_CONFLICT, str(exc))
    raise exc


_ERRORS = (
    service.ActionNotFound,
    service.ActionStateError,
    service.ActionValidationError,
    service.ActionExecutionError,
    suppress.SuppressionNotFound,
    suppress.SuppressionStateError,
)


@router.get("/actions", response_model=Page[ResponseAction])
async def list_actions(
    user: CurrentUser,
    status_: ActionStatus | None = Query(default=None, alias="status"),
    incident_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Page[ResponseAction]:
    return await service.list_actions(status=status_, incident_id=incident_id, limit=limit, offset=offset)


@router.get("/actions/{action_id}", response_model=ResponseAction)
async def get_action(action_id: str, user: CurrentUser) -> ResponseAction:
    try:
        return await service.get_action(action_id)
    except _ERRORS as exc:
        raise _http(exc) from None


@router.post("/actions", response_model=ResponseAction)
async def propose(body: ActionProposal, user: AnalystUser) -> ResponseAction:
    """Create a proposal (status=proposed). Nothing runs until someone approves it."""
    # Callers cannot impersonate the rule engine / LLM / policy.
    proposal = body.model_copy(update={"proposed_by": ActionProposer.USER})
    try:
        return await service.create_proposal(proposal, actor=user.username)
    except _ERRORS as exc:
        raise _http(exc) from None


@router.post("/actions/{action_id}/approve", response_model=ResponseAction)
async def approve(action_id: str, user: AnalystUser) -> ResponseAction:
    try:
        return await service.approve_action(action_id, actor=user.username)
    except _ERRORS as exc:
        raise _http(exc) from None


@router.post("/actions/{action_id}/reject", response_model=ResponseAction)
async def reject(action_id: str, user: AnalystUser, body: RejectRequest | None = None) -> ResponseAction:
    try:
        return await service.reject_action(
            action_id, actor=user.username, reason=body.reason if body else None, suppress_options=body
        )
    except _ERRORS as exc:
        raise _http(exc) from None


@router.post("/actions/{action_id}/revert", response_model=ResponseAction)
async def revert(action_id: str, user: AnalystUser, body: RevertRequest | None = None) -> ResponseAction:
    try:
        return await service.revert_action(
            action_id, actor=user.username, reason=body.reason if body else None, suppress_options=body
        )
    except _ERRORS as exc:
        raise _http(exc) from None


# ---------------------------------------------------------------- suppressions (audit #63)


@router.get("/suppressions", response_model=Page[ResponseSuppression])
async def list_suppressions(
    user: CurrentUser,
    active: bool = True,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Page[ResponseSuppression]:
    """Suppressions in force (``active=false``: also expired / lifted ones)."""
    return await suppress.list_suppressions(active_only=active, limit=limit, offset=offset)


@router.post("/suppressions", response_model=ResponseSuppression)
async def create_suppression(body: ResponseSuppressionIn, user: AnalystUser) -> ResponseSuppression:
    """Suppress a type + target ahead of time (e.g. a shared NAT / monitoring address). Mode ``suppress``."""
    try:
        return await suppress.create_suppression(body, actor=user.username)
    except _ERRORS as exc:
        raise _http(exc) from None


@router.post("/suppressions/{suppression_id}/lift", response_model=ResponseSuppression)
async def lift_suppression(suppression_id: str, user: AnalystUser) -> ResponseSuppression:
    try:
        return await suppress.lift_suppression(suppression_id, actor=user.username)
    except _ERRORS as exc:
        raise _http(exc) from None
