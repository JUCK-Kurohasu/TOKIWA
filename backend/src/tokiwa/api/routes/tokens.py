"""API tokens for sensors / gate / automation (admin only).

Only the SHA-256 hash is stored. The plaintext is returned exactly once, in the create / rotate response, and is
never written to logs or the audit trail. Deleting a token revokes it (the row is kept for the audit trail).
The same operations exist on the CLI (``tokiwa token list|revoke|rotate``) via :mod:`tokiwa.auth.api_tokens`.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status
from sqlalchemy import select

from tokiwa.api.deps import AdminUser, DbSession
from tokiwa.auth.api_tokens import issue_token, revoke_token, rotate_token
from tokiwa.db.models.core import ApiTokenRow
from tokiwa.schemas.system import ApiToken, ApiTokenCreate, ApiTokenCreated, ApiTokenRotate

router = APIRouter(prefix="/api/v1/tokens", tags=["tokens"])


@router.get("", response_model=list[ApiToken])
async def list_tokens(session: DbSession, admin: AdminUser) -> list[ApiToken]:
    stmt = select(ApiTokenRow).order_by(ApiTokenRow.created_at.desc(), ApiTokenRow.id.desc())
    rows = (await session.execute(stmt)).scalars().all()
    return [ApiToken.model_validate(r) for r in rows]


def _created(row: ApiTokenRow, plaintext: str) -> ApiTokenCreated:
    return ApiTokenCreated(**ApiToken.model_validate(row).model_dump(), token=plaintext)


@router.post("", response_model=ApiTokenCreated, status_code=status.HTTP_201_CREATED)
async def create_token(body: ApiTokenCreate, session: DbSession, admin: AdminUser) -> ApiTokenCreated:
    scopes = list(dict.fromkeys(str(s) for s in body.scopes))
    if not scopes:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "at least one scope is required")
    issued = await issue_token(
        session,
        name=body.name,
        scopes=scopes,
        actor=admin.username,
        expires_in_days=body.expires_in_days,
        allowed_sensor_ids=body.allowed_sensor_ids,
        allowed_datasets=body.allowed_datasets,
    )
    return _created(issued.row, issued.plaintext)


@router.post("/{token_id}/rotate", response_model=ApiTokenCreated, status_code=status.HTTP_201_CREATED)
async def rotate(
    token_id: str, session: DbSession, admin: AdminUser, body: ApiTokenRotate | None = None
) -> ApiTokenCreated:
    row = await session.get(ApiTokenRow, token_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    opts = body or ApiTokenRotate()
    try:
        issued = await rotate_token(
            session,
            row,
            actor=admin.username,
            grace_hours=opts.grace_hours,
            expires_in_days=opts.expires_in_days,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return _created(issued.row, issued.plaintext)


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke(token_id: str, session: DbSession, admin: AdminUser) -> Response:
    row = await session.get(ApiTokenRow, token_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    await revoke_token(session, row, actor=admin.username)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
