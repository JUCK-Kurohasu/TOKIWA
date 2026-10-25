"""API tokens for sensors / gate / automation (admin only).

Only the SHA-256 hash is stored. The plaintext is returned exactly once, in the create response, and is never
written to logs or the audit trail. Deleting a token revokes it (the row is kept for the audit trail).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status
from sqlalchemy import select

from tokiwa.api.deps import AdminUser, DbSession
from tokiwa.audit import record_audit
from tokiwa.auth.security import generate_api_token
from tokiwa.db.models.core import ApiTokenRow
from tokiwa.schemas.system import ApiToken, ApiTokenCreate, ApiTokenCreated
from tokiwa.util import new_id, utcnow

router = APIRouter(prefix="/api/v1/tokens", tags=["tokens"])


@router.get("", response_model=list[ApiToken])
async def list_tokens(session: DbSession, admin: AdminUser) -> list[ApiToken]:
    stmt = select(ApiTokenRow).order_by(ApiTokenRow.created_at.desc(), ApiTokenRow.id.desc())
    rows = (await session.execute(stmt)).scalars().all()
    return [ApiToken.model_validate(r) for r in rows]


@router.post("", response_model=ApiTokenCreated, status_code=status.HTTP_201_CREATED)
async def create_token(body: ApiTokenCreate, session: DbSession, admin: AdminUser) -> ApiTokenCreated:
    scopes = list(dict.fromkeys(str(s) for s in body.scopes))
    if not scopes:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "at least one scope is required")
    token, digest, prefix = generate_api_token()
    row = ApiTokenRow(
        id=new_id(), name=body.name, token_hash=digest, prefix=prefix, scopes=scopes, created_at=utcnow()
    )
    session.add(row)
    await session.flush()
    await record_audit(
        admin.username,
        "token.create",
        row.id,
        {"name": row.name, "scopes": scopes, "prefix": prefix},
        session=session,
    )
    return ApiTokenCreated(**ApiToken.model_validate(row).model_dump(), token=token)


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_token(token_id: str, session: DbSession, admin: AdminUser) -> Response:
    row = await session.get(ApiTokenRow, token_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    if not row.revoked:
        row.revoked = True
        await record_audit(
            admin.username,
            "token.revoke",
            row.id,
            {"name": row.name, "prefix": row.prefix},
            session=session,
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
