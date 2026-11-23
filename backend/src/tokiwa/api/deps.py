"""FastAPI dependencies shared by all routes.

- ``DbSession``      async SQLAlchemy session (commit on success)
- ``CurrentUser``    any logged-in user (JWT bearer)
- ``AnalystUser``    role analyst or admin (write operations on alerts/incidents/actions)
- ``AdminUser``      role admin (users, tokens, settings)
- ``IngestToken``    API token with scope "ingest" (X-Tokiwa-Token header or Bearer tkw_...)
- ``GateToken``      API token with scope "gate"
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Annotated, Any

import jwt
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.auth.api_tokens import is_expired
from tokiwa.auth.security import API_TOKEN_PREFIX, decode_access_token, hash_api_token, token_version_matches
from tokiwa.db.models.core import ApiTokenRow, UserRow
from tokiwa.db.session import get_session
from tokiwa.schemas.system import ApiToken, Role, User
from tokiwa.util import utcnow

# scope="function": the session is committed (or rolled back) when the route returns, *before* the response is
# sent -- see tokiwa.db.session.get_session. Keep it: the default "request" scope commits after the client already
# has its 2xx (audit #91).
DbSession = Annotated[AsyncSession, Depends(get_session, scope="function")]


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return None
    return value.strip()


async def user_from_token(session: AsyncSession, token: str | None) -> User:
    """Resolve a user JWT. Shared by header auth and the SSE stream (which must use a query parameter)."""
    if not token or token.startswith(API_TOKEN_PREFIX):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "not authenticated", headers={"WWW-Authenticate": "Bearer"}
        )
    try:
        claims = decode_access_token(token)
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "invalid token", headers={"WWW-Authenticate": "Bearer"}
        ) from exc
    row = await session.get(UserRow, claims.get("sub"))
    if row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found")
    if not token_version_matches(claims, row.token_version):
        # Password/role changed, logged out or sessions revoked since this JWT was issued (#34).
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "token revoked", headers={"WWW-Authenticate": "Bearer"}
        )
    return User.model_validate(row)


async def get_current_user(
    session: DbSession,
    authorization: Annotated[str | None, Header()] = None,
) -> User:
    """JWT from the Authorization header only.

    The ``?access_token=`` query form is accepted solely by ``GET /api/v1/stream`` (EventSource cannot set
    headers); accepting it everywhere would leak JWTs into access logs, proxies and browser history.
    """
    return await user_from_token(session, _bearer(authorization))


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_role(*roles: Role) -> Callable[..., Coroutine[Any, Any, User]]:
    async def dep(user: CurrentUser) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        return user

    return dep


AnalystUser = Annotated[User, Depends(require_role(Role.ADMIN, Role.ANALYST))]
AdminUser = Annotated[User, Depends(require_role(Role.ADMIN))]


def require_token_scope(scope: str) -> Callable[..., Coroutine[Any, Any, ApiToken]]:
    async def dep(
        session: DbSession,
        x_tokiwa_token: Annotated[str | None, Header()] = None,
        authorization: Annotated[str | None, Header()] = None,
    ) -> ApiToken:
        token = x_tokiwa_token or _bearer(authorization)
        if not token or not token.startswith(API_TOKEN_PREFIX):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API token required")
        row = (
            await session.execute(select(ApiTokenRow).where(ApiTokenRow.token_hash == hash_api_token(token)))
        ).scalar_one_or_none()
        if row is None or row.revoked:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid API token")
        if is_expired(row):  # audit #163: expires_at NULL = never
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API token expired")
        if scope not in row.scopes:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"token lacks scope {scope!r}")
        row.last_used = utcnow()
        return ApiToken.model_validate(row)

    return dep


IngestToken = Annotated[ApiToken, Depends(require_token_scope("ingest"))]
GateToken = Annotated[ApiToken, Depends(require_token_scope("gate"))]
