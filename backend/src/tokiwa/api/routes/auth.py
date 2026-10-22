"""First-run setup, login, current user."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select

from tokiwa import __version__
from tokiwa.api.deps import CurrentUser, DbSession
from tokiwa.auth.security import create_access_token, hash_password, verify_password
from tokiwa.db.models.core import UserRow
from tokiwa.schemas.system import AuthStatus, LoginRequest, Role, TokenResponse, User, UserCreate
from tokiwa.util import new_id, utcnow

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


async def _user_count(session: DbSession) -> int:
    return int((await session.execute(select(func.count()).select_from(UserRow))).scalar_one())


@router.get("/status", response_model=AuthStatus)
async def auth_status(session: DbSession) -> AuthStatus:
    return AuthStatus(setup_required=await _user_count(session) == 0, version=__version__)


@router.post("/setup", response_model=TokenResponse)
async def setup(body: UserCreate, session: DbSession) -> TokenResponse:
    """Create the first admin. Only allowed while no user exists."""
    if await _user_count(session) > 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "setup already completed")
    row = UserRow(
        id=new_id(),
        username=body.username,
        password_hash=hash_password(body.password),
        role=Role.ADMIN,
        created_at=utcnow(),
        last_login=utcnow(),
    )
    session.add(row)
    await session.flush()
    token, ttl = create_access_token(row.id, row.username, row.role)
    return TokenResponse(access_token=token, expires_in=ttl, user=User.model_validate(row))


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, session: DbSession) -> TokenResponse:
    row = (
        await session.execute(select(UserRow).where(UserRow.username == body.username))
    ).scalar_one_or_none()
    if row is None or not verify_password(body.password, row.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    row.last_login = utcnow()
    token, ttl = create_access_token(row.id, row.username, row.role)
    return TokenResponse(access_token=token, expires_in=ttl, user=User.model_validate(row))


@router.get("/me", response_model=User)
async def me(user: CurrentUser) -> User:
    return user
