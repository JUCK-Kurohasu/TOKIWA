"""First-run setup, login, current user."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from tokiwa import __version__
from tokiwa.api.deps import CurrentUser, DbSession
from tokiwa.audit import record_audit
from tokiwa.auth.accounts import lock_accounts, mark_setup_completed, setup_completed, user_count
from tokiwa.auth.security import create_access_token, hash_password, verify_password
from tokiwa.db.models.core import UserRow
from tokiwa.db.session import session_scope
from tokiwa.runtime import on_startup
from tokiwa.schemas.system import AuthStatus, LoginRequest, Role, TokenResponse, User, UserCreate
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@on_startup
async def _check_accounts() -> None:
    """Backfill the setup flag for databases from before it existed, and warn when no admin is left."""
    try:
        async with session_scope() as session:
            if await user_count(session) == 0:
                return
            admins = await lock_accounts(session)
            await mark_setup_completed(session, by="(existing users)")
        if not admins:
            log.warning(
                "no user has the admin role: users, API tokens and settings cannot be managed from the UI. "
                "Create one on the server with: tokiwa user create <name> --role admin"
            )
    except Exception:
        log.exception("account check at startup failed")


@router.get("/status", response_model=AuthStatus)
async def auth_status(session: DbSession) -> AuthStatus:
    return AuthStatus(setup_required=not await setup_completed(session), version=__version__)


@router.post("/setup", response_model=TokenResponse)
async def setup(body: UserCreate, session: DbSession) -> TokenResponse:
    """Create the first admin. Only allowed once per installation (not again when all users are deleted)."""
    if await setup_completed(session):
        raise HTTPException(status.HTTP_409_CONFLICT, "setup already completed")
    password_hash = hash_password(body.password)  # before the lock (slow)
    await lock_accounts(session)
    if await setup_completed(session):  # another setup / `tokiwa user create` won the race
        raise HTTPException(status.HTTP_409_CONFLICT, "setup already completed")
    now = utcnow()
    row = UserRow(
        id=new_id(),
        username=body.username,
        password_hash=password_hash,
        role=Role.ADMIN,
        created_at=now,
        last_login=now,
    )
    session.add(row)
    await mark_setup_completed(session, by=body.username)
    try:
        await session.flush()
    except IntegrityError as exc:  # PostgreSQL: concurrent setup inserted auth_state first
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "setup already completed") from exc
    await record_audit(body.username, "auth.setup", row.id, {"username": row.username}, session=session)
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
