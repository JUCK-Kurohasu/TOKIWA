"""First-run setup, login, current user."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from tokiwa import __version__
from tokiwa.api.deps import CurrentUser, DbSession
from tokiwa.audit import record_audit
from tokiwa.auth import throttle
from tokiwa.auth.accounts import (
    lock_accounts,
    mark_setup_completed,
    revoke_sessions,
    setup_completed,
    user_count,
)
from tokiwa.auth.security import create_access_token, hash_password_async, verify_password_async
from tokiwa.auth.setup_code import (
    announce_setup_code,
    check_setup_code,
    consume_setup_code,
    current_setup_code,
    ensure_setup_code,
)
from tokiwa.config import get_settings
from tokiwa.db.models.core import UserRow
from tokiwa.db.session import session_scope
from tokiwa.runtime import on_startup
from tokiwa.schemas.auth import SetupRequest
from tokiwa.schemas.system import AuthStatus, LoginRequest, Role, TokenResponse, User
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@on_startup
async def _check_accounts() -> None:
    """Startup: announce the setup code while setup is pending; otherwise backfill the setup flag for
    databases from before it existed, drop a leftover setup code, and warn when no admin is left."""
    try:
        admins: set[str] = set()
        async with session_scope() as session:
            if await user_count(session) > 0:
                admins = await lock_accounts(session)
                await mark_setup_completed(session, by="(existing users)")
                pending = False
            else:
                pending = not await setup_completed(session)
        if pending:
            if get_settings().auth.setup_code_required:
                code = current_setup_code()
                if code:
                    announce_setup_code(code)
                else:
                    ensure_setup_code()
            return
        consume_setup_code()  # e.g. the first admin was created with `tokiwa user create`
        if not admins:
            log.warning(
                "no user has the admin role: users, API tokens and settings cannot be managed from the UI. "
                "Create one on the server with: tokiwa user create <name> --role admin"
            )
    except Exception:
        log.exception("account check at startup failed")


@router.get("/status", response_model=AuthStatus)
async def auth_status(session: DbSession) -> AuthStatus:
    required = not await setup_completed(session)
    return AuthStatus(
        setup_required=required,
        version=__version__,
        setup_code_required=required and get_settings().auth.setup_code_required,
    )


@router.post("/setup", response_model=TokenResponse)
async def setup(body: SetupRequest, request: Request, session: DbSession) -> TokenResponse:
    """Create the first admin. Only allowed once per installation (not again when all users are deleted).

    Requires the one-time setup code from the server log / ``data_dir/setup-code`` (#95), so that being first on
    the network is not enough to take over a fresh installation.
    """
    if await setup_completed(session):
        raise HTTPException(status.HTTP_409_CONFLICT, "setup already completed")
    ip = _client_ip(request)
    if get_settings().auth.setup_code_required:
        scopes = throttle.setup_scopes(ip)
        await _refuse_if_locked(session, scopes)
        ensure_setup_code()  # re-created (and logged) if it went missing, so the operator can always find one
        if not check_setup_code(body.setup_code):
            log.warning("first-run setup refused: missing or wrong setup code (client %s)", ip)
            await throttle.record_failure(session, scopes)
            await record_audit(
                body.username,
                "auth.setup.failure",
                None,
                {"client_ip": ip, "reason": "setup_code"},
                session=session,
            )
            await session.commit()  # keep the failure although the request is rejected
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "missing or wrong setup code (see the server log or data_dir/setup-code)",
            )
    password_hash = await hash_password_async(body.password)  # before the lock (slow)
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
    consume_setup_code()
    await record_audit(
        body.username,
        "auth.setup",
        row.id,
        {"username": row.username, "client_ip": ip},
        session=session,
    )
    token, ttl = create_access_token(row.id, row.username, row.role, row.token_version)
    return TokenResponse(access_token=token, expires_in=ttl, user=User.model_validate(row))


async def _refuse_if_locked(session: DbSession, scopes: list[throttle.Scope]) -> None:
    wait = await throttle.retry_after(session, scopes)
    if wait is not None:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many failed attempts; try again later",
            headers={"Retry-After": str(wait)},
        )


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, session: DbSession) -> TokenResponse:
    """Password login with throttling, constant-time user lookup and an audit trail (#56).

    The attempt is recorded as a failure (and committed) *before* the lock check and the slow password check,
    and forgotten when refused or on success, so parallel requests cannot exceed the limit (see
    :func:`tokiwa.auth.throttle.record_failure`). Unknown user names cost one scrypt like known ones.
    """
    ip = _client_ip(request)
    scopes = throttle.login_scopes(body.username, ip)
    pending = await throttle.record_failure(session, scopes)
    await session.commit()
    if await throttle.over_limit(session, scopes):
        await throttle.forget(session, pending)  # refused attempts are not counted (do not extend the lock)
        await session.commit()
        wait = await throttle.retry_after(session, scopes) or 1
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many failed attempts; try again later",
            headers={"Retry-After": str(wait)},
        )
    row = (
        await session.execute(select(UserRow).where(UserRow.username == body.username))
    ).scalar_one_or_none()
    ok = await verify_password_async(body.password, row.password_hash if row is not None else None)
    if row is None or not ok:
        locked = await throttle.retry_after(session, scopes) is not None
        await record_audit(
            body.username[:128],
            "auth.login.failure",
            row.id if row is not None else None,
            {"client_ip": ip, "known_user": row is not None, "locked": locked},  # never the password
            session=session,
        )
        await session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    await throttle.forget(session, pending)
    await throttle.clear_user(session, body.username, ip)
    row.last_login = utcnow()
    await record_audit(row.username, "auth.login.success", row.id, {"client_ip": ip}, session=session)
    token, ttl = create_access_token(row.id, row.username, row.role, row.token_version)
    return TokenResponse(access_token=token, expires_in=ttl, user=User.model_validate(row))


@router.get("/me", response_model=User)
async def me(user: CurrentUser) -> User:
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(user: CurrentUser, request: Request, session: DbSession) -> Response:
    """Server-side logout: invalidates **every** JWT of this user (all browsers/devices), not only this one.

    A JWT cannot be revoked individually without a per-token deny list; the per-user version counter covers the
    cases that matter (stolen token, shared machine) at the cost of logging out the user's other sessions (#34).
    """
    await revoke_sessions(session, user.id)
    await record_audit(
        user.username, "auth.logout", user.id, {"client_ip": _client_ip(request)}, session=session
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
