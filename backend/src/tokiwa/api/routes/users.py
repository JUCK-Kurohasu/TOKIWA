"""User administration (admin only).

Invariants: an admin cannot delete themselves, and the last remaining admin can be neither deleted nor
demoted (otherwise nobody could manage users/tokens/settings any more). Every change is audit-logged.

A password or role change, and ``POST /users/{id}/revoke-sessions``, invalidate the user's existing JWTs
(``users.token_version``, #34).

Changes run under :func:`tokiwa.auth.accounts.lock_accounts`: two admins demoting/deleting each other at the
same moment must not both pass the "more than one admin" check (#92 / #170). After the lock, the target and the
acting admin are re-read, because either may have changed while this request waited.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.api.deps import AdminUser, DbSession
from tokiwa.audit import record_audit
from tokiwa.auth.accounts import lock_accounts, revoke_sessions
from tokiwa.auth.security import hash_password_async
from tokiwa.db.models.core import UserRow
from tokiwa.schemas.system import Role, User, UserCreate
from tokiwa.schemas.users import UserUpdate
from tokiwa.util import new_id, utcnow

router = APIRouter(prefix="/api/v1/users", tags=["users"])


async def _get_or_404(session: AsyncSession, user_id: str) -> UserRow:
    row = await session.get(UserRow, user_id, populate_existing=True)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return row


async def _lock_and_recheck(session: AsyncSession, admin: User) -> set[str]:
    """Take the account lock, then make sure the caller is still an admin. Returns the current admin ids."""
    admins = await lock_accounts(session)
    if admin.id not in admins:
        # Demoted or deleted by a concurrent request after this one was authorized.
        raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
    return admins


@router.get("", response_model=list[User])
async def list_users(session: DbSession, admin: AdminUser) -> list[User]:
    rows = (await session.execute(select(UserRow).order_by(UserRow.created_at, UserRow.id))).scalars().all()
    return [User.model_validate(r) for r in rows]


@router.post("", response_model=User, status_code=status.HTTP_201_CREATED)
async def create_user(body: UserCreate, session: DbSession, admin: AdminUser) -> User:
    exists = (
        await session.execute(select(UserRow.id).where(UserRow.username == body.username))
    ).scalar_one_or_none()
    if exists is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")
    row = UserRow(
        id=new_id(),
        username=body.username,
        password_hash=await hash_password_async(body.password),
        role=body.role,
        created_at=utcnow(),
    )
    session.add(row)
    await session.flush()
    await record_audit(
        admin.username,
        "user.create",
        row.id,
        {"username": row.username, "role": str(body.role)},
        session=session,
    )
    return User.model_validate(row)


@router.patch("/{user_id}", response_model=User)
async def update_user(user_id: str, body: UserUpdate, session: DbSession, admin: AdminUser) -> User:
    # Hash before taking the lock: scrypt is slow and the lock blocks every other account change.
    new_hash = await hash_password_async(body.password) if body.password is not None else None
    admins = await _lock_and_recheck(session, admin)
    row = await _get_or_404(session, user_id)
    details: dict[str, object] = {"username": row.username}
    if body.role is not None and body.role != row.role:
        if row.role == Role.ADMIN and len(admins) <= 1:
            raise HTTPException(status.HTTP_409_CONFLICT, "cannot demote the last admin")
        details["role"] = {"from": row.role, "to": str(body.role)}
        row.role = body.role
    if new_hash is not None:
        row.password_hash = new_hash
        details["password_changed"] = True  # never log the password itself
    if len(details) > 1:  # something actually changed
        await session.flush()
        # Existing logins of that user end (also the caller's own when changing themselves): a password or role
        # change is often the response to a stolen session (#34).
        await revoke_sessions(session, row.id)
        details["sessions_revoked"] = True
        await record_audit(admin.username, "user.update", row.id, details, session=session)
    return User.model_validate(row)


@router.post("/{user_id}/revoke-sessions", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_user_sessions(user_id: str, session: DbSession, admin: AdminUser) -> Response:
    """Log the user out everywhere: every JWT issued to them so far stops working (#34)."""
    row = await _get_or_404(session, user_id)
    await revoke_sessions(session, row.id)
    await record_audit(
        admin.username, "user.sessions_revoked", row.id, {"username": row.username}, session=session
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: str, session: DbSession, admin: AdminUser) -> Response:
    if user_id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot delete yourself")
    admins = await _lock_and_recheck(session, admin)
    row = await _get_or_404(session, user_id)
    if row.role == Role.ADMIN and len(admins) <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "cannot delete the last admin")
    await session.delete(row)
    await record_audit(
        admin.username, "user.delete", user_id, {"username": row.username, "role": row.role}, session=session
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
