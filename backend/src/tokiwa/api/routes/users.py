"""User administration (admin only).

Invariants: an admin cannot delete themselves, and the last remaining admin can be neither deleted nor
demoted (otherwise nobody could manage users/tokens/settings any more). Every change is audit-logged.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.api.deps import AdminUser, DbSession
from tokiwa.audit import record_audit
from tokiwa.auth.security import hash_password
from tokiwa.db.models.core import UserRow
from tokiwa.schemas.system import Role, User, UserCreate
from tokiwa.schemas.users import UserUpdate
from tokiwa.util import new_id, utcnow

router = APIRouter(prefix="/api/v1/users", tags=["users"])


async def _admin_count(session: AsyncSession) -> int:
    stmt = select(func.count()).select_from(UserRow).where(UserRow.role == Role.ADMIN)
    return int((await session.execute(stmt)).scalar_one())


async def _get_or_404(session: AsyncSession, user_id: str) -> UserRow:
    row = await session.get(UserRow, user_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return row


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
        password_hash=hash_password(body.password),
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
    row = await _get_or_404(session, user_id)
    details: dict[str, object] = {"username": row.username}
    if body.role is not None and body.role != row.role:
        if row.role == Role.ADMIN and await _admin_count(session) <= 1:
            raise HTTPException(status.HTTP_409_CONFLICT, "cannot demote the last admin")
        details["role"] = {"from": row.role, "to": str(body.role)}
        row.role = body.role
    if body.password is not None:
        row.password_hash = hash_password(body.password)
        details["password_changed"] = True  # never log the password itself
    if len(details) > 1:  # something actually changed
        await session.flush()
        await record_audit(admin.username, "user.update", row.id, details, session=session)
    return User.model_validate(row)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: str, session: DbSession, admin: AdminUser) -> Response:
    if user_id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot delete yourself")
    row = await _get_or_404(session, user_id)
    if row.role == Role.ADMIN and await _admin_count(session) <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "cannot delete the last admin")
    await session.delete(row)
    await record_audit(
        admin.username, "user.delete", user_id, {"username": row.username, "role": row.role}, session=session
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
