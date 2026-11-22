"""Account invariants that need database-level serialization.

Why this module exists: "the last admin can be neither demoted nor deleted" and "setup runs once" are
check-then-write rules. Checked with a plain ``SELECT count(*)`` and written later, two concurrent requests both
pass the check (#92 / #170 / #95). Every such change therefore first calls :func:`lock_accounts` in the same
transaction, then re-reads what it checks.

How the lock works per database:

- **SQLite** has one writer at a time. pysqlite only sends ``BEGIN`` (deferred) before the first DML statement,
  so a no-op ``UPDATE`` makes this transaction the writer right away (the equivalent of ``BEGIN IMMEDIATE``).
  A concurrent request blocks in that statement (busy timeout) until this transaction ends, and then reads the
  committed state.
- **PostgreSQL** (and other databases with row locks): ``SELECT ... FOR UPDATE`` on every admin row. A
  concurrent demotion/deletion waits for those rows and, under READ COMMITTED, re-checks them afterwards, so it
  no longer counts an admin that was just demoted or deleted. Setup on an empty table has no admin row to lock;
  there the primary key of ``auth_state`` makes the second concurrent setup fail on INSERT.

Rule: after :func:`lock_accounts`, write only through the *same* session (e.g. ``record_audit(...,
session=session)``). On SQLite a second session would wait for the lock this session holds (self-deadlock until
the busy timeout).
"""

from __future__ import annotations

from sqlalchemy import false, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.db.models.auth import AUTH_STATE_ID, AuthStateRow
from tokiwa.db.models.core import UserRow
from tokiwa.schemas.system import Role
from tokiwa.util import utcnow


async def lock_accounts(session: AsyncSession) -> set[str]:
    """Serialize account changes until this transaction ends. Returns the ids of the current admins."""
    if session.get_bind().dialect.name == "sqlite":
        await session.execute(
            update(UserRow)
            .where(false())
            .values(role=UserRow.role)
            .execution_options(synchronize_session=False)
        )
    # TODO(verify): exercised against SQLite only (no PostgreSQL in the test environment). The FOR UPDATE
    # semantics relied on here are PostgreSQL's documented READ COMMITTED behaviour.
    rows = await session.execute(select(UserRow.id).where(UserRow.role == Role.ADMIN).with_for_update())
    return set(rows.scalars())


async def revoke_sessions(session: AsyncSession, user_id: str) -> bool:
    """Invalidate every JWT issued to the user so far (atomic ``token_version + 1``). False if no such user."""
    result = await session.execute(
        update(UserRow).where(UserRow.id == user_id).values(token_version=UserRow.token_version + 1)
    )
    return bool(getattr(result, "rowcount", 0))


async def user_count(session: AsyncSession) -> int:
    return int((await session.execute(select(func.count()).select_from(UserRow))).scalar_one())


async def setup_completed(session: AsyncSession) -> bool:
    """True once the first-run setup happened (flag), or for databases from before the flag (users exist)."""
    state = await session.get(AuthStateRow, AUTH_STATE_ID, populate_existing=True)
    if state is not None and state.setup_completed_at is not None:
        return True
    return await user_count(session) > 0


async def mark_setup_completed(session: AsyncSession, by: str) -> None:
    """Record (idempotently) that setup is done. Call after :func:`lock_accounts`; flushes with the caller."""
    state = await session.get(AuthStateRow, AUTH_STATE_ID, populate_existing=True)
    if state is None:
        session.add(AuthStateRow(id=AUTH_STATE_ID, setup_completed_at=utcnow(), setup_completed_by=by[:64]))
    elif state.setup_completed_at is None:
        state.setup_completed_at = utcnow()
        state.setup_completed_by = by[:64]
