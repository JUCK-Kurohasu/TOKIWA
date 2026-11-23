"""Login / setup throttling (#56): a sliding-window failure count per user name + source IP and per source IP.

Why the database and not process memory: several uvicorn workers would each allow the full number of attempts,
and a restart would reset the counters. Failures are rare, so one small row per failure is cheap; rows older
than the window are deleted whenever a new failure is recorded.

Semantics: a scope is locked while it has at least ``limit`` failures in the last ``login_lockout_minutes``. It
unlocks when the oldest of those failures leaves the window. Refused (locked) attempts are not verified and not
counted, so a legitimate user who keeps retrying does not extend the lock, and an attacker gets at most
``limit`` guesses per window and pair. A successful login clears the user + IP scope (not the per-IP scope, so
logging into one's own account does not reset a spraying count).

Writes go through the caller's session (see :mod:`tokiwa.auth.accounts` for why a second session must not be
used while the request may hold the SQLite write lock); the caller commits.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.config import get_settings
from tokiwa.db.models.auth import LoginFailureRow
from tokiwa.util import new_id, sha256_hex, utcnow

# Module-level so tests can move the clock (monkeypatch ``throttle.now``).
now = utcnow


@dataclass(frozen=True)
class Scope:
    key: str
    limit: int


def _window() -> timedelta:
    return timedelta(minutes=get_settings().auth.login_lockout_minutes)


def _user_key(username: str, ip: str | None) -> str:
    return sha256_hex(f"user|{username.strip().lower()[:128]}|{ip or '-'}")


def _ip_key(ip: str | None) -> str:
    return sha256_hex(f"ip|{ip or '-'}")


def login_scopes(username: str, ip: str | None) -> list[Scope]:
    auth = get_settings().auth
    scopes = [
        Scope(_user_key(username, ip), auth.login_max_failures),
        Scope(_ip_key(ip), auth.login_max_failures_per_ip),
    ]
    return [s for s in scopes if s.limit > 0]


def setup_scopes(ip: str | None) -> list[Scope]:
    """Wrong setup codes count against the source IP (there is no user name yet)."""
    limit = get_settings().auth.login_max_failures_per_ip
    return [Scope(_ip_key(ip), limit)] if limit > 0 else []


async def retry_after(session: AsyncSession, scopes: list[Scope]) -> int | None:
    """Seconds until the most restrictive locked scope opens again, or None if none is locked."""
    current = now()
    start = current - _window()
    wait: float | None = None
    for scope in scopes:
        stmt = (
            select(LoginFailureRow.created_at)
            .where(LoginFailureRow.key == scope.key, LoginFailureRow.created_at > start)
            .order_by(LoginFailureRow.created_at.desc())
            .limit(scope.limit)
        )
        recent: list[datetime] = list((await session.execute(stmt)).scalars())
        if len(recent) >= scope.limit:
            opens = recent[-1] + _window()  # the oldest of the last `limit` failures leaves the window
            seconds = (opens - current).total_seconds()
            wait = seconds if wait is None else max(wait, seconds)
    return max(1, math.ceil(wait)) if wait is not None else None


async def over_limit(session: AsyncSession, scopes: list[Scope]) -> bool:
    """True if a scope has *more* than ``limit`` failures in the window (i.e. counting the caller's own pending
    row, see :func:`record_failure`)."""
    start = now() - _window()
    for scope in scopes:
        stmt = (
            select(LoginFailureRow.id)
            .where(LoginFailureRow.key == scope.key, LoginFailureRow.created_at > start)
            .limit(scope.limit + 1)
        )
        if len((await session.execute(stmt)).all()) > scope.limit:
            return True
    return False


async def record_failure(session: AsyncSession, scopes: list[Scope]) -> list[str]:
    """Add one failure to each scope (and prune expired rows). Returns the new row ids.

    Login records the attempt *before* checking anything, commits, and only then counts (:func:`over_limit`,
    which includes its own row); it :func:`forget` s the rows if refused or on success. Checking first and
    recording after the slow password check would let a burst of parallel requests all pass the check: N
    connections would get N guesses instead of ``limit``. Because every request commits its row before it
    counts, the k-th committed attempt sees at least k rows, so at most ``limit`` attempts proceed.
    """
    current = now()
    await session.execute(delete(LoginFailureRow).where(LoginFailureRow.created_at <= current - _window()))
    ids = []
    for scope in scopes:
        row = LoginFailureRow(id=new_id(), key=scope.key, created_at=current)
        session.add(row)
        ids.append(row.id)
    await session.flush()
    return ids


async def forget(session: AsyncSession, ids: list[str]) -> None:
    if ids:
        await session.execute(delete(LoginFailureRow).where(LoginFailureRow.id.in_(ids)))


async def clear_user(session: AsyncSession, username: str, ip: str | None) -> None:
    """After a successful login: forget that pair's failures (the per-IP count stays)."""
    await session.execute(delete(LoginFailureRow).where(LoginFailureRow.key == _user_key(username, ip)))
