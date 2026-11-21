"""Last-admin protection under concurrency (#92 / #170) and the one-shot setup flag.

The race tests line both requests up right after authentication (a barrier inside ``user_from_token``), so the
two handlers run their check-then-write sections at the same time instead of one finishing before the other
starts. Without serialization both requests succeed and no admin is left.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from typing import Any

import httpx
import pytest
from sqlalchemy import delete

from tokiwa.api import deps
from tokiwa.api.routes import auth as auth_routes
from tokiwa.auth.accounts import lock_accounts, setup_completed
from tokiwa.auth.security import hash_password
from tokiwa.db.models.auth import AUTH_STATE_ID, AuthStateRow
from tokiwa.db.models.core import UserRow
from tokiwa.db.session import session_scope
from tokiwa.util import new_id

from .conftest import MakeUser


async def _me(client: httpx.AsyncClient, headers: dict[str, str]) -> dict[str, str]:
    r = await client.get("/api/v1/auth/me", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


async def _admin_count(client: httpx.AsyncClient, headers: dict[str, str]) -> int:
    r = await client.get("/api/v1/users", headers=headers)
    assert r.status_code == 200, r.text
    return sum(1 for u in r.json() if u["role"] == "admin")


@contextmanager
def _auth_barrier(monkeypatch: pytest.MonkeyPatch, parties: int) -> Iterator[None]:
    """Hold each request after it authenticated until ``parties`` requests have done so."""
    original: Callable[..., Awaitable[Any]] = deps.user_from_token
    arrived = 0
    released = asyncio.Event()

    async def gated(*args: Any, **kwargs: Any) -> Any:
        nonlocal arrived
        user = await original(*args, **kwargs)
        arrived += 1
        if arrived >= parties:
            released.set()
        await asyncio.wait_for(released.wait(), timeout=10)
        return user

    with monkeypatch.context() as m:
        m.setattr(deps, "user_from_token", gated)
        yield


async def test_concurrent_mutual_demotion_keeps_one_admin(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    make_user: MakeUser,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin2_headers = await make_user("admin", "admin2")
    admin = await _me(client, admin_headers)
    admin2 = await _me(client, admin2_headers)
    with _auth_barrier(monkeypatch, 2):
        r1, r2 = await asyncio.gather(
            client.patch(f"/api/v1/users/{admin2['id']}", json={"role": "viewer"}, headers=admin_headers),
            client.patch(f"/api/v1/users/{admin['id']}", json={"role": "viewer"}, headers=admin2_headers),
        )
    codes = sorted([r1.status_code, r2.status_code])
    assert codes[0] == 200 and codes[1] in (403, 409), (r1.text, r2.text)
    survivor = admin_headers if r1.status_code == 200 else admin2_headers
    assert await _admin_count(client, survivor) == 1


async def test_concurrent_mutual_delete_keeps_one_admin(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    make_user: MakeUser,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin2_headers = await make_user("admin", "admin2")
    admin = await _me(client, admin_headers)
    admin2 = await _me(client, admin2_headers)
    with _auth_barrier(monkeypatch, 2):
        r1, r2 = await asyncio.gather(
            client.delete(f"/api/v1/users/{admin2['id']}", headers=admin_headers),
            client.delete(f"/api/v1/users/{admin['id']}", headers=admin2_headers),
        )
    codes = sorted([r1.status_code, r2.status_code])
    assert codes[0] == 204 and codes[1] in (401, 403, 404, 409), (r1.text, r2.text)
    survivor = admin_headers if r1.status_code == 204 else admin2_headers
    assert await _admin_count(client, survivor) == 1
    assert (await client.get("/api/v1/auth/status")).json()["setup_required"] is False


async def _wipe_users() -> None:
    async with session_scope() as s:
        await s.execute(delete(UserRow))


async def test_setup_does_not_reopen_when_users_are_gone(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    # However the user table becomes empty (race, manual SQL, partial restore), setup stays closed.
    await _wipe_users()
    assert (await client.get("/api/v1/auth/status")).json()["setup_required"] is False
    r = await client.post("/api/v1/auth/setup", json={"username": "mallory", "password": "p" * 12})
    assert r.status_code == 409


async def test_concurrent_setup_creates_one_admin(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_hash = auth_routes.hash_password
    arrived = 0
    released = asyncio.Event()

    def counting_hash(password: str) -> str:
        nonlocal arrived
        arrived += 1
        if arrived >= 2:
            released.set()
        return original_hash(password)

    async def gated_lock(session: Any) -> set[str]:
        # Both requests have passed the first "setup done?" check before either takes the lock.
        await asyncio.wait_for(released.wait(), timeout=10)
        return await lock_accounts(session)

    monkeypatch.setattr(auth_routes, "hash_password", counting_hash)
    monkeypatch.setattr(auth_routes, "lock_accounts", gated_lock)
    r1, r2 = await asyncio.gather(
        client.post("/api/v1/auth/setup", json={"username": "first", "password": "p" * 12}),
        client.post("/api/v1/auth/setup", json={"username": "second", "password": "p" * 12}),
    )
    assert sorted([r1.status_code, r2.status_code]) == [200, 409], (r1.text, r2.text)
    winner = r1 if r1.status_code == 200 else r2
    headers = {"Authorization": f"Bearer {winner.json()['access_token']}"}
    users = (await client.get("/api/v1/users", headers=headers)).json()
    assert [u["role"] for u in users] == ["admin"]


async def test_startup_backfills_setup_flag_and_warns_without_admin(
    db: None, caplog: pytest.LogCaptureFixture
) -> None:
    async with session_scope() as s:  # a database from before the flag: users, no auth_state row
        s.add(
            UserRow(id=new_id(), username="analyst1", password_hash=hash_password("x" * 12), role="analyst")
        )
    with caplog.at_level("WARNING", logger="tokiwa.api.routes.auth"):
        await auth_routes._check_accounts()
    assert "no user has the admin role" in caplog.text
    async with session_scope() as s:
        state = await s.get(AuthStateRow, AUTH_STATE_ID)
        assert state is not None and state.setup_completed_at is not None
    await _wipe_users()
    async with session_scope() as s:
        assert await setup_completed(s) is True
