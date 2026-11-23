"""Login throttling, user-name enumeration, audit and non-blocking password hashing (#56)."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator, Callable
from datetime import timedelta
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from tokiwa.auth import security, throttle
from tokiwa.config import reset_settings_cache
from tokiwa.db.models.core import AuditRow
from tokiwa.db.session import session_scope
from tokiwa.util import utcnow

from .conftest import PASSWORD, MakeUser

LOGIN = "/api/v1/auth/login"


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Callable[[float], None]:
    """Freeze the throttle clock; call with minutes to move it forward."""
    t0 = utcnow()
    offset = {"minutes": 0.0}
    monkeypatch.setattr(throttle, "now", lambda: t0 + timedelta(minutes=offset["minutes"]))

    def advance(minutes: float) -> None:
        offset["minutes"] += minutes

    return advance


@pytest.fixture
async def other_ip_client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=("198.51.100.7", 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


async def _login(client: httpx.AsyncClient, username: str, password: str) -> httpx.Response:
    return await client.post(LOGIN, json={"username": username, "password": password})


async def _audit(action: str) -> list[AuditRow]:
    async with session_scope() as s:
        return list((await s.execute(select(AuditRow).where(AuditRow.action == action))).scalars())


async def test_lockout_per_user_and_ip_then_expires(
    client: httpx.AsyncClient,
    other_ip_client: httpx.AsyncClient,
    make_user: MakeUser,
    clock: Callable[[float], None],
) -> None:
    await make_user("analyst", "erin")
    for _ in range(5):
        assert (await _login(client, "erin", "wrong-password")).status_code == 401
    locked = await _login(client, "erin", PASSWORD)  # even the right password is refused while locked
    assert locked.status_code == 429
    assert 1 <= int(locked.headers["retry-after"]) <= 15 * 60
    # The lock is per user name + source IP: the owner elsewhere is not locked out by an attacker.
    assert (await _login(other_ip_client, "erin", PASSWORD)).status_code == 200

    clock(14)
    assert (await _login(client, "erin", PASSWORD)).status_code == 429
    clock(1.1)  # the oldest failure left the 15-minute window
    assert (await _login(client, "erin", PASSWORD)).status_code == 200
    # A success clears the pair: five fresh failures are allowed again.
    for _ in range(5):
        assert (await _login(client, "erin", "wrong-password")).status_code == 401
    assert (await _login(client, "erin", PASSWORD)).status_code == 429


async def test_unknown_users_are_throttled_and_cost_a_hash(
    client: httpx.AsyncClient, admin_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    original = security.verify_password

    def counting(password: str, encoded: str) -> bool:
        calls.append(encoded)
        return original(password, encoded)

    monkeypatch.setattr(security, "verify_password", counting)
    r = await _login(client, "nosuchuser", "whatever-password")
    assert r.status_code == 401 and r.json()["detail"] == "invalid credentials"
    assert len(calls) == 1, "an unknown user name still runs one scrypt (no timing difference)"
    for _ in range(4):
        await _login(client, "nosuchuser", "whatever-password")
    # Locking does not depend on whether the user exists, so it reveals nothing either.
    assert (await _login(client, "nosuchuser", "whatever-password")).status_code == 429


async def test_password_spraying_locks_the_source_ip(
    client: httpx.AsyncClient,
    other_ip_client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TOKIWA_AUTH__LOGIN_MAX_FAILURES_PER_IP", "3")
    reset_settings_cache()
    for name in ("alice", "bob", "carol"):
        assert (await _login(client, name, "Summer2026!")).status_code == 401
    assert (await _login(client, "admin", "correct-horse-battery")).status_code == 429
    assert (await _login(other_ip_client, "admin", "correct-horse-battery")).status_code == 200


async def test_login_audit_never_contains_the_password(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    assert (await _login(client, "admin", "wrong-password-123")).status_code == 401
    assert (await _login(client, "ghost", "wrong-password-456")).status_code == 401
    assert (await _login(client, "admin", "correct-horse-battery")).status_code == 200

    failures = await _audit("auth.login.failure")
    assert [(f.actor, f.details["known_user"]) for f in failures] == [("admin", True), ("ghost", False)]
    assert all(f.details["client_ip"] == "127.0.0.1" for f in failures)
    successes = await _audit("auth.login.success")
    assert [s.actor for s in successes] == ["admin"]
    for row in [*failures, *successes]:
        assert "wrong-password" not in repr(row.details) and "correct-horse" not in repr(row.details)


async def test_lock_engaging_is_audited(client: httpx.AsyncClient, admin_headers: dict[str, str]) -> None:
    for _ in range(5):
        await _login(client, "admin", "wrong-password")
    flags = [f.details["locked"] for f in await _audit("auth.login.failure")]
    assert flags == [False, False, False, False, True]


async def test_parallel_guesses_do_not_exceed_the_limit(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    results = await asyncio.gather(*(_login(client, "admin", f"guess-{i:04d}") for i in range(12)))
    codes = [r.status_code for r in results]
    # Each attempt commits its failure row before counting, so at most `limit` passwords are checked.
    assert 1 <= codes.count(401) <= 5, codes
    assert codes.count(401) + codes.count(429) == 12, codes


async def test_password_hashing_does_not_block_the_event_loop(
    client: httpx.AsyncClient, admin_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    started, release = threading.Event(), threading.Event()
    original = security.verify_password

    def slow_verify(password: str, encoded: str) -> bool:
        started.set()
        release.wait(timeout=10)
        return original(password, encoded)

    monkeypatch.setattr(security, "verify_password", slow_verify)
    login = asyncio.create_task(_login(client, "admin", "correct-horse-battery"))
    await asyncio.to_thread(started.wait, 10)
    # While the hash "runs", other requests are still served.
    health = await asyncio.wait_for(client.get("/api/v1/health"), timeout=5)
    assert health.status_code == 200
    assert not login.done()
    release.set()
    assert (await login).status_code == 200


async def test_wrong_setup_codes_are_throttled_and_audited(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TOKIWA_AUTH__LOGIN_MAX_FAILURES_PER_IP", "2")
    reset_settings_cache()
    body: dict[str, Any] = {"username": "admin", "password": "p" * 12, "setup_code": "NOPE-NOPE-NOPE-NOPE"}
    assert (await client.post("/api/v1/auth/setup", json=body)).status_code == 403
    assert (await client.post("/api/v1/auth/setup", json=body)).status_code == 403
    assert (await client.post("/api/v1/auth/setup", json=body)).status_code == 429
    assert len(await _audit("auth.setup.failure")) == 2
