"""#91: route writes must be committed *before* the response goes out, and a failing commit must not be a 2xx.

httpx's ASGITransport runs the whole ASGI call (including post-response dependency teardown) before it returns,
so "revoke, then re-use" through the normal ``client`` fixture passes even when the commit happens after the
response. These tests instead wrap the app's ``send`` and look at the database from a separate session at the
moment ``http.response.start`` is sent: anything not visible then is exactly the window the audit reproduced.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from fastapi import FastAPI

from tokiwa.api.deps import DbSession
from tokiwa.db.models.core import ApiTokenRow, SettingRow, UserRow
from tokiwa.db.session import get_sessionmaker
from tokiwa.util import new_id

Check = Callable[[], Awaitable[Any]]


def _probe(app: FastAPI, check: Check) -> tuple[Any, list[Any]]:
    """ASGI wrapper that runs ``check()`` when the response starts and records its result."""
    seen: list[Any] = []

    async def wrapped(scope: dict[str, Any], receive: Any, send: Any) -> None:
        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                seen.append(await check())
            await send(message)

        await app(scope, receive, send_wrapper)

    return wrapped, seen


def _client(asgi: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=asgi), base_url="http://testserver")


async def test_route_write_is_committed_before_response_starts(app: FastAPI) -> None:
    key = f"test.commit.{new_id()}"

    async def write(session: DbSession) -> dict[str, bool]:
        session.add(SettingRow(key=key, value={"v": 1}))
        return {"ok": True}

    app.add_api_route("/api/v1/__test/commit", write, methods=["POST"])

    async def committed() -> bool:
        async with get_sessionmaker()() as s:
            return await s.get(SettingRow, key) is not None

    asgi, seen = _probe(app, committed)
    async with _client(asgi) as c:
        r = await c.post("/api/v1/__test/commit")
    assert r.status_code == 200
    assert seen == [True]


async def test_commit_failure_is_not_reported_as_success(app: FastAPI) -> None:
    """A constraint violation that only surfaces at commit time (no flush in the route) becomes 409, not 200."""

    async def write(session: DbSession) -> dict[str, bool]:
        for _ in range(2):
            session.add(UserRow(id=new_id(), username="dup-user", password_hash="x", role="viewer"))
        return {"ok": True}

    app.add_api_route("/api/v1/__test/dup", write, methods=["POST"])
    async with _client(app) as c:
        r = await c.post("/api/v1/__test/dup")
    assert r.status_code == 409, r.text
    body = r.json()
    assert "detail" in body
    # Generic message: no SQL statement / bound parameters (password hashes ...) leak to the client.
    assert "INSERT" not in r.text and "password_hash" not in r.text

    async with get_sessionmaker()() as s:
        assert (await s.get(UserRow, "dup-user")) is None


async def test_integrity_error_raised_in_route_maps_to_409(app: FastAPI) -> None:
    async def write(session: DbSession) -> dict[str, bool]:
        for _ in range(2):
            session.add(UserRow(id=new_id(), username="dup-flush", password_hash="x", role="viewer"))
        await session.flush()
        return {"ok": True}

    app.add_api_route("/api/v1/__test/dup-flush", write, methods=["POST"])
    async with _client(app) as c:
        r = await c.post("/api/v1/__test/dup-flush")
    assert r.status_code == 409


async def test_revoked_token_is_rejected_right_after_204(
    app: FastAPI, client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    """Audit scenario: DELETE /tokens/{id} returned 204 but the token still worked for a few ms."""
    created = await client.post(
        "/api/v1/tokens", json={"name": "race", "scopes": ["gate"]}, headers=admin_headers
    )
    assert created.status_code in (200, 201), created.text
    token_id, token = created.json()["id"], created.json()["token"]

    async def revoked() -> bool:
        async with get_sessionmaker()() as s:
            row = await s.get(ApiTokenRow, token_id)
            return row is None or bool(row.revoked)

    asgi, seen = _probe(app, revoked)
    async with _client(asgi) as c:
        r = await c.delete(f"/api/v1/tokens/{token_id}", headers=admin_headers)
        assert r.status_code == 204
        assert seen == [True]
        again = await c.get("/api/v1/gate/policy", headers={"X-Tokiwa-Token": token})
    assert again.status_code == 401
