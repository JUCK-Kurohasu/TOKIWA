"""Audit #100: the UI opens the SSE stream with a single-use, short-lived ticket instead of its JWT in the URL."""

from __future__ import annotations

import logging

import httpx
import pytest

from tokiwa.api.routes import stream as stream_mod
from tokiwa.bus import bus

from .conftest import OpenSSE


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    c = _Clock()
    monkeypatch.setattr(stream_mod, "tickets", stream_mod.TicketStore(clock=c))
    return c


async def _ticket(client: httpx.AsyncClient, headers: dict[str, str]) -> str:
    r = await client.post("/api/v1/stream/ticket", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["expires_in"] == stream_mod.TICKET_TTL_SECONDS
    assert r.headers["cache-control"] == "no-store"
    return str(body["ticket"])


async def test_ticket_requires_a_user_jwt(client: httpx.AsyncClient, ingest_headers: dict[str, str]) -> None:
    assert (await client.post("/api/v1/stream/ticket")).status_code == 401
    assert (await client.post("/api/v1/stream/ticket", headers=ingest_headers)).status_code == 401
    token = ingest_headers["X-Tokiwa-Token"]
    r = await client.post("/api/v1/stream/ticket", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401  # API tokens are not user credentials


async def test_ticket_opens_the_stream_once(
    client: httpx.AsyncClient, open_sse: OpenSSE, viewer_headers: dict[str, str], clock: _Clock
) -> None:
    ticket = await _ticket(client, viewer_headers)
    assert viewer_headers["Authorization"].removeprefix("Bearer ") not in ticket
    async with open_sse(params={"ticket": ticket}) as conn:
        assert conn.status == 200
        assert (await conn.next_event()) == {"comment": "connected"}
        await bus.publish("alert.created", {"id": "a1"})
        assert (await conn.next_message()) == {"topic": "alert.created", "data": {"id": "a1"}}
    # EventSource's automatic reconnect re-uses the URL: a used ticket is refused, so the UI fetches a new one.
    async with open_sse(params={"ticket": ticket}) as conn:
        assert conn.status == 401
    assert len(stream_mod.tickets) == 0


async def test_ticket_expires(
    client: httpx.AsyncClient, open_sse: OpenSSE, viewer_headers: dict[str, str], clock: _Clock
) -> None:
    ticket = await _ticket(client, viewer_headers)
    clock.now += stream_mod.TICKET_TTL_SECONDS
    async with open_sse(params={"ticket": ticket}) as conn:
        assert conn.status == 401
    assert (await client.get("/api/v1/stream", params={"ticket": "junk"})).status_code == 401


async def test_logout_between_issue_and_use_ends_access(
    client: httpx.AsyncClient, open_sse: OpenSSE, viewer_headers: dict[str, str], clock: _Clock
) -> None:
    ticket = await _ticket(client, viewer_headers)
    assert (await client.post("/api/v1/auth/logout", headers=viewer_headers)).status_code == 204
    async with open_sse(params={"ticket": ticket}) as conn:
        assert conn.status == 401  # the JWT behind the ticket is checked again when it is redeemed


def test_ticket_store_caps() -> None:
    clock = _Clock()
    store = stream_mod.TicketStore(clock=clock)
    first = store.issue("u1", "jwt-1")
    for _ in range(stream_mod.MAX_TICKETS_PER_USER):
        store.issue("u1", "jwt-1")
    other = store.issue("u2", "jwt-2")
    assert len(store) == stream_mod.MAX_TICKETS_PER_USER + 1
    assert store.redeem(first) is None  # the oldest ticket of u1 was dropped
    assert store.redeem(other) == "jwt-2"
    assert store.redeem(other) is None  # single use
    clock.now += stream_mod.TICKET_TTL_SECONDS
    store.issue("u3", "jwt-3")  # issuing purges expired tickets
    assert len(store) == 1


async def test_legacy_access_token_still_works_but_warns(
    open_sse: OpenSSE,
    viewer_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(stream_mod, "_legacy_warned_at", None)
    jwt = viewer_headers["Authorization"].removeprefix("Bearer ")
    with caplog.at_level(logging.WARNING, logger=stream_mod.__name__):
        for _ in range(2):
            async with open_sse(params={"access_token": jwt}) as conn:
                assert conn.status == 200
    warnings = [r for r in caplog.records if "deprecated" in r.getMessage()]
    assert len(warnings) == 1  # rate-limited
    assert jwt not in warnings[0].getMessage()


def test_access_log_redacts_ticket(caplog: pytest.LogCaptureFixture) -> None:
    access = logging.getLogger("uvicorn.access")
    with caplog.at_level(logging.INFO, logger="uvicorn.access"):
        access.info(
            '%s - "%s %s HTTP/%s" %d', "127.0.0.1:1", "GET", "/api/v1/stream?ticket=SECRET-T&x=1", "1.1", 200
        )
    line = caplog.records[-1].getMessage()
    assert "SECRET-T" not in line and "ticket=[REDACTED]&x=1" in line
