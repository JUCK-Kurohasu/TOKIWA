"""Audit #39: slow request bodies and many parallel requests from one client must not exhaust the Gate.

Before, a POST that sent one byte every few seconds held an upstream connection for as long as it liked; ~530 of
them from one IP filled the upstream pool (512) and every other visitor got 504, while no event reached the
server until the requests finished. Real timeouts are short here (fractions of a second) to keep the test fast.
"""

from __future__ import annotations

import asyncio
from typing import Any

from gate_helpers import CLIENT_IP, FakeServer, GateFactory, Upstream, events_of, http_scope


class TrickleClient:
    """Raw ASGI client: sends the scripted messages, then nothing (blocks) until released."""

    def __init__(self, messages: list[dict[str, Any]]) -> None:
        self.inbox = list(messages)
        self.release = asyncio.Event()
        self.sent: list[dict[str, Any]] = []

    async def receive(self) -> dict[str, Any]:
        if self.inbox:
            return self.inbox.pop(0)
        await self.release.wait()
        return {"type": "http.disconnect"}

    async def send(self, message: dict[str, Any]) -> None:
        self.sent.append(message)

    @property
    def status(self) -> int | None:
        start = next((m for m in self.sent if m["type"] == "http.response.start"), None)
        return start["status"] if start else None


def _post_scope(ip: str = CLIENT_IP) -> dict[str, Any]:
    scope = http_scope("/upload", b"/upload", ip=ip, method="POST")
    scope["headers"] = [*scope["headers"], (b"content-length", b"100")]
    return scope


async def test_stalled_body_gets_408_and_an_event(make_gate: GateFactory, fake_server: FakeServer) -> None:
    app, gate = await make_gate(body_idle_timeout_seconds=0.05)
    client = TrickleClient([{"type": "http.request", "body": b"a", "more_body": True}])
    await asyncio.wait_for(app(_post_scope(), client.receive, client.send), timeout=5)
    assert client.status == 408
    assert gate._inflight == {}  # released
    (event,) = await events_of(gate, fake_server)
    assert "gate:slow_body" in event["tags"]
    assert event["labels"]["gate.slow_body"] == "idle"


async def test_trickling_body_hits_the_total_deadline(
    make_gate: GateFactory, fake_server: FakeServer
) -> None:
    """One byte just inside the idle gap, forever: the total deadline still ends it."""
    app, gate = await make_gate(body_idle_timeout_seconds=0.2, body_total_timeout_seconds=0.15)

    class Dribble(TrickleClient):
        async def receive(self) -> dict[str, Any]:
            await asyncio.sleep(0.03)
            return {"type": "http.request", "body": b"x", "more_body": True}

    client = Dribble([])
    await asyncio.wait_for(app(_post_scope(), client.receive, client.send), timeout=5)
    assert client.status == 408
    (event,) = await events_of(gate, fake_server)
    assert event["labels"]["gate.slow_body"] == "total"


async def test_normal_post_still_forwarded(make_gate: GateFactory, upstream: Upstream) -> None:
    app, _gate = await make_gate(body_idle_timeout_seconds=0.5)
    client = TrickleClient(
        [
            {"type": "http.request", "body": b"a=1&", "more_body": True},
            {"type": "http.request", "body": b"b=2", "more_body": False},
        ]
    )
    await asyncio.wait_for(app(_post_scope(), client.receive, client.send), timeout=5)
    assert client.status == 200
    assert upstream.requests and upstream.requests[0]["body"] == b"a=1&b=2"


async def test_requests_per_client_cap(make_gate: GateFactory, fake_server: FakeServer) -> None:
    app, gate = await make_gate(max_requests_per_client=2, body_idle_timeout_seconds=0)
    held = [TrickleClient([{"type": "http.request", "body": b"a", "more_body": True}]) for _ in range(2)]
    tasks = [asyncio.create_task(app(_post_scope(), c.receive, c.send)) for c in held]
    for _ in range(50):
        await asyncio.sleep(0)
    assert gate._inflight[CLIENT_IP] == 2

    third = TrickleClient([{"type": "http.request", "body": b"", "more_body": False}])
    await asyncio.wait_for(app(http_scope("/", b"/"), third.receive, third.send), timeout=5)
    assert third.status == 429
    other = TrickleClient([{"type": "http.request", "body": b"", "more_body": False}])
    await asyncio.wait_for(app(http_scope("/", b"/", ip="192.0.2.77"), other.receive, other.send), timeout=5)
    assert other.status == 200  # another client is unaffected

    for c in held:
        c.release.set()  # they hang up
    await asyncio.wait_for(asyncio.gather(*tasks), timeout=5)
    assert gate._inflight == {}  # decremented on disconnect too
    events = await events_of(gate, fake_server)
    assert any("gate:conn_limit" in e["tags"] for e in events)


async def test_cancelled_request_releases_its_slot(make_gate: GateFactory) -> None:
    app, gate = await make_gate(max_requests_per_client=1, body_idle_timeout_seconds=0)
    client = TrickleClient([{"type": "http.request", "body": b"a", "more_body": True}])
    task = asyncio.create_task(app(_post_scope(), client.receive, client.send))
    for _ in range(50):
        await asyncio.sleep(0)
    assert gate._inflight[CLIENT_IP] == 1
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert gate._inflight == {}
