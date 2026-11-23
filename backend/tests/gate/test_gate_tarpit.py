"""Tarpit resource bounds (audit #99): slots per client / in total, and no holding for a client that left."""

from __future__ import annotations

import asyncio
from typing import Any

from gate_helpers import CLIENT_IP, FakeServer, GateFactory, Upstream, events_of, http_scope

from tokiwa.gate.app import Gate


class Client:
    """Raw ASGI client whose receive() blocks after the scripted messages, like a real server's."""

    def __init__(self, messages: list[dict[str, Any]], *, hang_up: asyncio.Event | None = None) -> None:
        self.inbox = list(messages)
        self.hang_up = hang_up or asyncio.Event()
        self.sent: list[dict[str, Any]] = []

    async def receive(self) -> dict[str, Any]:
        if self.inbox:
            return self.inbox.pop(0)
        await self.hang_up.wait()
        return {"type": "http.disconnect"}

    async def send(self, message: dict[str, Any]) -> None:
        self.sent.append(message)


def _held(gate: Gate) -> asyncio.Event:
    """Make the tarpit wait until the returned event is set (no real time passes in these tests)."""
    release = asyncio.Event()

    async def sleep(_seconds: float) -> None:
        await release.wait()

    gate._sleep = sleep
    return release


async def _settle() -> None:
    for _ in range(20):
        await asyncio.sleep(0)


def _post(body_chunks: list[bytes]) -> list[dict[str, Any]]:
    return [
        {"type": "http.request", "body": chunk, "more_body": i < len(body_chunks) - 1}
        for i, chunk in enumerate(body_chunks)
    ]


async def test_client_that_hangs_up_is_not_held_nor_forwarded(
    make_gate: GateFactory, upstream: Upstream, fake_server: FakeServer
) -> None:
    fake_server.set_policy("v1", tarpit={CLIENT_IP: 30_000})
    app, gate = await make_gate()
    _held(gate)  # the delay never ends by itself
    client = Client([{"type": "http.request", "body": b"", "more_body": False}])
    task = asyncio.create_task(app(http_scope("/slow", b"/slow"), client.receive, client.send))
    await _settle()
    assert gate._tarpit_active == 1 and not task.done()
    client.hang_up.set()
    await asyncio.wait_for(task, timeout=5)
    assert client.sent == [] and upstream.requests == []
    assert gate._tarpit_active == 0 and not gate._tarpit_per_client
    (event,) = await events_of(gate, fake_server)
    assert "gate:client_disconnect" in event["tags"] and event["http"]["status"] == 499


async def test_body_read_while_held_still_reaches_the_upstream(
    make_gate: GateFactory, upstream: Upstream, fake_server: FakeServer
) -> None:
    fake_server.set_policy("v1", tarpit={CLIENT_IP: 2_000})
    app, gate = await make_gate()
    release = _held(gate)
    scope = http_scope("/form", b"/form", method="POST")
    scope["headers"] = [*scope["headers"], (b"content-length", b"10"), (b"content-type", b"text/plain")]
    client = Client(_post([b"hello", b"world"]))
    task = asyncio.create_task(app(scope, client.receive, client.send))
    await _settle()
    assert client.inbox == []  # both chunks were read while waiting for a disconnect
    release.set()
    await asyncio.wait_for(task, timeout=5)
    assert client.sent[0]["status"] == 200
    assert upstream.requests[0]["body"] == b"helloworld"
    (event,) = await events_of(gate, fake_server)
    assert event["http"]["request_body"] == "helloworld" and "gate:tarpit" in event["tags"]


async def test_held_requests_are_capped_per_client_and_in_total(
    make_gate: GateFactory, upstream: Upstream, fake_server: FakeServer
) -> None:
    fake_server.set_policy("v1", tarpit={"198.51.100.0/24": 5_000})
    app, gate = await make_gate(tarpit_max_per_client=2, tarpit_max_concurrent=3)
    release = _held(gate)

    def start(ip: str) -> tuple[Client, asyncio.Task[None]]:
        c = Client([{"type": "http.request", "body": b"", "more_body": False}])
        return c, asyncio.create_task(app(http_scope("/x", b"/x", ip=ip), c.receive, c.send))

    a1, a2, a3 = start("198.51.100.1"), start("198.51.100.1"), start("198.51.100.1")
    await _settle()
    assert a3[1].done() and a3[0].sent[0]["status"] == 429  # third from the same client: no slot
    assert dict(a3[0].sent[0]["headers"])[b"retry-after"] == b"5"
    b1, b2 = start("198.51.100.2"), start("198.51.100.2")
    await _settle()
    assert not b1[1].done() and b2[1].done() and b2[0].sent[0]["status"] == 429  # total of 3 reached
    release.set()
    await asyncio.wait_for(asyncio.gather(a1[1], a2[1], b1[1]), timeout=5)
    assert [c.sent[0]["status"] for c in (a1[0], a2[0], b1[0])] == [200, 200, 200]
    assert gate._tarpit_active == 0 and len(upstream.requests) == 3
    events = await events_of(gate, fake_server)
    overflow = [e for e in events if "gate:tarpit_overflow" in e["tags"]]
    assert len(overflow) == 2 and all(e["labels"]["gate.action"] == "tarpit_overflow" for e in overflow)


async def test_caps_can_be_disabled(make_gate: GateFactory, fake_server: FakeServer) -> None:
    fake_server.set_policy("v1", tarpit={CLIENT_IP: 1_000})
    app, gate = await make_gate(tarpit_max_per_client=0, tarpit_max_concurrent=0)
    release = _held(gate)
    clients = [Client([{"type": "http.request", "body": b"", "more_body": False}]) for _ in range(20)]
    tasks = [asyncio.create_task(app(http_scope("/x", b"/x"), c.receive, c.send)) for c in clients]
    await _settle()
    assert gate._tarpit_active == 20
    release.set()
    await asyncio.wait_for(asyncio.gather(*tasks), timeout=5)
    assert all(c.sent[0]["status"] == 200 for c in clients)
