"""Shipper against a mocked ingest server (httpx.MockTransport): batching, token, retry, offline buffer."""

from __future__ import annotations

import json
from collections.abc import Callable

import httpx

from tokiwa.schemas.events import Event, EventKind
from tokiwa.sensors.shipper import INGEST_PATH, Shipper


def _events(n: int, start: int = 0) -> list[Event]:
    return [Event(kind=EventKind.CUSTOM, dataset="test.x", message=str(start + i)) for i in range(n)]


class Server:
    """Scripted ingest endpoint: ``plan`` yields a status code (or an exception) per request."""

    def __init__(self, plan: Callable[[int], int | Exception]) -> None:
        self.plan = plan
        self.requests: list[httpx.Request] = []
        self.accepted: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        outcome = self.plan(len(self.requests))
        if isinstance(outcome, Exception):
            raise outcome
        body = json.loads(request.content)
        if outcome == 200:
            self.accepted.extend(e["message"] for e in body["events"])
            return httpx.Response(200, json={"accepted": len(body["events"]), "alerts": 0, "alert_ids": []})
        return httpx.Response(outcome, json={"detail": "x"})


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def _shipper(
    server: Server,
    delays: list[float] | None = None,
    *,
    clock: Clock | None = None,
    batch_size: int = 500,
    max_buffer: int = 50_000,
    max_retries: int = 3,
    backoff_base: float = 1.0,
) -> Shipper:
    async def sleep(d: float) -> None:
        if delays is not None:
            delays.append(d)

    return Shipper(
        "http://tokiwa.test/",
        "tkw_secret_token",
        transport=httpx.MockTransport(server.handler),
        sleep=sleep,
        clock=clock or Clock(),
        batch_size=batch_size,
        max_buffer=max_buffer,
        max_retries=max_retries,
        backoff_base=backoff_base,
    )


async def test_batches_and_token_header() -> None:
    server = Server(lambda i: 200)
    s = _shipper(server, batch_size=4)
    s.submit(_events(10))
    assert await s.flush() == 10
    assert len(server.requests) == 3  # 4 + 4 + 2
    req = server.requests[0]
    assert req.url.path == INGEST_PATH
    assert req.headers["X-Tokiwa-Token"] == "tkw_secret_token"
    assert server.accepted == [str(i) for i in range(10)]  # order preserved
    assert s.pending == 0 and s.sent == 10
    await s.aclose()


async def test_retry_with_exponential_backoff() -> None:
    server = Server(lambda i: 503 if i < 3 else 200)
    delays: list[float] = []
    s = _shipper(server, delays, max_retries=3, backoff_base=1.0)
    s.submit(_events(2))
    assert await s.flush() == 2
    assert len(server.requests) == 3
    assert len(delays) == 2
    assert 0.5 <= delays[0] <= 1.0 and 1.0 <= delays[1] <= 2.0  # base * 2**attempt with 50-100 % jitter
    await s.aclose()


async def test_offline_keeps_events_and_backs_off_then_recovers() -> None:
    online = {"up": False}
    server = Server(lambda i: 200 if online["up"] else httpx.ConnectError("refused"))
    clock = Clock()
    s = _shipper(server, max_retries=1, clock=clock)
    s.submit(_events(5))
    assert await s.flush() == 0
    assert s.pending == 5 and s.consecutive_failures == 1
    calls = len(server.requests)
    # Within the backoff window nothing is attempted
    assert await s.flush() == 0
    assert len(server.requests) == calls
    # New events queue behind the undelivered ones
    s.submit(_events(2, start=5))
    online["up"] = True
    clock.t = 10_000.0
    assert await s.flush() == 7
    assert server.accepted == [str(i) for i in range(7)]
    assert s.consecutive_failures == 0
    await s.aclose()


async def test_buffer_cap_drops_oldest() -> None:
    server = Server(lambda i: 200)
    s = _shipper(server, max_buffer=5)
    s.submit(_events(8))
    assert s.pending == 5 and s.dropped == 3
    await s.flush()
    assert server.accepted == ["3", "4", "5", "6", "7"]
    await s.aclose()


async def test_rejected_batch_is_dropped_not_retried() -> None:
    server = Server(lambda i: 422 if i == 1 else 200)
    s = _shipper(server, batch_size=2, max_retries=3)
    s.submit(_events(4))
    assert await s.flush() == 2
    assert s.rejected == 2 and s.pending == 0
    assert len(server.requests) == 2  # no retries for 422
    await s.aclose()


async def test_auth_failure_keeps_events() -> None:
    server = Server(lambda i: 401)
    s = _shipper(server, max_retries=3)
    s.submit(_events(3))
    assert await s.flush() == 0
    assert len(server.requests) == 1  # a bad token is not retried in a tight loop
    assert s.pending == 3
    await s.aclose()


async def test_force_flush_ignores_backoff() -> None:
    state = {"fail": True}
    server = Server(lambda i: 500 if state["fail"] else 200)
    s = _shipper(server, max_retries=0)
    s.submit(_events(1))
    assert await s.flush() == 0
    state["fail"] = False
    assert await s.flush() == 0  # still backing off
    assert await s.flush(force=True) == 1
    await s.aclose()
