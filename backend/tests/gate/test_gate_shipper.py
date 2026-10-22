from __future__ import annotations

import asyncio

import httpx
import pytest
from gate_helpers import FakeServer

from tokiwa.gate.shipper import EventShipper
from tokiwa.schemas.events import DeceptionInfo, Endpoint, Event, EventKind, HttpInfo


def _event(i: int) -> Event:
    return Event(
        kind=EventKind.HTTP,
        dataset="gate.http",
        sensor_id="gate-test",
        source=Endpoint(ip="203.0.113.7"),
        http=HttpInfo(method="GET", path=f"/p/{i}", status=200),
        labels={"i": str(i)},
    )


def _shipper(server: FakeServer, **kw: object) -> tuple[EventShipper, httpx.AsyncClient]:
    client = httpx.AsyncClient(transport=httpx.MockTransport(server.handler))
    args: dict[str, object] = {"batch_size": 3, "flush_interval": 0.05, "max_queue": 10}
    args.update(kw)
    return EventShipper(client, "http://tokiwa.test", "tkw_ship", **args), client  # type: ignore[arg-type]


def _ids(server: FakeServer) -> list[int]:
    return [int(e["labels"]["i"]) for e in server.events]


async def test_flush_batches_with_token(fake_server: FakeServer) -> None:
    shipper, client = _shipper(fake_server)
    async with client:
        for i in range(7):
            shipper.submit(_event(i))
        assert await shipper.flush() == 7
    assert [len(b["events"]) for b in fake_server.batches] == [3, 3, 1]
    assert set(fake_server.tokens) == {"tkw_ship"}
    assert _ids(fake_server) == list(range(7))
    assert "ingested_at" not in fake_server.events[0]  # None fields are not shipped
    snap = shipper.snapshot()
    assert snap["sent"] == 7 and snap["batches_sent"] == 3 and snap["queued"] == 0


async def test_overflow_drops_oldest(fake_server: FakeServer) -> None:
    shipper, client = _shipper(fake_server, max_queue=10)
    async with client:
        for i in range(25):
            shipper.submit(_event(i))
        assert len(shipper) == 10
        assert shipper.stats.dropped_overflow == 15
        await shipper.flush()
    assert _ids(fake_server) == list(range(15, 25))  # newest survive


async def test_transient_failure_keeps_order_and_retries(fake_server: FakeServer) -> None:
    shipper, client = _shipper(fake_server)
    async with client:
        for i in range(5):
            shipper.submit(_event(i))
        fake_server.down = True
        assert await shipper.flush() == 0
        assert len(shipper) == 5
        assert shipper.stats.failed_attempts == 1 and "ConnectError" in (shipper.stats.last_error or "")
        fake_server.down = False
        fake_server.ingest_status = 503
        assert await shipper.flush() == 0
        assert shipper.stats.last_error == "HTTP 503"
        fake_server.ingest_status = 200
        shipper.submit(_event(5))
        assert await shipper.flush() == 6
    assert _ids(fake_server) == list(range(6))
    assert shipper.stats.last_error is None


async def test_requeue_respects_cap(fake_server: FakeServer) -> None:
    shipper, client = _shipper(fake_server, max_queue=4, batch_size=3)
    async with client:
        for i in range(4):
            shipper.submit(_event(i))
        fake_server.down = True
        await shipper.flush()
        for i in range(4, 6):
            shipper.submit(_event(i))  # queue full -> oldest (0, 1) evicted
        fake_server.down = False
        await shipper.flush()
    assert _ids(fake_server) == [2, 3, 4, 5]
    assert shipper.stats.dropped_overflow == 2


@pytest.mark.parametrize("status", [401, 403, 422])
async def test_permanent_rejection_drops_batch(fake_server: FakeServer, status: int) -> None:
    shipper, client = _shipper(fake_server)
    async with client:
        for i in range(4):
            shipper.submit(_event(i))
        fake_server.ingest_status = status
        assert await shipper.flush() == 0
        assert len(shipper) == 0
        assert shipper.stats.dropped_rejected == 4
        assert str(status) in (shipper.stats.last_error or "")


async def test_background_loop_flushes_on_interval_and_batch(fake_server: FakeServer) -> None:
    shipper, client = _shipper(fake_server, batch_size=100, flush_interval=0.05)
    async with client:
        task = asyncio.create_task(shipper.run())
        try:
            shipper.submit(_event(0))  # below batch_size: goes out on the interval
            for _ in range(100):
                if fake_server.events:
                    break
                await asyncio.sleep(0.01)
            assert _ids(fake_server) == [0]
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        shipper.submit(_event(1))
        await shipper.aclose()
    assert _ids(fake_server) == [0, 1]


async def test_backoff_skips_sends_while_server_is_down(fake_server: FakeServer) -> None:
    shipper, client = _shipper(fake_server, batch_size=1, flush_interval=0.05, max_backoff=60)
    async with client:
        fake_server.down = True
        task = asyncio.create_task(shipper.run())
        try:
            for i in range(3):
                shipper.submit(_event(i))
                await asyncio.sleep(0.06)
            # exponential backoff: far fewer attempts than wake-ups
            assert 1 <= shipper.stats.failed_attempts <= 3
            assert len(shipper) == 3
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_events_accepted_by_real_ingest_api(
    client: httpx.AsyncClient, ingest_headers: dict[str, str]
) -> None:
    """Contract check: what the gate ships is accepted by the actual TOKIWA ingest endpoint."""
    shipper = EventShipper(client, "http://testserver", ingest_headers["X-Tokiwa-Token"], batch_size=10)
    shipper.submit(_event(1))
    deception = _event(2).model_copy(
        update={
            "kind": EventKind.DECEPTION,
            "dataset": "gate.deception",
            "deception": DeceptionInfo(asset_id="a1", asset_kind="decoy_path", detail="x"),
            "tags": ["gate:decoy"],
        }
    )
    shipper.submit(deception)
    assert await shipper.flush() == 2
    assert shipper.stats.dropped_rejected == 0
