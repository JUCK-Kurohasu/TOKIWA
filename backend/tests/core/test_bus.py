"""Regression tests for EventBus.drain()."""

from __future__ import annotations

import asyncio

from tokiwa.bus import EventBus


async def test_drain_returns_with_done_but_unpruned_tasks() -> None:
    bus = EventBus()

    async def noop() -> None:
        return None

    task = asyncio.ensure_future(noop())
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert task.done()
    # Simulate the race: the task is done but its discard callback has not run yet.
    bus._tasks.add(task)
    await asyncio.wait_for(bus.drain(timeout=2.0), timeout=3.0)
    assert not bus._tasks


async def test_drain_waits_for_cascading_handlers() -> None:
    bus = EventBus()
    seen: list[str] = []

    async def first(payload: object) -> None:
        await asyncio.sleep(0.01)
        seen.append("first")
        await bus.publish("b", payload)

    async def second(payload: object) -> None:
        await asyncio.sleep(0.01)
        seen.append("second")

    bus.subscribe("a", first)
    bus.subscribe("b", second)
    await bus.publish("a", {})
    await bus.drain(timeout=2.0)
    assert seen == ["first", "second"]
