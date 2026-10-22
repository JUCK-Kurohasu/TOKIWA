"""In-process async pub/sub that decouples modules.

Topics (payloads are Pydantic models or dicts, documented in docs/architecture.md#event-bus):

- ``event.ingested``      list[Event]            after events are stored
- ``alert.created``       Alert                  new alert row
- ``alert.updated``       Alert                  dedup hit / status / triage change
- ``incident.created``    Incident
- ``incident.updated``    Incident
- ``action.proposed``     ResponseAction
- ``action.updated``      ResponseAction         approved / active / expired / reverted ...
- ``deception.tripped``   dict                   {asset_id, event_id, source_ip}
- ``intel.vuln_matched``  VulnMatch
- ``intel.advisory``      Advisory
- ``llm.call``            LLMCall                audit record written

Handlers run as background tasks so publishers never block on subscribers. Tests call ``await bus.drain()``
to wait until all handler tasks (including ones they spawn) are finished.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any

log = logging.getLogger(__name__)

Handler = Callable[[Any], Awaitable[None]]


class EventBus:
    def __init__(self) -> None:
        self._subs: dict[str, list[Handler]] = defaultdict(list)
        self._tasks: set[asyncio.Task[None]] = set()
        # Streaming listeners (SSE): receive every (topic, payload)
        self._queues: set[asyncio.Queue[tuple[str, Any]]] = set()

    def subscribe(self, topic: str, handler: Handler) -> None:
        if handler not in self._subs[topic]:
            self._subs[topic].append(handler)

    def unsubscribe(self, topic: str, handler: Handler) -> None:
        if handler in self._subs.get(topic, []):
            self._subs[topic].remove(handler)

    def clear(self) -> None:
        self._subs.clear()

    async def publish(self, topic: str, payload: Any) -> None:
        for q in list(self._queues):
            try:
                q.put_nowait((topic, payload))
            except asyncio.QueueFull:
                log.warning("bus listener queue full; dropping %s", topic)
        for handler in list(self._subs.get(topic, [])):
            task = asyncio.create_task(self._run(topic, handler, payload))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _run(self, topic: str, handler: Handler, payload: Any) -> None:
        try:
            await handler(payload)
        except Exception:
            log.exception("bus handler %r failed for topic %s", handler, topic)

    def listen(self, maxsize: int = 1000) -> asyncio.Queue[tuple[str, Any]]:
        q: asyncio.Queue[tuple[str, Any]] = asyncio.Queue(maxsize=maxsize)
        self._queues.add(q)
        return q

    def unlisten(self, q: asyncio.Queue[tuple[str, Any]]) -> None:
        self._queues.discard(q)

    async def drain(self, timeout: float = 10.0) -> None:
        async with asyncio.timeout(timeout):
            while self._tasks:
                await asyncio.gather(*list(self._tasks), return_exceptions=True)


bus = EventBus()
