"""Event shipper: batches events to ``POST /api/v1/ingest/events`` with retry and an offline buffer.

* Batches of ``batch_size`` (server accepts at most 5000 per request).
* Each batch is retried with exponential backoff + jitter on network errors, 5xx and 429. After
  ``max_retries`` the shipper goes "offline": events stay buffered and the next flush is postponed with a
  growing delay, so a down server is not hammered.
* The buffer is capped at ``max_buffer`` events; when full the **oldest** events are dropped (and counted)
  because recent telemetry is the most useful when the server comes back.
* 400/413/422 mean the batch itself is unacceptable — it is dropped instead of blocking the queue forever.
  401/403 (bad token) keep the events and back off; fixing the token recovers them.

The token travels only in the ``X-Tokiwa-Token`` header and is never logged.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import deque
from collections.abc import Awaitable, Callable, Iterable
from enum import Enum

import httpx

from tokiwa.schemas.events import Event

log = logging.getLogger(__name__)

INGEST_PATH = "/api/v1/ingest/events"
SERVER_MAX_BATCH = 5000


class _Outcome(Enum):
    OK = "ok"
    REJECTED = "rejected"  # dropped: the server will never accept this batch
    FAILED = "failed"  # kept: try again later


class Shipper:
    def __init__(
        self,
        server_url: str,
        token: str | None,
        *,
        batch_size: int = 500,
        max_buffer: int = 50_000,
        max_retries: int = 3,
        backoff_base: float = 1.0,
        backoff_max: float = 60.0,
        timeout: float = 30.0,
        verify: bool = True,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.batch_size = max(1, min(batch_size, SERVER_MAX_BATCH))
        self.max_buffer = max(1, max_buffer)
        self.max_retries = max(0, max_retries)
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self._sleep = sleep
        self._clock = clock
        self._buffer: deque[Event] = deque()
        self._next_flush_at = 0.0
        self.consecutive_failures = 0
        self.sent = 0
        self.dropped = 0  # buffer overflow
        self.rejected = 0  # refused by the server (4xx)
        headers = {"User-Agent": "tokiwa-agent"}
        if token:
            headers["X-Tokiwa-Token"] = token
        else:
            log.warning(
                "no ingest token configured; the server will reject events (set TOKIWA_AGENT__INGEST_TOKEN)"
            )
        self._client = httpx.AsyncClient(
            base_url=server_url.rstrip("/"),
            headers=headers,
            timeout=timeout,
            verify=verify,
            transport=transport,
        )

    # -- buffer ---------------------------------------------------------------------------------------
    @property
    def pending(self) -> int:
        return len(self._buffer)

    def submit(self, events: Iterable[Event]) -> None:
        self._buffer.extend(events)
        self._enforce_cap()

    def _enforce_cap(self) -> None:
        overflow = len(self._buffer) - self.max_buffer
        if overflow > 0:
            for _ in range(overflow):
                self._buffer.popleft()
            self.dropped += overflow
            log.warning("shipper buffer full (%d); dropped %d oldest events", self.max_buffer, overflow)

    # -- sending --------------------------------------------------------------------------------------
    def backoff(self, attempt: int) -> float:
        delay = min(self.backoff_max, self.backoff_base * (2**attempt))
        return delay * (0.5 + random.random() / 2)  # jitter: 50-100 %

    async def flush(self, *, force: bool = False) -> int:
        """Send buffered events. Returns how many were accepted. Stops at the first undeliverable batch."""
        if not force and self._clock() < self._next_flush_at:
            return 0
        accepted = 0
        while self._buffer:
            n = min(self.batch_size, len(self._buffer))
            batch = [self._buffer.popleft() for _ in range(n)]
            outcome = await self._send_with_retry(batch)
            if outcome is _Outcome.OK:
                accepted += n
                self.sent += n
                self.consecutive_failures = 0
                continue
            if outcome is _Outcome.REJECTED:
                self.rejected += n
                continue
            # FAILED: put the batch back in front (events submitted meanwhile stay behind it).
            self._buffer.extendleft(reversed(batch))
            self._enforce_cap()
            self.consecutive_failures += 1
            self._next_flush_at = self._clock() + self.backoff(self.consecutive_failures)
            break
        return accepted

    async def _send_with_retry(self, batch: list[Event]) -> _Outcome:
        payload = {"events": [e.model_dump(mode="json", exclude_none=True) for e in batch]}
        for attempt in range(self.max_retries + 1):
            try:
                resp = await self._client.post(INGEST_PATH, json=payload)
            except httpx.HTTPError as exc:
                log.warning("ingest failed (%s: %s), attempt %d", type(exc).__name__, exc, attempt + 1)
            else:
                if resp.is_success:
                    return _Outcome.OK
                if resp.status_code in (400, 413, 422):
                    log.error("server rejected a batch of %d events: HTTP %d", len(batch), resp.status_code)
                    return _Outcome.REJECTED
                if resp.status_code in (401, 403):
                    log.error("ingest token rejected (HTTP %d); keeping events buffered", resp.status_code)
                    return _Outcome.FAILED
                log.warning("ingest failed: HTTP %d, attempt %d", resp.status_code, attempt + 1)
            if attempt < self.max_retries:
                await self._sleep(self.backoff(attempt))
        return _Outcome.FAILED

    async def aclose(self) -> None:
        await self._client.aclose()
