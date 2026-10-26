"""Batching event shipper: gate -> ``POST /api/v1/ingest/events``.

Design constraints (from docs/tasks/gate.md):

- The proxy must never wait on the TOKIWA server. ``submit()`` is synchronous and O(1); network I/O happens
  in a background task.
- Memory is bounded. When the queue is full the *oldest* events are dropped (recent activity is more useful
  for an in-progress incident) and the drop is counted in :class:`ShipperStats`.
- Fail-open: server down / slow / erroring never affects proxied traffic. Transient failures (network, 5xx,
  408, 429) are retried with exponential backoff, keeping the batch at the head of the queue; permanent ones
  (other 4xx, e.g. a revoked token or a schema mismatch) drop the batch with an error log, because retrying
  them forever would only pin memory.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime

import httpx

from tokiwa.schemas.events import Event
from tokiwa.util import utcnow

log = logging.getLogger(__name__)

INGEST_PATH = "/api/v1/ingest/events"
MAX_BATCH = 5000  # IngestBatch.events max_length


@dataclass
class ShipperStats:
    queued: int = 0
    submitted: int = 0
    sent: int = 0
    batches_sent: int = 0
    dropped_overflow: int = 0  # evicted because the queue was full (oldest first)
    dropped_rejected: int = 0  # server answered a permanent 4xx for the batch
    failed_attempts: int = 0  # transient failures (will be retried)
    last_error: str | None = None
    last_success: datetime | None = None

    def as_dict(self) -> dict[str, object]:
        d = asdict(self)
        d["last_success"] = self.last_success.isoformat() if self.last_success else None
        return d


class EventShipper:
    def __init__(
        self,
        client: httpx.AsyncClient,
        server_url: str,
        token: str | None,
        *,
        batch_size: int = 100,
        flush_interval: float = 1.0,
        max_queue: int = 10_000,
        timeout: float = 10.0,
        max_backoff: float = 30.0,
    ) -> None:
        self._client = client
        self._url = server_url.rstrip("/") + INGEST_PATH
        self._token = token
        self.batch_size = max(1, min(batch_size, MAX_BATCH))
        self.flush_interval = max(0.05, flush_interval)
        self.max_queue = max(self.batch_size, max_queue)
        self._timeout = timeout
        self._max_backoff = max_backoff
        self._queue: deque[Event] = deque()
        self._wakeup = asyncio.Event()
        self._send_lock = asyncio.Lock()
        self._consecutive_failures = 0
        self._retry_at = 0.0
        self.stats = ShipperStats()

    # ------------------------------------------------------------------ producer side (request path)
    def submit(self, event: Event) -> None:
        self._queue.append(event)
        self.stats.submitted += 1
        overflow = len(self._queue) - self.max_queue
        if overflow > 0:
            self._drop_oldest(overflow)
        if len(self._queue) >= self.batch_size:
            self._wakeup.set()

    def submit_many(self, events: list[Event]) -> None:
        for e in events:
            self.submit(e)

    def _drop_oldest(self, n: int) -> None:
        for _ in range(min(n, len(self._queue))):
            self._queue.popleft()
        before = self.stats.dropped_overflow
        self.stats.dropped_overflow += n
        # One line per drop would flood logs during an outage: warn on the first drop and every 1000 after.
        if before == 0 or before // 1000 != self.stats.dropped_overflow // 1000:
            log.warning(
                "gate shipper queue full (%d): dropped %d oldest events so far",
                self.max_queue,
                self.stats.dropped_overflow,
            )

    def __len__(self) -> int:
        return len(self._queue)

    # ------------------------------------------------------------------ consumer side (background task)
    async def run(self) -> None:
        """Full batches go out as soon as they fill up; a partial batch waits at most ``flush_interval``.

        (Draining the queue to empty on every wake-up would turn a busy gate into dozens of tiny POSTs per
        second -- one DB transaction each on the server.)
        """
        loop = asyncio.get_running_loop()
        while True:
            timed_out = False
            try:
                await asyncio.wait_for(self._wakeup.wait(), timeout=self.flush_interval)
            except TimeoutError:
                timed_out = True
            self._wakeup.clear()
            if not self._queue or loop.time() < self._retry_at:
                continue
            await self.flush(partial=timed_out)

    async def flush(self, *, partial: bool = True) -> int:
        """Send queued events now, in batches. ``partial=False`` sends full batches only.

        Returns the number of events delivered. Never raises.
        """
        delivered = 0
        async with self._send_lock:
            while self._queue and (partial or len(self._queue) >= self.batch_size):
                n = min(self.batch_size, len(self._queue))
                batch = [self._queue.popleft() for _ in range(n)]
                outcome = await self._send(batch)
                if outcome == "ok":
                    delivered += n
                    continue
                if outcome == "retry":
                    self._queue.extendleft(reversed(batch))
                    overflow = len(self._queue) - self.max_queue
                    if overflow > 0:
                        self._drop_oldest(overflow)
                    break
                # "drop": permanent rejection, move on to the next batch
        self.stats.queued = len(self._queue)
        return delivered

    async def _send(self, batch: list[Event]) -> str:
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["X-Tokiwa-Token"] = self._token
        payload = json.dumps(
            {"events": [e.model_dump(mode="json", exclude_none=True) for e in batch]},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            resp = await self._client.post(self._url, content=payload, headers=headers, timeout=self._timeout)
        except httpx.HTTPError as exc:
            return self._transient(f"{type(exc).__name__}: {exc}")
        if 200 <= resp.status_code < 300:
            if self._consecutive_failures:
                log.info("gate shipper recovered after %d failed attempts", self._consecutive_failures)
            self._consecutive_failures = 0
            self._retry_at = 0.0
            self.stats.sent += len(batch)
            self.stats.batches_sent += 1
            self.stats.last_success = utcnow()
            self.stats.last_error = None
            return "ok"
        if resp.status_code in (408, 429) or resp.status_code >= 500:
            return self._transient(f"HTTP {resp.status_code}")
        self.stats.dropped_rejected += len(batch)
        self.stats.last_error = f"HTTP {resp.status_code} (batch of {len(batch)} dropped)"
        log.error(
            "gate shipper: server rejected batch of %d events with HTTP %d; dropping (check token / version)",
            len(batch),
            resp.status_code,
        )
        return "drop"

    def _transient(self, reason: str) -> str:
        self.stats.failed_attempts += 1
        self.stats.last_error = reason
        level = logging.WARNING if self._consecutive_failures == 0 else logging.DEBUG
        log.log(
            level, "gate shipper: send failed (%s); %d events queued, will retry", reason, len(self._queue)
        )
        self._consecutive_failures += 1
        backoff = min(self._max_backoff, self.flush_interval * (2 ** min(self._consecutive_failures - 1, 10)))
        with contextlib.suppress(RuntimeError):
            self._retry_at = asyncio.get_running_loop().time() + backoff
        return "retry"

    async def aclose(self, timeout: float = 5.0) -> None:
        """Best-effort final flush on shutdown."""
        if not self._queue:
            return
        try:
            await asyncio.wait_for(self.flush(), timeout=timeout)
        except TimeoutError:
            log.warning("gate shipper: shutdown flush timed out; %d events lost", len(self._queue))

    def snapshot(self) -> dict[str, object]:
        self.stats.queued = len(self._queue)
        return self.stats.as_dict()
