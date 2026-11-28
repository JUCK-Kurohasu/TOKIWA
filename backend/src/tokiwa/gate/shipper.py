"""Batching event shipper: gate -> ``POST /api/v1/ingest/events``.

Design constraints (from docs/tasks/gate.md):

- The proxy must never wait on the TOKIWA server. ``submit()`` is synchronous and O(1); network I/O happens
  in a background task.
- Memory is bounded. When the queue is full, plain successful page views (GET/HEAD, 2xx/3xx, no query string,
  no Gate tag) are dropped first, oldest first; only when none are left do other events go, oldest first
  (audit #55: a flood of cheap GETs used to push the attack that preceded it out of the queue). This is a
  heuristic -- the client chooses method, status and query -- so the drops are also *reported*: the next batch
  that reaches the server carries a ``gate.health`` event with the counts (built at send time, so it cannot be
  evicted itself), and the ``sensor.events_dropped`` detector alerts on it.
- Fail-open: server down / slow / erroring never affects proxied traffic. Transient failures (network, 5xx,
  408, 429) are retried with exponential backoff, keeping the batch at the head of the queue; permanent ones
  (other 4xx, e.g. a missing scope or a schema mismatch) drop the batch with an error log, because retrying
  them forever would only pin memory.
- 401 (token revoked / expired / rotated, audit #163) is *not* permanent: the token file is re-read and the
  batch is re-sent at once when the token changed; otherwise the events stay queued (bounded, oldest dropped)
  and are retried with backoff until the operator writes a valid token to the file.
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

from tokiwa.gate.tokens import TokenSource
from tokiwa.schemas.events import Event, EventKind
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
    dropped_overflow: int = 0  # evicted because the queue was full (plain page views first, then oldest)
    dropped_notable: int = 0  # ...of which were not plain page views (#55)
    drops_reported: int = 0  # dropped_overflow + dropped_rejected the server has been told about
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
        token: str | TokenSource | None,
        *,
        batch_size: int = 100,
        flush_interval: float = 1.0,
        max_queue: int = 10_000,
        timeout: float = 10.0,
        max_backoff: float = 30.0,
        sensor_id: str | None = None,
    ) -> None:
        self.sensor_id = sensor_id
        self._client = client
        self._url = server_url.rstrip("/") + INGEST_PATH
        self._tokens = TokenSource.of(token)
        self.batch_size = max(1, min(batch_size, MAX_BATCH))
        self.flush_interval = max(0.05, flush_interval)
        self.max_queue = max(self.batch_size, max_queue)
        self._timeout = timeout
        self._max_backoff = max_backoff
        # Two queues so eviction can prefer plain page views without scanning (#55); _notable is sent first.
        self._notable: deque[Event] = deque()
        self._plain: deque[Event] = deque()
        self._wakeup = asyncio.Event()
        self._send_lock = asyncio.Lock()
        self._consecutive_failures = 0
        self._retry_at = 0.0
        self.stats = ShipperStats()

    # ------------------------------------------------------------------ producer side (request path)
    def submit(self, event: Event) -> None:
        (self._plain if is_plain_page_view(event) else self._notable).append(event)
        self.stats.submitted += 1
        overflow = len(self) - self.max_queue
        if overflow > 0:
            self._evict(overflow)
        if len(self) >= self.batch_size:
            self._wakeup.set()

    def submit_many(self, events: list[Event]) -> None:
        for e in events:
            self.submit(e)

    def _evict(self, n: int) -> None:
        notable = 0
        for _ in range(n):
            if self._plain:
                self._plain.popleft()
            elif self._notable:
                self._notable.popleft()
                notable += 1
            else:
                break
        before = self.stats.dropped_overflow
        self.stats.dropped_overflow += n
        self.stats.dropped_notable += notable
        # One line per drop would flood logs during an outage: warn on the first drop and every 1000 after.
        if before == 0 or before // 1000 != self.stats.dropped_overflow // 1000:
            log.warning(
                "gate shipper queue full (%d): dropped %d events so far (%d not plain page views)",
                self.max_queue,
                self.stats.dropped_overflow,
                self.stats.dropped_notable,
            )

    def _take(self, n: int) -> list[Event]:
        batch: list[Event] = []
        while len(batch) < n and (self._notable or self._plain):
            batch.append(self._notable.popleft() if self._notable else self._plain.popleft())
        return batch

    def _put_back(self, batch: list[Event]) -> None:
        for e in reversed(batch):
            (self._plain if is_plain_page_view(e) else self._notable).appendleft(e)

    @property
    def _unreported_drops(self) -> int:
        return self.stats.dropped_overflow + self.stats.dropped_rejected - self.stats.drops_reported

    def _health_event(self) -> Event:
        """Tell the server what was lost (#55). Built at send time, never queued, so it cannot be evicted."""
        s = self.stats
        return Event(
            kind=EventKind.CUSTOM,
            dataset=HEALTH_DATASET,
            sensor_id=self.sensor_id,
            message=(
                f"Gate shipper lost {self._unreported_drops} event(s) since the last report: queue full "
                f"(max {self.max_queue}) while the server was unreachable or slow, or batches rejected."
            ),
            tags=["gate:health"],
            labels={
                "health.dropped": str(self._unreported_drops),
                "health.dropped_overflow_total": str(s.dropped_overflow),
                "health.dropped_notable_total": str(s.dropped_notable),
                "health.dropped_rejected_total": str(s.dropped_rejected),
                "health.queued": str(len(self)),
                "health.max_queue": str(self.max_queue),
            },
        )

    def __len__(self) -> int:
        return len(self._notable) + len(self._plain)

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
            if not (len(self) or self._unreported_drops) or loop.time() < self._retry_at:
                continue
            await self.flush(partial=timed_out)

    async def flush(self, *, partial: bool = True) -> int:
        """Send queued events now, in batches. ``partial=False`` sends full batches only.

        Returns the number of events delivered. Never raises.
        """
        delivered = 0
        async with self._send_lock:
            while (len(self) and (partial or len(self) >= self.batch_size)) or self._unreported_drops:
                report = self._unreported_drops
                health = [self._health_event()] if report else []
                batch = self._take(min(self.batch_size - len(health), len(self)))
                outcome = await self._send(health + batch)
                if outcome == "ok":
                    delivered += len(batch)
                    self.stats.drops_reported += report
                    continue
                if outcome == "retry":
                    self._put_back(batch)  # the health event is rebuilt next time with fresh counts
                    overflow = len(self) - self.max_queue
                    if overflow > 0:
                        self._evict(overflow)
                    break
                # "drop": permanent rejection, move on to the next batch (the rejection itself is reported next).
                # The report is not an event of the protected site: keep it out of dropped_rejected.
                self.stats.dropped_rejected -= len(health)
                if not batch:
                    # Only the report was refused (e.g. a token without the scope): give up on these counts
                    # rather than re-sending a refused report every flush interval.
                    self.stats.drops_reported += report
                    break
        self.stats.queued = len(self)
        return delivered

    async def _post(self, payload: bytes) -> httpx.Response:
        headers = {"Content-Type": "application/json"}
        token = self._tokens.get()
        if token:
            headers["X-Tokiwa-Token"] = token
        return await self._client.post(self._url, content=payload, headers=headers, timeout=self._timeout)

    async def _send(self, batch: list[Event]) -> str:
        payload = json.dumps(
            {"events": [e.model_dump(mode="json", exclude_none=True) for e in batch]},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            resp = await self._post(payload)
            if resp.status_code == 401 and self._tokens.reload():
                resp = await self._post(payload)  # the token file was replaced: retry once right away
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
        if resp.status_code == 401:
            # Keep the events: the operator is expected to write a new token to the token file.
            return self._transient("HTTP 401 (API token rejected; waiting for a new token in the token file)")
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
        log.log(level, "gate shipper: send failed (%s); %d events queued, will retry", reason, len(self))
        self._consecutive_failures += 1
        backoff = min(self._max_backoff, self.flush_interval * (2 ** min(self._consecutive_failures - 1, 10)))
        with contextlib.suppress(RuntimeError):
            self._retry_at = asyncio.get_running_loop().time() + backoff
        return "retry"

    async def aclose(self, timeout: float = 5.0) -> None:
        """Best-effort final flush on shutdown."""
        if not len(self):
            return
        try:
            await asyncio.wait_for(self.flush(), timeout=timeout)
        except TimeoutError:
            log.warning("gate shipper: shutdown flush timed out; %d events lost", len(self))

    def snapshot(self) -> dict[str, object]:
        self.stats.queued = len(self)
        return self.stats.as_dict()


HEALTH_DATASET = "gate.health"
_PLAIN_METHODS = frozenset({"GET", "HEAD"})


def is_plain_page_view(event: Event) -> bool:
    """A successful GET/HEAD without query string or Gate tag: the first to go when the queue is full (#55)."""
    h = event.http
    if event.kind != EventKind.HTTP or h is None:
        return False
    if (h.method or "").upper() not in _PLAIN_METHODS or h.query:
        return False
    if h.status is None or h.status >= 400:
        return False
    return not any(t.startswith("gate:") for t in event.tags)
