"""Per-client token-bucket rate limiter for the gate's ``rate_limited`` policy.

The policy says "max N requests per minute" for an IP/CIDR. Each *client IP* gets its own bucket (so a CIDR
entry limits every address inside it individually, matching how the respond module proposes per-attacker
limits). Bucket capacity is N (burst) and it refills at N/60 tokens per second.

Memory is bounded: buckets live in an LRU map (``max_keys``); an evicted bucket simply starts full again,
which errs on the side of letting traffic through (fail-open), never on blocking legitimate users.
"""

from __future__ import annotations

import math
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float
    per_minute: int


class TokenBucketLimiter:
    def __init__(self, *, clock: Callable[[], float] = time.monotonic, max_keys: int = 100_000) -> None:
        self._clock = clock
        self._max_keys = max_keys
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()

    def allow(self, key: str, per_minute: int) -> tuple[bool, float]:
        """Consume one token. Returns ``(allowed, retry_after_seconds)``.

        ``per_minute <= 0`` denies everything (a "rate limit of zero" is effectively a soft block that still
        answers 429 rather than 403).
        """
        if per_minute <= 0:
            return False, 60.0
        now = self._clock()
        capacity = float(per_minute)
        rate = per_minute / 60.0
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(tokens=capacity, updated=now, per_minute=per_minute)
            self._buckets[key] = bucket
            if len(self._buckets) > self._max_keys:
                self._buckets.popitem(last=False)
        else:
            self._buckets.move_to_end(key)
            if bucket.per_minute != per_minute:  # policy changed: keep the fill ratio, rescale capacity
                bucket.tokens = min(capacity, bucket.tokens * capacity / max(bucket.per_minute, 1))
                bucket.per_minute = per_minute
            elapsed = max(0.0, now - bucket.updated)
            bucket.tokens = min(capacity, bucket.tokens + elapsed * rate)
            bucket.updated = now
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True, 0.0
        return False, max(1.0, math.ceil((1.0 - bucket.tokens) / rate))

    def reset(self) -> None:
        self._buckets.clear()

    def __len__(self) -> int:
        return len(self._buckets)
