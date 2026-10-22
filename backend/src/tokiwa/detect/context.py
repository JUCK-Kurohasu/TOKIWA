"""Shared state for detectors: TTL key/value store and per-key sliding windows (in memory).

State is per-process and intentionally simple (lab scale). It is lost on restart, which only affects
windowed detectors for the duration of one window.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypeVar

from tokiwa.config import Settings, get_settings
from tokiwa.util import utcnow

T = TypeVar("T")


class TTLStore:
    """Namespaced key/value with expiry. ``ns`` is usually the detector id."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._data: dict[tuple[str, str], tuple[float, Any]] = {}
        self._clock = clock
        self._ops = 0

    def get(self, ns: str, key: str, default: Any = None) -> Any:
        item = self._data.get((ns, key))
        if item is None:
            return default
        expires, value = item
        if expires < self._clock():
            self._data.pop((ns, key), None)
            return default
        return value

    def set(self, ns: str, key: str, value: Any, ttl: float = 3600.0) -> None:
        self._data[(ns, key)] = (self._clock() + ttl, value)
        self._ops += 1
        if self._ops % 5000 == 0:
            self.sweep()

    def setdefault(self, ns: str, key: str, factory: Callable[[], T], ttl: float = 3600.0) -> T:
        value = self.get(ns, key)
        if value is None:
            value = factory()
        self.set(ns, key, value, ttl)  # refresh TTL on access
        return value  # type: ignore[no-any-return]

    def delete(self, ns: str, key: str) -> None:
        self._data.pop((ns, key), None)

    def sweep(self) -> None:
        now = self._clock()
        for k in [k for k, (exp, _) in self._data.items() if exp < now]:
            self._data.pop(k, None)

    def clear(self) -> None:
        self._data.clear()


@dataclass
class Window:
    """Sliding time window of (timestamp, value) items, bounded by age and length."""

    seconds: float
    maxlen: int = 10_000
    items: deque[tuple[float, Any]] = field(default_factory=deque)

    def add(self, ts: datetime, value: Any) -> None:
        t = ts.timestamp()
        self.items.append((t, value))
        while len(self.items) > self.maxlen:
            self.items.popleft()
        self.evict(t)

    def evict(self, now: float) -> None:
        cutoff = now - self.seconds
        while self.items and self.items[0][0] < cutoff:
            self.items.popleft()

    def values(self) -> list[Any]:
        return [v for _, v in self.items]

    def timestamps(self) -> list[float]:
        return [t for t, _ in self.items]

    def __len__(self) -> int:
        return len(self.items)


class DetectionContext:
    def __init__(self, settings: Settings | None = None, state: TTLStore | None = None) -> None:
        self.settings = settings or get_settings()
        self.state = state or TTLStore()
        self._windows: dict[tuple[str, str], Window] = {}
        # Per-batch scratch space shared across detectors (reset by the engine for every batch)
        self.scratch: dict[str, Any] = {}

    def now(self) -> datetime:
        return utcnow()

    def window(self, ns: str, key: str, seconds: float, maxlen: int = 10_000) -> Window:
        w = self._windows.get((ns, key))
        if w is None:
            w = Window(seconds=seconds, maxlen=maxlen)
            self._windows[(ns, key)] = w
            if len(self._windows) % 2000 == 0:
                self._gc_windows()
        return w

    def _gc_windows(self) -> None:
        now = time.time()
        for k in [k for k, w in self._windows.items() if not w.items or w.items[-1][0] < now - w.seconds]:
            self._windows.pop(k, None)

    def reset(self) -> None:
        self.state.clear()
        self._windows.clear()
        self.scratch.clear()
