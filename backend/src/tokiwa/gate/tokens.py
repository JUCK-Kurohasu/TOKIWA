"""Gate API token source with hot reload (audit #163).

Why: the Gate used to read ``--token-file`` once at start, so replacing a leaked token meant restarting the Gate
(which drops proxied traffic and opens a fail-open window) or losing telemetry to 401s. Now the shipper and the
policy fetcher ask a :class:`TokenSource` for the current token on every request:

- the file is re-read when its mtime / size / inode changes (checked at most every ``check_interval`` seconds,
  one ``stat()``), so ``tokiwa token rotate`` + writing the new token to the file switches over without a restart;
- on HTTP 401 the caller forces :meth:`TokenSource.reload` and retries if the token changed;
- an empty, unreadable or half-written file keeps the previous token (never send an empty token).

The token value is never logged.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from pathlib import Path

log = logging.getLogger(__name__)


class TokenSource:
    def __init__(
        self,
        token: str | None = None,
        path: Path | None = None,
        *,
        check_interval: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._token = token or None
        self.path = path
        self.check_interval = max(0.0, check_interval)
        self._clock = clock
        self._sig: tuple[int, int, int] | None = None
        self._checked_at = float("-inf")
        self.reloads = 0
        self._warned = False
        if path is not None:
            self._read(force=True)
            self._checked_at = clock()
            self.reloads = 0  # the initial read is not a reload

    @classmethod
    def of(cls, value: str | TokenSource | None) -> TokenSource:
        return value if isinstance(value, TokenSource) else cls(value)

    def get(self) -> str | None:
        """Current token; re-reads the file when it changed (rate-limited stat)."""
        if self.path is not None:
            now = self._clock()
            if now - self._checked_at >= self.check_interval:
                self._checked_at = now
                self._read(force=False)
        return self._token

    def reload(self) -> bool:
        """Force a re-read (after a 401). Returns True when the token value changed."""
        if self.path is None:
            return False
        self._checked_at = self._clock()
        return self._read(force=True)

    def _read(self, *, force: bool) -> bool:
        assert self.path is not None
        try:
            st = os.stat(self.path)
        except OSError as exc:
            self._warn(f"cannot stat token file {self.path}: {type(exc).__name__}")
            return False
        sig = (st.st_mtime_ns, st.st_size, st.st_ino)
        if not force and sig == self._sig:
            return False
        try:
            value = self.path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError) as exc:
            self._warn(f"cannot read token file {self.path}: {type(exc).__name__}")
            return False
        if not value:
            # Half-written (truncate-then-write) or emptied by mistake: keep the previous token.
            self._warn(f"token file {self.path} is empty; keeping the previous token")
            return False
        self._sig = sig
        self._warned = False
        if value == self._token:
            return False
        first = self._token is None
        self._token = value
        if not first:
            self.reloads += 1
            log.info("gate: API token reloaded from %s", self.path)
        return True

    def _warn(self, message: str) -> None:
        if not self._warned:
            log.warning("gate: %s", message)
            self._warned = True
