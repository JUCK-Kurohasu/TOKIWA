"""``tail -F`` for log adapters: follow a file across rotation and truncation.

Rotation is detected by an identity change of the path (``st_dev``/``st_ino``): the remainder of the old file
is drained first, then the new file is read from its beginning. Truncation in place (logrotate
``copytruncate``) is detected by the size dropping below our read offset. Only complete lines are returned;
a trailing partial line is buffered until its newline arrives (or the file is rotated away).

All file I/O is blocking and meant to run via ``asyncio.to_thread`` (see :class:`LogSource`).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO, Literal

from tokiwa.schemas.events import Event, EventKind
from tokiwa.sensors.normalize import ParseContext, ParseStats
from tokiwa.util import utcnow

log = logging.getLogger(__name__)

StartAt = Literal["end", "beginning"]
HEALTH_DATASET = "agent.health"
HEALTH_REPORT_SECONDS = 300.0


class FileTailer:
    def __init__(
        self,
        path: str | Path,
        *,
        start_at: StartAt = "end",
        max_bytes_per_poll: int = 4 * 1024 * 1024,
        max_line_bytes: int = 1024 * 1024,
    ) -> None:
        self.path = Path(path)
        self.start_at = start_at
        self.max_bytes_per_poll = max_bytes_per_poll
        self.max_line_bytes = max_line_bytes
        self._fh: BinaryIO | None = None
        self._ident: tuple[int, int] | None = None
        self._pos = 0
        self._buf = b""
        self._started = False
        self.rotations = 0
        self.truncations = 0

    # -- public ---------------------------------------------------------------------------------------
    def read_lines(self) -> list[str]:
        """Return the complete lines appended since the previous call (blocking)."""
        first_poll = not self._started
        self._started = True
        lines: list[str] = []
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            # Rotated away and not recreated yet: finish what is left in the old file.
            if self._fh is not None:
                lines.extend(self._read_available(final=False))
            return lines
        except OSError as exc:
            log.warning("cannot stat %s: %s", self.path, exc)
            return lines

        ident = (st.st_dev, st.st_ino)
        if self._fh is None:
            # Honour start_at only for a file that existed when we started; a file that appears later is
            # entirely new content.
            self._open(seek_end=first_poll and self.start_at == "end")
        elif ident != self._ident:
            lines.extend(self._read_available(final=True))
            self._close()
            self.rotations += 1
            self._open(seek_end=False)
        elif st.st_size < self._pos:
            log.info("%s was truncated; reading from the start", self.path)
            assert self._fh is not None
            self._fh.seek(0)
            self._pos = 0
            self._buf = b""
            self.truncations += 1
        if self._fh is not None:
            lines.extend(self._read_available(final=False))
        return lines

    def read_head(self, max_bytes: int = 65536) -> list[str]:
        """First lines of the current file (for formats with a header, e.g. Zeek TSV ``#fields``)."""
        try:
            with open(self.path, "rb") as fh:
                data = fh.read(max_bytes)
        except OSError:
            return []
        head, _, _ = data.rpartition(b"\n")
        return [self._decode(chunk) for chunk in head.split(b"\n")] if head else []

    def close(self) -> None:
        self._close()

    # -- internals ------------------------------------------------------------------------------------
    def _open(self, *, seek_end: bool) -> None:
        try:
            fh = open(self.path, "rb")  # noqa: SIM115 - kept open across polls on purpose
        except OSError as exc:
            log.warning("cannot open %s: %s", self.path, exc)
            return
        # Identity of what we actually opened (the path may have been swapped since stat()).
        st = os.fstat(fh.fileno())
        self._fh = fh
        self._ident = (st.st_dev, st.st_ino)
        self._buf = b""
        if seek_end:
            self._pos = fh.seek(0, os.SEEK_END)
        else:
            self._pos = 0

    def _close(self) -> None:
        if self._fh is not None:
            with contextlib.suppress(OSError):
                self._fh.close()
        self._fh = None
        self._ident = None
        self._buf = b""
        self._pos = 0

    def _read_available(self, *, final: bool) -> list[str]:
        assert self._fh is not None
        self._fh.seek(self._pos)
        data = self._fh.read(self.max_bytes_per_poll)
        self._pos += len(data)
        buf = self._buf + data
        parts = buf.split(b"\n")
        self._buf = parts.pop()  # incomplete tail (b"" when data ended with a newline)
        if final and self._buf:
            parts.append(self._buf)
            self._buf = b""
        elif len(self._buf) > self.max_line_bytes:
            log.warning("%s: line longer than %d bytes, emitting truncated", self.path, self.max_line_bytes)
            parts.append(self._buf[: self.max_line_bytes])
            self._buf = b""
        return [self._decode(p) for p in parts]

    @staticmethod
    def _decode(chunk: bytes) -> str:
        return chunk.decode("utf-8", errors="replace").rstrip("\r")


class LineParser:
    """Turns one log line into zero or more events. Stateless parsers only implement :meth:`parse`."""

    name = "lines"

    def parse(self, line: str) -> list[Event]:  # pragma: no cover - interface
        raise NotImplementedError

    def wants_header(self, line: str) -> bool:
        """True when ``line`` cannot be parsed without the file header (read via ``read_head``)."""
        return False

    def feed_header(self, lines: list[str]) -> None:
        return None


class LogSource:
    """A tailed file plus the parser for its format.

    Audit #131: what the parser could not read is counted (``errors`` = parser exceptions, ``parser.ctx.stats``
    = unparseable lines / timestamps) and :meth:`health_event` turns new counts into a warning and an
    ``agent.health`` event — at once for the first problem, then at most every ``report_seconds``.
    """

    def __init__(
        self,
        tailer: FileTailer,
        parser: LineParser,
        *,
        report_seconds: float = HEALTH_REPORT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.tailer = tailer
        self.parser = parser
        self.lines = 0
        self.errors = 0
        self.report_seconds = report_seconds
        self._clock = clock
        self._next_report = 0.0
        self._reported = ParseStats()
        self._reported_errors = 0

    @property
    def name(self) -> str:
        return f"{self.parser.name}:{self.tailer.path}"

    def poll_sync(self) -> list[Event]:
        events: list[Event] = []
        for line in self.tailer.read_lines():
            if not line.strip():
                continue
            self.lines += 1
            try:
                if self.parser.wants_header(line):
                    self.parser.feed_header(self.tailer.read_head())
                events.extend(self.parser.parse(line))
            except Exception:
                self.errors += 1
                log.debug("failed to parse line from %s", self.name, exc_info=True)
        return events

    async def poll(self) -> list[Event]:
        return await asyncio.to_thread(self.poll_sync)

    @property
    def ctx(self) -> ParseContext | None:
        """The adapters keep their :class:`ParseContext` (with the per-source stats) in ``parser.ctx``."""
        ctx = getattr(self.parser, "ctx", None)
        return ctx if isinstance(ctx, ParseContext) else None

    @property
    def stats(self) -> ParseStats:
        ctx = self.ctx
        return ctx.stats if ctx is not None else ParseStats()

    def health_event(self) -> Event | None:
        """An ``agent.health`` event when new problems were counted since the last report (else None)."""
        current, errors = self.stats.snapshot(), self.errors
        delta, new_errors = current.minus(self._reported), errors - self._reported_errors
        if not delta.any() and new_errors <= 0:
            return None
        now = self._clock()
        if now < self._next_report:
            return None  # keep counting; reported together at the next slot
        self._next_report = now + self.report_seconds
        self._reported, self._reported_errors = current, errors
        hints: list[str] = []
        if delta.unparsed:
            hints.append(f"{delta.unparsed} line(s) not in the expected format")
        if new_errors > 0:
            hints.append(f"{new_errors} line(s) made the parser fail")
        if delta.bad_time:
            hints.append(f"{delta.bad_time} timestamp(s) not understood (collection time used)")
        if delta.naive_time:
            hints.append(
                f"{delta.naive_time} timestamp(s) without UTC offset read as UTC (set agent.log_timezone)"
            )
        if delta.recovered:
            hints.append(f"{delta.recovered} nginx escape=default line(s) decoded (set escape=json)")
        message = f"{self.name}: " + "; ".join(hints)
        ctx = self.ctx
        if delta.unparsed or delta.bad_time or new_errors > 0:
            log.warning("log source %s", message)
        else:
            log.info("log source %s", message)
        return Event(
            timestamp=utcnow(),
            kind=EventKind.CUSTOM,
            dataset=HEALTH_DATASET,
            sensor_id=ctx.sensor_id if ctx else None,
            host=ctx.host if ctx else None,
            message=message[:1000],
            labels={
                "health.source": self.name[:512],
                "health.parser": self.parser.name,
                "health.unparsed": str(delta.unparsed + max(new_errors, 0)),
                "health.bad_time": str(delta.bad_time),
                "health.naive_time": str(delta.naive_time),
                "health.recovered": str(delta.recovered),
                "health.lines": str(self.lines),
            },
        )

    def close(self) -> None:
        self.tailer.close()
