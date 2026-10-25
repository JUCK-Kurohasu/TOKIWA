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
from pathlib import Path
from typing import BinaryIO, Literal

from tokiwa.schemas.events import Event

log = logging.getLogger(__name__)

StartAt = Literal["end", "beginning"]


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
    """A tailed file plus the parser for its format."""

    def __init__(self, tailer: FileTailer, parser: LineParser) -> None:
        self.tailer = tailer
        self.parser = parser
        self.lines = 0
        self.errors = 0

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

    def close(self) -> None:
        self.tailer.close()
