"""FileTailer: start position, partial lines, rotation (rename + recreate), copytruncate, late files."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tokiwa.sensors.logtail import FileTailer, LogSource
from tokiwa.sensors.nginx import NginxJsonParser
from tokiwa.sensors.normalize import ParseContext


def _append(path: Path, text: str) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(text)


def test_start_at_end_skips_existing(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    p.write_text("old1\nold2\n")
    t = FileTailer(p, start_at="end")
    assert t.read_lines() == []
    _append(p, "new1\n")
    assert t.read_lines() == ["new1"]
    t.close()


def test_start_at_beginning_reads_existing(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    p.write_text("old1\nold2\n")
    t = FileTailer(p, start_at="beginning")
    assert t.read_lines() == ["old1", "old2"]
    assert t.read_lines() == []
    t.close()


def test_partial_line_is_buffered(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    p.write_text("")
    t = FileTailer(p, start_at="end")
    t.read_lines()
    _append(p, '{"a": 1')
    assert t.read_lines() == []
    _append(p, "}\r\nnext\n")
    assert t.read_lines() == ['{"a": 1}', "next"]
    t.close()


def test_rotation_rename_and_recreate(tmp_path: Path) -> None:
    p = tmp_path / "access.log"
    p.write_text("")
    t = FileTailer(p, start_at="end")
    t.read_lines()
    _append(p, "before-rotate\nlast-of-old")  # unterminated last line in the old file
    assert t.read_lines() == ["before-rotate"]
    os.rename(p, tmp_path / "access.log.1")
    _append(tmp_path / "access.log.1", "\n")  # writer still had the old file open
    # Missing between rename and recreate: nothing lost, nothing duplicated
    assert t.read_lines() == ["last-of-old"]
    p.write_text("first-of-new\n")
    assert t.read_lines() == ["first-of-new"]
    assert t.rotations == 1
    _append(p, "second-of-new\n")
    assert t.read_lines() == ["second-of-new"]
    t.close()


def test_rotation_drains_old_file_before_switching(tmp_path: Path) -> None:
    p = tmp_path / "access.log"
    p.write_text("")
    t = FileTailer(p, start_at="end")
    t.read_lines()
    _append(p, "a\n")
    os.rename(p, tmp_path / "access.log.1")
    _append(tmp_path / "access.log.1", "b\n")
    p.write_text("c\n")
    # one poll sees both the tail of the old file and the new file, in order
    assert t.read_lines() == ["a", "b", "c"]
    t.close()


def test_copytruncate(tmp_path: Path) -> None:
    p = tmp_path / "access.log"
    p.write_text("x" * 50 + "\n")
    t = FileTailer(p, start_at="end")
    t.read_lines()
    with p.open("w") as fh:  # truncate in place (logrotate copytruncate)
        fh.write("after\n")
    assert t.read_lines() == ["after"]
    assert t.truncations == 1
    t.close()


def test_file_created_after_start_is_read_from_beginning(tmp_path: Path) -> None:
    p = tmp_path / "late.log"
    t = FileTailer(p, start_at="end")
    assert t.read_lines() == []  # does not exist yet: no error
    p.write_text("hello\nworld\n")
    assert t.read_lines() == ["hello", "world"]
    t.close()


def test_overlong_line_is_emitted_truncated(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    p.write_text("")
    t = FileTailer(p, start_at="end", max_line_bytes=10)
    t.read_lines()
    _append(p, "y" * 25)
    out = t.read_lines()
    assert out == ["y" * 10]
    t.close()


@pytest.mark.usefixtures("settings")
async def test_log_source_async_poll_counts_errors(tmp_path: Path) -> None:
    p = tmp_path / "nginx.json"
    p.write_text("")
    src = LogSource(FileTailer(p, start_at="end"), NginxJsonParser(ParseContext(sensor_id="s")))
    assert await src.poll() == []
    _append(p, '{"request_method":"GET","request_uri":"/x","status":"200"}\n[1,2]\n\n')
    events = await src.poll()
    assert len(events) == 1 and events[0].http is not None and events[0].http.path == "/x"
    assert src.lines == 2  # blank line ignored
    src.close()
