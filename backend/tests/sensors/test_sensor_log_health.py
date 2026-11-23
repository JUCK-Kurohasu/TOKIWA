"""Audit #131: log format mistakes are counted and reported instead of silently dropping telemetry.

Repro: docs/audit/2026-11/repro/L12/pass2/t_fmt.py (nginx escape=default line, offset-less / Caddy wall times).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from tokiwa.cli import _create_token
from tokiwa.config import AgentSettings, Settings
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.detectors.sensor_health import LogParseFailuresDetector
from tokiwa.schemas.events import EventKind, HostInfo
from tokiwa.sensors.agent import build_sources
from tokiwa.sensors.caddy import CaddyJsonParser
from tokiwa.sensors.logtail import FileTailer, LogSource
from tokiwa.sensors.nginx import NginxJsonParser, decode_escape_default
from tokiwa.sensors.normalize import ParseContext, event_time, parse_ts
from tokiwa.sensors.tz import resolve_timezone
from tokiwa.sensors.zeek import ZeekParser

JST = timezone(timedelta(hours=9))
# nginx escape=default: '"' -> \x22, UTF-8 bytes -> \xHH (ngx_http_log_escape)
ESCAPE_DEFAULT = (
    r'{"time_local":"11/Nov/2026:09:00:00 +0900","remote_addr":"203.0.113.9",'
    r'"request":"GET /?id=1%27+OR+1=1-- HTTP/1.1","status":"200",'
    r'"http_user_agent":"sqlmap\x22probe \xE3\x81\x82"}'
)


def test_nginx_escape_default_line_is_decoded_not_dropped() -> None:
    ctx = ParseContext(sensor_id="t")
    events = NginxJsonParser(ctx).parse(ESCAPE_DEFAULT)
    assert len(events) == 1
    http = events[0].http
    assert http is not None and http.user_agent == 'sqlmap"probe あ'
    assert events[0].source is not None and events[0].source.ip == "203.0.113.9"
    assert ctx.stats.recovered == 1 and ctx.stats.unparsed == 0
    assert decode_escape_default(r'"a\x5Cb"') == r'"a\\b"'  # backslash -> JSON escape


def test_unparseable_lines_are_counted_but_deliberate_skips_are_not() -> None:
    nginx = ParseContext()
    p = NginxJsonParser(nginx)
    assert p.parse('{"broken": "json"') == [] and p.parse("plain text line") == []
    assert p.parse('{"msg": "not an access record"}') == []  # valid JSON, skipped on purpose
    assert nginx.stats.unparsed == 2

    zeek = ParseContext()
    z = ZeekParser(zeek, "conn")
    assert z.parse("#separator \\x09") == [] and zeek.stats.unparsed == 0  # header lines are not failures
    assert z.parse("1.0\tCabc\t10.0.0.1") == [] and zeek.stats.unparsed == 1  # TSV without #fields


def test_offset_less_timestamps_use_log_timezone_or_are_counted() -> None:
    assert parse_ts("2026-11-11 09:00:00") == datetime(2026, 11, 11, 9, tzinfo=UTC)  # unchanged default
    assert parse_ts("2026-11-11 09:00:00", tz=JST) == datetime(2026, 11, 11, 0, tzinfo=UTC)
    assert parse_ts("2026-11-11T09:00:00+09:00", tz=UTC) == datetime(
        2026, 11, 11, 0, tzinfo=UTC
    )  # offset wins

    utc_ctx, jst_ctx = ParseContext(), ParseContext(tz=JST)
    assert event_time("2026-11-11T09:00:00", utc_ctx) == datetime(2026, 11, 11, 9, tzinfo=UTC)
    assert utc_ctx.stats.naive_time == 1
    assert event_time("2026-11-11T09:00:00", jst_ctx) == datetime(2026, 11, 11, 0, tzinfo=UTC)
    assert jst_ctx.stats.naive_time == 0
    assert event_time(1731283200.5, utc_ctx).year == 2024 and utc_ctx.stats.naive_time == 1  # epoch is UTC


def test_more_time_formats_and_bad_time_counting() -> None:
    ctx = ParseContext(tz=JST)
    # Caddy wall / wall_milli / wall_nano (local wall clock)
    for value in ("2026/11/11 09:00:00", "2026/11/11 09:00:00.250", "2026/11/11 09:00:00.250000123"):
        assert event_time(value, ctx).replace(microsecond=0) == datetime(2026, 11, 11, 0, tzinfo=UTC)
    assert parse_ts(1731283200123456) == parse_ts(1731283200.123456)  # microseconds since the epoch
    assert parse_ts("1731283200123456789") == parse_ts(1731283200.123456789)  # nanoseconds
    assert ctx.stats.bad_time == 0
    before = datetime.now(UTC)
    assert event_time("Nov 11 09:00:00", ctx) >= before  # not understood -> collection time, counted
    assert ctx.stats.bad_time == 1
    event_time(None, ctx)  # missing is not an error
    assert ctx.stats.bad_time == 1


def test_caddy_wall_time_in_record_uses_timezone() -> None:
    ctx = ParseContext(tz=JST)
    line = '{"ts":"2026/11/11 09:00:00.000","request":{"method":"GET","uri":"/x","remote_ip":"192.0.2.4"}}'
    (ev,) = CaddyJsonParser(ctx).parse(line)
    assert ev.timestamp == datetime(2026, 11, 11, 0, tzinfo=UTC)


def test_log_timezone_setting_is_validated() -> None:
    assert AgentSettings(log_timezone="+09:00").log_timezone == "+09:00"
    assert AgentSettings(log_timezone="UTC").log_timezone == "UTC"
    assert resolve_timezone("-0530") == timezone(-timedelta(hours=5, minutes=30))
    for bad in ("JST+9", "Asia/Tokio", "+25:00"):
        with pytest.raises(ValidationError):
            AgentSettings(log_timezone=bad)


def test_build_sources_gives_each_source_its_own_stats_and_tz(settings: Settings, tmp_path: Path) -> None:
    cfg = settings.agent.model_copy(
        update={"nginx_json_logs": [tmp_path / "a.log", tmp_path / "b.log"], "log_timezone": "+09:00"}
    )
    a, b = build_sources(cfg, ParseContext(sensor_id="s", host=HostInfo(name="web-1")), "beginning")
    assert a.ctx is not None and b.ctx is not None and a.ctx.stats is not b.ctx.stats
    assert a.ctx.tz == JST and a.ctx.sensor_id == "s"


async def test_health_event_is_reported_once_then_throttled(tmp_path: Path, settings: Settings) -> None:
    log = tmp_path / "access.log"
    log.write_text("not json\n" + ESCAPE_DEFAULT + "\n", encoding="utf-8")
    now = [100.0]
    src = LogSource(
        FileTailer(log, start_at="beginning"),
        NginxJsonParser(ParseContext(sensor_id="agent-1", host=HostInfo(name="web-1"))),
        report_seconds=300.0,
        clock=lambda: now[0],
    )
    try:
        assert len(src.poll_sync()) == 1
        health = src.health_event()
        assert health is not None and health.kind == EventKind.CUSTOM and health.dataset == "agent.health"
        assert health.labels["health.unparsed"] == "1" and health.labels["health.recovered"] == "1"
        assert health.sensor_id == "agent-1" and health.source is None
        assert src.health_event() is None  # nothing new

        with log.open("a", encoding="utf-8") as fh:
            fh.write("still not json\n{\n")
        src.poll_sync()
        assert src.health_event() is None  # within the report interval: held, not lost
        now[0] += 301
        later = src.health_event()
        assert later is not None and later.labels["health.unparsed"] == "2"
    finally:
        src.close()

    drafts = await LogParseFailuresDetector().process(health, DetectionContext(settings))
    assert len(drafts) == 1 and drafts[0].severity == "medium" and drafts[0].source_ip is None


async def test_bound_token_accepts_agent_health(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    token = await _create_token("agent-web01", ["ingest"], allowed_datasets=["nginx.access"])
    event: dict[str, Any] = {"kind": "custom", "dataset": "agent.health", "labels": {"health.unparsed": "1"}}
    r = await client.post(
        "/api/v1/ingest/events", json={"events": [event]}, headers={"X-Tokiwa-Token": token}
    )
    assert r.status_code == 200, r.text
    other = {"kind": "custom", "dataset": "agent.other"}
    r = await client.post(
        "/api/v1/ingest/events", json={"events": [other]}, headers={"X-Tokiwa-Token": token}
    )
    assert r.status_code == 403
