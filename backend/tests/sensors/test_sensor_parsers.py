"""Fixture parse tests for the log adapters (nginx / caddy / Suricata EVE / Zeek TSV + JSON)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tokiwa.schemas.events import Event, EventKind, HostInfo
from tokiwa.sensors.caddy import CaddyJsonParser
from tokiwa.sensors.logtail import FileTailer, LineParser, LogSource
from tokiwa.sensors.nginx import NginxJsonParser
from tokiwa.sensors.normalize import ParseContext, parse_ts, split_hostport, split_uri, truncate_raw
from tokiwa.sensors.suricata import SuricataEveParser
from tokiwa.sensors.zeek import ZeekParser, log_type_from_name

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "logs"
CTX = ParseContext(sensor_id="agent-1", host=HostInfo(name="web-1"))


def _parse_file(path: Path, parser: LineParser) -> list[Event]:
    src = LogSource(FileTailer(path, start_at="beginning"), parser)
    try:
        return src.poll_sync()
    finally:
        src.close()


def _dump(events: list[Event]) -> str:
    return json.dumps([e.model_dump(mode="json") for e in events])


@pytest.mark.usefixtures("settings")
def test_nginx_json() -> None:
    events = _parse_file(FIXTURES / "nginx_access.json", NginxJsonParser(CTX))
    assert len(events) == 3  # the non-JSON line is skipped
    first, login, env = events
    assert all(e.kind == EventKind.HTTP and e.dataset == "nginx.access" for e in events)
    assert first.sensor_id == "agent-1" and first.host is not None and first.host.name == "web-1"
    assert first.source is not None and first.source.ip == "203.0.113.10" and first.source.port == 51234
    assert first.destination is not None and first.destination.port == 80
    assert first.timestamp.isoformat() == "2026-10-22T10:00:01+00:00"  # +09:00 converted to UTC
    h = first.http
    assert h is not None
    assert (h.method, h.path, h.query, h.status, h.response_size) == ("GET", "/products", "id=1", 200, 512)
    assert h.duration_ms == pytest.approx(12.0)
    assert h.http_version == "1.1"
    assert h.headers["accept-language"] == "ja,en;q=0.8"
    assert "x-forwarded-for" not in h.headers  # empty values dropped
    assert first.labels["request_id"] == "6f1c2d"

    assert login.http is not None
    assert login.http.user_agent == "python-httpx/0.27.0"
    assert login.http.query is not None and "supersecretvalue123" not in login.http.query
    assert login.http.headers["cookie"] == "[REDACTED:cookie]"
    assert login.http.headers["authorization"] == "[REDACTED:authorization]"
    assert login.http.request_body_size == 42
    dumped = _dump([login])
    for secret in ("supersecretvalue123", "abcdef0123456789", "abcdefghijklmnopqrstuvwxyz"):
        assert secret not in dumped

    # Fallback keys: "request" line, msec timestamp, IPv4-mapped address
    assert env.http is not None and env.http.method == "GET" and env.http.path == "/.env"
    assert env.http.http_version == "1.0" and env.http.response_size == 153
    assert env.source is not None and env.source.ip == "192.0.2.44"
    assert env.timestamp.year == 2026


@pytest.mark.usefixtures("settings")
def test_caddy_json() -> None:
    events = _parse_file(FIXTURES / "caddy_access.json", CaddyJsonParser(CTX))
    assert len(events) == 2  # the tls log record is not an access log
    a, b = events
    assert a.dataset == "caddy.access" and a.kind == EventKind.HTTP
    assert a.source is not None and a.source.ip == "203.0.113.20" and a.source.port == 41342
    assert a.destination is not None and (a.destination.hostname, a.destination.port) == ("app.lab", 8443)
    assert a.http is not None
    assert a.http.scheme == "https" and a.http.http_version == "2.0" and a.http.status == 200
    assert a.http.response_content_type == "text/html; charset=utf-8"
    assert a.http.duration_ms == pytest.approx(0.929675)
    assert a.http.headers["cookie"] == "[REDACTED:cookie]"
    assert a.http.headers["authorization"] == "[REDACTED:authorization]"
    assert a.http.user_agent == "Mozilla/5.0 Firefox/131.0"
    dumped = _dump([a])
    for secret in ("very-secret-cookie", "dXNlcjpwYXNzd29yZDEyMw", "new-secret", "AKIAABCDEFGHIJKLMNOP"):
        assert secret not in dumped

    assert b.source is not None and (b.source.ip, b.source.port) == ("2001:db8::5", 5555)
    assert b.http is not None and b.http.method == "POST" and b.http.scheme == "http" and b.http.status == 500


@pytest.mark.usefixtures("settings")
def test_suricata_eve() -> None:
    events = _parse_file(FIXTURES / "suricata_eve.json", SuricataEveParser(CTX))
    kinds = [e.kind for e in events]
    assert kinds == [
        EventKind.IDS_ALERT,
        EventKind.HTTP,
        EventKind.CONNECTION,
        EventKind.DNS,
        EventKind.DNS,
    ]  # stats skipped
    alert, http, flow, dns2, dns3 = events
    assert all(e.dataset == "suricata.eve" for e in events)
    assert alert.ids is not None
    assert alert.ids.engine == "suricata" and alert.ids.signature_id == 2010935 and alert.ids.severity == 2
    assert alert.source is not None and alert.source.ip == "198.51.100.23"
    assert alert.labels["suricata.event_type"] == "alert" and alert.labels["flow_id"] == "1234567890"
    assert alert.http is not None and alert.http.query is not None and "hunter22" not in alert.http.query
    assert alert.timestamp.isoformat() == "2026-10-22T10:00:00.123456+00:00"

    assert (
        http.http is not None
        and http.http.status == 200
        and http.http.headers["cookie"] == "[REDACTED:cookie]"
    )
    assert "topsecret" not in _dump([http])

    assert flow.network is not None
    assert flow.network.bytes_out == 180 and flow.network.bytes_in == 120 and flow.network.packets == 5
    assert flow.network.state == "closed" and flow.network.protocol == "ssh"
    assert flow.network.duration_ms == pytest.approx(2500.0)

    assert dns2.labels["dns.query"] == "example.com" and dns2.labels["dns.answers"] == "93.184.216.34"
    assert dns3.labels["dns.query"] == "api.lab" and dns3.labels["dns.rrtype"] == "AAAA"
    assert dns3.message == "dns request api.lab AAAA"


@pytest.mark.usefixtures("settings")
@pytest.mark.parametrize("variant", ["zeek", "zeek_json"])
def test_zeek_logs(variant: str) -> None:
    d = FIXTURES / variant
    conn = _parse_file(d / "conn.log", ZeekParser(CTX, "conn"))
    http = _parse_file(d / "http.log", ZeekParser(CTX, "http"))
    notice = _parse_file(d / "notice.log", ZeekParser(CTX, "notice"))
    assert conn and http and notice
    c = conn[0]
    assert c.kind == EventKind.CONNECTION and c.dataset == "zeek.conn"
    assert c.network is not None and c.network.state == "SF" and c.network.transport == "tcp"
    assert c.labels["zeek.uid"]
    h = http[0]
    assert h.kind == EventKind.HTTP and h.dataset == "zeek.http" and h.http is not None
    assert h.http.status == 200
    n = notice[0]
    assert n.kind == EventKind.IDS_ALERT and n.dataset == "zeek.notice"
    assert n.ids is not None and n.ids.engine == "zeek"
    # credentials logged by Zeek's http.log never leave the host
    dumped = _dump(http)
    assert "s3cr3tpass" not in dumped and "letmein" not in dumped

    if variant == "zeek":
        assert len(conn) == 2
        assert c.source is not None and (c.source.ip, c.source.port) == ("198.51.100.23", 51234)
        assert c.destination is not None and c.destination.port == 80
        assert c.network.direction == "inbound" and c.network.protocol == "http"
        assert (c.network.bytes_out, c.network.bytes_in, c.network.packets) == (100, 200, 10)
        assert c.network.duration_ms == pytest.approx(500.0)
        assert (
            conn[1].network is not None
            and conn[1].network.state == "S0"
            and conn[1].network.bytes_out is None
        )
        assert h.http.path == "/search" and h.http.query is not None
        assert "abcdef123" not in h.http.query  # session=... masked
        assert "a\tb" in h.http.query  # \x09 escape decoded
        assert h.http.response_content_type == "text/html"
        assert n.ids.signature == "Scan::Port_Scan" and n.ids.category == "Scan"
        assert n.source is not None and n.source.ip == "198.51.100.23"
        assert n.destination is not None and n.destination.ip == "10.0.0.5"
        assert n.ids.action == "Notice::ACTION_LOG"
    else:
        assert c.network.direction == "internal" and c.network.packets == 18
        assert h.http.user_agent == "Claude-User" and h.timestamp.isoformat() == "2026-10-22T10:00:10+00:00"
        assert h.http.response_content_type == "application/json"
        assert n.ids.signature == "SSH::Password_Guessing"
        assert n.source is not None and n.source.ip == "203.0.113.50"


@pytest.mark.usefixtures("settings")
def test_zeek_tsv_header_from_head_when_tailing_from_end(tmp_path: Path) -> None:
    """Starting at the end of a TSV log skips its header: the parser fetches it with read_head()."""
    src_text = (FIXTURES / "zeek" / "conn.log").read_text()
    header = "".join(
        line + "\n" for line in src_text.splitlines() if line.startswith("#") and "#close" not in line
    )
    rows = [line for line in src_text.splitlines() if not line.startswith("#")]
    path = tmp_path / "conn.log"
    path.write_text(header)
    source = LogSource(FileTailer(path, start_at="end"), ZeekParser(CTX, "conn"))
    assert source.poll_sync() == []
    with path.open("a") as fh:
        fh.write(rows[0] + "\n")
    events = source.poll_sync()
    source.close()
    assert len(events) == 1 and events[0].source is not None and events[0].source.ip == "198.51.100.23"


def test_log_type_from_name() -> None:
    assert log_type_from_name("conn.log") == "conn"
    assert log_type_from_name("http.10:00:00-11:00:00.log") == "http"
    assert log_type_from_name("dns.log") is None


@pytest.mark.usefixtures("settings")
def test_truncate_raw_caps_size_and_redacts() -> None:
    # redact_obj caps each string at 2048 chars, so several long fields are needed to exceed 4 KB
    rec = {"password": "hunter2", **{f"f{i}": "x" * 2000 for i in range(5)}}
    small = truncate_raw({"password": "hunter2", "nested": {"token": "abc", "ok": "fine"}})
    assert small["password"] == "[REDACTED:secret]" and small["nested"]["token"] == "[REDACTED:secret]"
    assert small["nested"]["ok"] == "fine"
    big = truncate_raw(rec)
    assert big["_truncated"] is True and len(big["text"].encode()) <= 4096
    assert "hunter2" not in big["text"]


def test_normalize_helpers() -> None:
    assert split_uri("/a/b?x=1&y=2") == ("/a/b", "x=1&y=2")
    assert split_uri("http://h/p?q") == ("/p", "q")
    assert split_uri(None) == (None, None)
    assert split_hostport("[::1]:8080") == ("::1", 8080)
    assert split_hostport("example.com:443") == ("example.com", 443)
    assert split_hostport("2001:db8::1") == ("2001:db8::1", None)
    ts = parse_ts("22/Oct/2026:19:00:00 +0900")
    assert ts is not None and ts.hour == 10
    assert parse_ts(1792663200) is not None
    assert parse_ts("1792663200123") is not None  # milliseconds
    assert parse_ts("garbage") is None
    assert parse_ts("-") is None
