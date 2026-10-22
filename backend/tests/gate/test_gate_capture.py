from __future__ import annotations

import pytest

from tokiwa.config import RedactionSettings, Settings
from tokiwa.gate.capture import (
    BodyCapture,
    EventBuilder,
    Exchange,
    capture_headers,
    classify_content_type,
    looks_textual,
)
from tokiwa.schemas.events import EventKind
from tokiwa.schemas.response import DecoyRoute

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzNDUifQ.c2lnbmF0dXJlMTIzNDU2Nzg"


@pytest.mark.parametrize(
    ("content_type", "expected"),
    [
        ("application/json; charset=utf-8", True),
        ("text/plain", True),
        ("application/x-www-form-urlencoded", True),
        ("application/vnd.api+json", True),
        ("application/soap+xml", True),
        ("image/png", False),
        ("application/octet-stream", False),
        ("multipart/form-data; boundary=x", None),
        (None, None),
    ],
)
def test_classify_content_type(content_type: str | None, expected: bool | None) -> None:
    assert classify_content_type(content_type) is expected


def test_looks_textual() -> None:
    assert looks_textual(b"--b\r\nContent-Disposition: form-data; name=q\r\n\r\nunion select 1\r\n")
    assert looks_textual("日本語のテキスト".encode())
    assert not looks_textual(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
    assert not looks_textual(bytes(range(128, 256)))


def test_body_capture_prefix_and_size() -> None:
    cap = BodyCapture(8)
    for chunk in (b"abc", b"defgh", b"ijklmnop"):
        cap.feed(chunk)
    cap.complete = True
    assert cap.prefix == b"abcdefgh"
    assert cap.size == 16
    assert cap.truncated
    assert cap.text("text/plain") == "abcdefgh"


def test_body_capture_does_not_split_multibyte_chars() -> None:
    cap = BodyCapture(4)
    cap.feed("あい".encode())  # 6 bytes; the limit cuts the second char in half
    cap.complete = True
    assert cap.text("text/plain") == "あ"


def test_body_capture_binary_and_empty() -> None:
    cap = BodyCapture(64)
    cap.feed(b"\x89PNG\r\n\x1a\n\x00\x01")
    cap.complete = True
    assert cap.text("image/png") is None
    assert cap.text(None) is None  # sniffed as binary
    assert BodyCapture(64).text("application/json") is None


def test_capture_headers_keeps_order_and_duplicates() -> None:
    headers, order = capture_headers(
        [(b"Host", b"x"), (b"accept", b"*/*"), (b"cookie", b"a=1"), (b"Cookie", b"b=2"), (b"x-a", b"1")]
    )
    assert order == ["host", "accept", "cookie", "cookie", "x-a"]
    assert headers["cookie"] == "a=1; b=2"
    assert headers["host"] == "x"


def _exchange(**kw: object) -> Exchange:
    base: dict[str, object] = {
        "method": "POST",
        "scheme": "https",
        "path": "/api/login",
        "query": "next=/home&api_key=supersecretvalue",
        "raw_headers": [
            (b"host", b"shop.example"),
            (b"user-agent", b"python-httpx/0.28.1"),
            (b"authorization", f"Bearer {JWT}".encode()),
            (b"content-type", b"application/json"),
            (b"referer", b"https://shop.example/?email=alice@example.com"),
        ],
        "client_ip": "203.0.113.7",
        "client_port": 40000,
        "server_ip": "10.0.0.5",
        "server_port": 8080,
    }
    base.update(kw)
    return Exchange(**base)  # type: ignore[arg-type]


def test_event_builder_redacts_everything(settings: Settings) -> None:
    builder = EventBuilder(sensor_id="gate-x", capture_body_bytes=4096, redaction=settings.llm.redaction)
    ex = _exchange()
    ex.body = BodyCapture(4096)
    ex.body.feed(b'{"user":"alice@example.com","password":"hunter22","note":"' + JWT.encode() + b'"}')
    ex.body.complete = True
    ex.status = 200
    ex.response_size = 12
    ex.tag("gate:test")
    ex.labels["gate.action"] = "proxy"
    (event,) = builder.build(ex)
    http = event.http
    assert http is not None
    assert event.kind == EventKind.HTTP and event.dataset == "gate.http" and event.sensor_id == "gate-x"
    assert event.source is not None and event.source.ip == "203.0.113.7"
    assert http.headers["authorization"] == "[REDACTED:authorization]"
    assert "supersecretvalue" not in (http.query or "")
    assert "alice@example.com" not in (http.referrer or "")
    body = http.request_body or ""
    assert "hunter22" not in body and "alice@example.com" not in body and JWT not in body
    assert '"user"' in body  # structure kept for detection
    assert http.request_body_size == ex.body.size
    assert http.header_order[0] == "host"
    assert http.duration_ms is not None and http.duration_ms >= 0
    assert event.tags == ["gate:test"] and event.labels == {"gate.action": "proxy"}


def test_body_redaction_is_not_capped_by_generic_field_limit() -> None:
    redaction = RedactionSettings(max_field_chars=100)
    builder = EventBuilder(sensor_id="g", capture_body_bytes=1000, redaction=redaction)
    ex = _exchange()
    ex.body = BodyCapture(1000)
    ex.body.feed(b"q=" + b"A" * 900)
    ex.body.complete = True
    (event,) = builder.build(ex)
    assert event.http is not None
    assert len(event.http.request_body or "") == 902


def test_unread_body_size_falls_back_to_content_length(settings: Settings) -> None:
    builder = EventBuilder(sensor_id="g", capture_body_bytes=64, redaction=settings.llm.redaction)
    ex = _exchange(raw_headers=[(b"content-length", b"123456"), (b"content-type", b"application/json")])
    ex.status = 403
    (event,) = builder.build(ex)  # blocked requests are answered without reading the body
    assert event.http is not None
    assert event.http.request_body_size == 123456
    assert event.http.request_body is None


def test_decoy_exchange_yields_deception_event(settings: Settings) -> None:
    builder = EventBuilder(sensor_id="g", capture_body_bytes=64, redaction=settings.llm.redaction)
    ex = _exchange(method="GET", path="/.env", query="")
    ex.decoy = DecoyRoute(asset_id="asset-1", kind="decoy_path", path="/.env")
    ex.status = 200
    http_event, deception_event = builder.build(ex)
    assert http_event.kind == EventKind.HTTP
    assert deception_event.kind == EventKind.DECEPTION
    assert deception_event.dataset == "gate.deception"
    assert deception_event.deception is not None
    assert deception_event.deception.asset_id == "asset-1"
    assert deception_event.deception.asset_kind == "decoy_path"
    assert deception_event.timestamp == http_event.timestamp
    assert deception_event.http is not None and deception_event.http.path == "/.env"


def test_hostname_endpoints(settings: Settings) -> None:
    builder = EventBuilder(sensor_id="g", capture_body_bytes=0, redaction=settings.llm.redaction)
    (event,) = builder.build(_exchange(server_ip="gate.internal", server_port=None, client_ip=None))
    assert event.destination is not None and event.destination.hostname == "gate.internal"
    assert event.source is not None and event.source.ip is None
