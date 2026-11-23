"""Compressed request bodies (audit #141): the capture holds what an inflating upstream will process."""

from __future__ import annotations

import gzip
import zlib

from gate_helpers import FakeServer, GateFactory, Upstream, client_for, events_of

from tokiwa.config import Settings
from tokiwa.detect.web_common import build_view
from tokiwa.gate.capture import BodyCapture, EventBuilder, Exchange, decode_request_body
from tokiwa.schemas.events import Event

FORM = b"user=admin&password=x' OR '1'='1' UNION SELECT username,password FROM users--"


def _raw_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return c.compress(data) + c.flush()


def test_decode_request_body_codings() -> None:
    assert decode_request_body(gzip.compress(FORM), "gzip", 4096, False).data == FORM
    assert decode_request_body(gzip.compress(FORM), "X-GZIP", 4096, False).data == FORM
    assert decode_request_body(zlib.compress(FORM), "deflate", 4096, False).data == FORM
    assert decode_request_body(_raw_deflate(FORM), "deflate", 4096, False).data == FORM
    stacked = decode_request_body(gzip.compress(zlib.compress(FORM)), "deflate, gzip", 4096, False)
    assert stacked.status == "decoded" and stacked.data == FORM and not stacked.truncated
    plain = decode_request_body(FORM, "identity", 4096, False)
    assert plain.status == "identity" and plain.data == FORM


def test_unknown_and_corrupt_codings_are_reported() -> None:
    assert decode_request_body(b"\x1b\x00opaque", "br", 4096, False).status == "unknown"
    assert decode_request_body(b"x", "gzip, gzip, gzip", 4096, False).status == "unknown"
    failed = decode_request_body(b"definitely not gzip", "gzip", 4096, False)
    assert failed.status == "failed" and failed.data == b"definitely not gzip"
    assert decode_request_body(b"", "gzip", 4096, False).status == "empty"


def test_second_gzip_member_is_not_hidden() -> None:
    """Concatenated members are one gzip stream to an inflating upstream (Node zlib, gunzip)."""
    body = gzip.compress(b"harmless=1&") + gzip.compress(FORM)
    decoded = decode_request_body(body, "gzip", 4096, False)
    assert decoded.data == b"harmless=1&" + FORM and not decoded.truncated


def test_decompression_bomb_is_capped_at_the_capture_limit() -> None:
    bomb = gzip.compress(b"A" * 20_000_000)  # ~20 KB on the wire
    capture = BodyCapture(4096)
    capture.feed(bomb)
    capture.complete = True
    decoded = decode_request_body(capture.prefix, "gzip", 4096, capture.truncated)
    assert len(decoded.data) == 4096 and decoded.truncated


def test_truncated_compressed_prefix_yields_partial_text() -> None:
    big = FORM + b"&pad=" + bytes(range(256)) * 200
    decoded = decode_request_body(gzip.compress(big)[:40], "gzip", 4096, True)
    assert decoded.status == "decoded" and decoded.truncated
    assert big.startswith(decoded.data)


def _event(settings: Settings, body: bytes, encoding: str) -> Event:
    builder = EventBuilder(sensor_id="g", capture_body_bytes=4096, redaction=settings.llm.redaction)
    ex = Exchange(
        method="POST",
        scheme="https",
        path="/login",
        query="",
        raw_headers=[
            (b"host", b"shop.example"),
            (b"content-type", b"application/x-www-form-urlencoded"),
            (b"content-encoding", encoding.encode()),
        ],
        client_ip="203.0.113.9",
        client_port=40000,
    )
    ex.body = BodyCapture(4096)
    ex.body.feed(body)
    ex.body.complete = True
    ex.status = 200
    (event,) = builder.build(ex)
    return event


def test_event_carries_the_inflated_body_and_the_mark(settings: Settings) -> None:
    wire = gzip.compress(FORM)
    event = _event(settings, wire, "gzip")
    http = event.http
    assert http is not None
    assert "UNION SELECT" in (http.request_body or "")
    assert http.request_body_size == len(wire)  # the wire size, as before
    assert "gate:req_encoded" in event.tags
    assert event.labels["gate.request_encoding"] == "gzip"
    assert event.labels["gate.request_body_decoded_bytes"] == str(len(FORM))
    view = build_view(event)
    assert view is not None
    assert any(t.param == "password" and "union select" in t.lower for t in view.targets)


def test_event_marks_unknown_and_failed_encodings(settings: Settings) -> None:
    br = _event(settings, b"\x1b\x00opaque-brotli", "br")
    assert "gate:req_encoding_unknown" in br.tags and br.labels["gate.request_encoding"] == "unknown"
    assert br.http is not None and br.http.request_body is None
    bad = _event(settings, b"\x1f\x8bnot-really-gzip", "gzip")
    assert "gate:req_decode_failed" in bad.tags and bad.labels["gate.request_encoding"] == "gzip"


async def test_gate_forwards_compressed_bytes_and_captures_text(
    make_gate: GateFactory, upstream: Upstream, fake_server: FakeServer
) -> None:
    app, gate = await make_gate()
    wire = gzip.compress(FORM)
    async with client_for(app) as c:
        r = await c.post(
            "/login",
            content=wire,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Content-Encoding": "gzip"},
        )
    assert r.status_code == 200
    assert upstream.requests[0]["body"] == wire  # the upstream decides itself whether to inflate
    (event,) = await events_of(gate, fake_server)
    assert "UNION SELECT" in event["http"]["request_body"]
    assert "gate:req_encoded" in event["tags"]
