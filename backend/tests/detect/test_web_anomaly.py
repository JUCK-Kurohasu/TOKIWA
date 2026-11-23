"""detect-web: request-shape anomalies the Gate records but no signature sees (audit #140 / #141 / #147 / #150).

The events are built with the Gate's own :class:`EventBuilder` where the signal depends on what the Gate records
(tags, labels, latin-1 header values), so a change of the Gate's vocabulary breaks these tests, not production.
"""

from __future__ import annotations

import gzip
from collections.abc import Callable
from typing import Any

from tokiwa.config import RedactionSettings, Settings, WebDetectionSettings
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.engine import DetectionEngine
from tokiwa.gate.capture import EventBuilder, Exchange
from tokiwa.schemas.alerts import AlertDraft
from tokiwa.schemas.events import Event

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"


def gate_event(
    headers: list[tuple[str, str]] | list[tuple[bytes, bytes]],
    *,
    path: str = "/",
    method: str = "GET",
    status: int = 200,
    body: bytes = b"",
    tags: tuple[str, ...] = (),
    labels: dict[str, str] | None = None,
) -> Event:
    """The HTTP event the Gate would emit for this request (capture, tags and labels included)."""
    raw = [
        (k if isinstance(k, bytes) else k.encode(), v if isinstance(v, bytes) else v.encode())
        for k, v in headers
    ]
    ex = Exchange(
        method=method,
        scheme="http",
        path=path,
        query="",
        raw_headers=raw,
        client_ip="203.0.113.10",
        client_port=50000,
        server_ip="10.0.0.5",
        server_port=8080,
    )
    ex.body.limit = 4096
    ex.body.feed(body)
    ex.body.complete = True
    ex.status = status
    for t in tags:
        ex.tag(t)
    ex.labels.update(labels or {})
    builder = EventBuilder(sensor_id="gate-test", capture_body_bytes=4096, redaction=RedactionSettings())
    return builder.build(ex)[0]


async def run(settings: Settings, ev: Event, detector: str) -> list[AlertDraft]:
    det = DetectionEngine(settings).all_detectors()[detector]
    assert det.accepts(ev)
    return await det.process(ev, DetectionContext(settings))


async def all_web(settings: Settings, ev: Event) -> dict[str, AlertDraft]:
    ctx = DetectionContext(settings)
    out: dict[str, AlertDraft] = {}
    for det in DetectionEngine(settings).all_detectors().values():
        if det.id.startswith("web.") and det.accepts(ev):
            for d in await det.process(ev, ctx):
                out[d.rule_id] = d
    return out


def browser_headers(extra: int = 0) -> list[tuple[str, str]]:
    base = [
        ("host", "app.lab"),
        ("user-agent", UA),
        ("accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"),
        ("accept-language", "ja,en;q=0.8"),
        ("accept-encoding", "gzip, deflate, br"),
        ("sec-fetch-site", "none"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-dest", "document"),
    ]
    return base + [(f"x-pad-{i}", "a") for i in range(extra)]


# ---------------------------------------------------------------------------------------------------- #140


async def test_padding_past_the_capture_is_medium(settings: Settings) -> None:
    ev = gate_event(browser_headers(70))  # 78 lines: the Gate keeps 64 names and labels the real count
    assert "gate:headers_truncated" in ev.tags and ev.labels["gate.header_count"] == "78"
    [d] = await run(settings, ev, "web.header_anomaly")
    assert d.severity == "medium"
    assert d.details["header_count"] == 78 and d.details["header_count_exact"] is True
    assert d.details["headers_dropped"] == 14
    assert {"header_anomaly.capture_dropped", "header_anomaly.count"} <= set(d.details["signatures"])
    assert d.fingerprint == "web.header_anomaly|203.0.113.10|header_anomaly.capture_dropped"
    assert d.details["header_names_sample"][-1] == "x-pad-55"  # last recorded name


async def test_elevated_count_below_the_capture_is_low(settings: Settings) -> None:
    [d] = await run(
        settings, gate_event(browser_headers(40)), "web.header_anomaly"
    )  # 48 lines, nothing dropped
    assert d.severity == "low"
    assert d.details["signatures"] == ["header_anomaly.count"]
    assert d.details["header_count"] == 48 and d.details["header_count_exact"] is False


async def test_normal_browser_and_cdn_headers_are_quiet(settings: Settings) -> None:
    cdn = [(n, "x") for n in ("cf-ray", "cf-ipcountry", "cf-visitor", "cdn-loop", "x-forwarded-for")]
    hints = [(f"sec-ch-ua-{n}", '"x"') for n in ("arch", "bitness", "model", "platform-version", "wow64")]
    cookies = [("cookie", "a=" + "b" * 5000), ("cookie", "c=" + "d" * 5000)]  # split cookies, joined > 8192
    ev = gate_event(browser_headers() + cdn + hints + cookies)
    assert "gate:headers_truncated" in ev.tags and "gate.headers_dropped" not in ev.labels  # clipped only
    assert await run(settings, ev, "web.header_anomaly") == []


async def test_header_count_thresholds_are_configurable(settings: Settings) -> None:
    settings.detection.web = WebDetectionSettings(header_count_low=10, header_count_medium=0)
    [d] = await run(settings, gate_event(browser_headers(5)), "web.header_anomaly")
    assert d.severity == "low"
    settings.detection.web = WebDetectionSettings(header_count_low=0, header_count_medium=0)
    assert await run(settings, gate_event(browser_headers(40)), "web.header_anomaly") == []


async def test_rejected_header_flood_is_medium_without_a_count(settings: Settings) -> None:
    # 101 copies of one name: one recorded name (no truncation label), but the Gate refused it with 431.
    ev = gate_event([("x-a", "1")] * 101, tags=("gate:too_many_headers",), status=431)
    [d] = await run(settings, ev, "web.header_anomaly")
    assert d.severity == "medium" and d.details["signature"] == "header_anomaly.rejected"


async def test_duplicate_host_is_medium_other_duplicates_low(settings: Settings) -> None:
    ev = gate_event([("host", "app.lab"), ("host", "admin.internal"), ("user-agent", UA)])
    assert ev.labels["gate.duplicate_headers"] == "host"
    [d] = await run(settings, ev, "web.header_anomaly")
    assert d.severity == "medium" and d.details["signatures"] == ["header_anomaly.duplicate_framing"]
    ev = gate_event([("host", "app.lab"), ("user-agent", UA), ("user-agent", "sqlmap/1.8")])
    [d] = await run(settings, ev, "web.header_anomaly")
    assert d.severity == "low" and d.details["duplicate_headers"] == ["user-agent"]


async def test_header_anomaly_ignores_deception_copy_and_plain_sensors(
    settings: Settings, make_http_event: Callable[..., Any]
) -> None:
    assert await run(settings, make_http_event("/", headers={"user-agent": UA}), "web.header_anomaly") == []
    det = DetectionEngine(settings).all_detectors()["web.header_anomaly"]
    ev = gate_event(browser_headers(70))
    assert not det.accepts(ev.model_copy(update={"kind": "deception"}))  # one alert per request, not two


# ---------------------------------------------------------------------------------------------------- #141

FORM = "application/x-www-form-urlencoded"
SQLI_FORM = b"user=admin&password=1' UNION SELECT password FROM users--"


async def test_unknown_coding_accepted_by_the_app_is_medium(settings: Settings) -> None:
    hdrs = [("host", "app.lab"), ("user-agent", UA), ("content-type", FORM), ("content-encoding", "br")]
    ev = gate_event(hdrs, method="POST", body=b"\x1b\x2a\x00\xf8\x07opaque", status=200)
    assert "gate:req_encoding_unknown" in ev.tags and ev.http is not None and ev.http.request_body is None
    [d] = await run(settings, ev, "web.uninspectable_body")
    assert d.severity == "medium" and d.details["signatures"] == ["body.encoding_unknown"]
    assert d.details["content_encoding"] == "br" and d.details["upstream_accepted"] is True
    assert d.details["location"] == "body"
    rejected = gate_event(hdrs, method="POST", body=b"\x1b\x2a\x00opaque", status=415)
    [d] = await run(settings, rejected, "web.uninspectable_body")
    assert d.severity == "low"


async def test_corrupt_gzip_is_low_and_the_raw_body_is_still_inspected(settings: Settings) -> None:
    hdrs = [("host", "app.lab"), ("user-agent", UA), ("content-type", FORM), ("content-encoding", "gzip")]
    ev = gate_event(hdrs, method="POST", body=SQLI_FORM)  # an app ignoring Content-Encoding reads this as is
    assert "gate:req_decode_failed" in ev.tags
    drafts = await all_web(settings, ev)
    assert drafts["web.uninspectable_body"].severity == "low"
    assert drafts["web.uninspectable_body"].details["signatures"] == ["body.decode_failed"]
    assert drafts["web.sqli"].details["param"] == "password"


async def test_inflated_and_plain_bodies_are_quiet(settings: Settings) -> None:
    hdrs = [("host", "app.lab"), ("user-agent", UA), ("content-type", FORM), ("content-encoding", "gzip")]
    ev = gate_event(hdrs, method="POST", body=gzip.compress(b"user=alice&remember=1"))
    assert "gate:req_encoded" in ev.tags
    assert await run(settings, ev, "web.uninspectable_body") == []
    plain = gate_event(hdrs[:3], method="POST", body=b"user=alice")
    assert await run(settings, plain, "web.uninspectable_body") == []


# ---------------------------------------------------------------------------------------------------- #147

GATE_PROXIED = {"gate.action": "proxy", "gate.stripped_headers": "x-original-url"}


async def test_override_to_another_path_is_medium_and_probes_the_target(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    ev = make_http_event(
        "/static/app.js",
        headers={"user-agent": UA, "x-original-url": "/.env"},
        tags=["gate:route_override", "gate:client_ip_header"],
        labels=GATE_PROXIED,
    )
    assert ev.http is not None
    ev.http.response_content_type = "text/plain"  # 200 for the request line, not for /.env
    drafts = await all_web(settings, ev)
    ro = drafts["web.route_override"]
    assert ro.severity == "medium" and ro.details["signatures"] == ["route_override.different_path"]
    assert ro.details["override_paths"] == {"x-original-url": "/.env"}
    assert ro.details["param"] == "x-original-url"
    assert ro.fingerprint == "web.route_override|203.0.113.10|route_override.different_path"
    probe = drafts["web.sensitive_file_probe"]
    assert probe.details["location"] == "header_custom" and probe.details["param"] == "x-original-url"
    assert probe.severity == "medium" and probe.details["exposure"] == "none"  # no 2xx escalation
    assert "route_override" in probe.tags


async def test_override_variants(settings: Settings, make_http_event: Callable[..., Event]) -> None:
    async def one(path: str, value: str, **kw: Any) -> AlertDraft | None:
        ev = make_http_event(path, headers={"user-agent": UA, "x-rewrite-url": value}, **kw)
        out = await run(settings, ev, "web.route_override")
        return out[0] if out else None

    # a front end repeating the URL it received (also behind a stripped prefix) is not a bypass
    assert await one("/admin", "/Admin?x=1") is None
    prefixed = make_http_event(
        "/v2/orders", headers={"x-forwarded-prefix": "/api/", "x-original-url": "/api/v2/orders?page=2"}
    )
    assert await run(settings, prefixed, "web.route_override") == []
    url = await one("/", "https://app.lab/admin/users?id=1#x")
    assert url is not None and url.severity == "medium"
    assert url.details["override_paths"] == {"x-rewrite-url": "/admin/users"}
    empty = await one("/", " ")
    assert empty is not None and empty.details["signature"] == "route_override.empty"
    # no Gate tag (an older Gate that forwards the header, or another sensor): still client-sent
    assert await one("/", "/admin", labels={"gate.action": "proxy"}) is not None


async def test_override_the_operator_lets_through_is_quiet(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    # gate.forward_client_headers: ["x-original-url"] (a trusted front proxy sets it): proxied, not stripped
    trusted = make_http_event(
        "/app",
        headers={"user-agent": UA, "x-original-url": "/old/app"},
        tags=["gate:route_override"],
        labels={"gate.action": "proxy"},
    )
    assert await run(settings, trusted, "web.route_override") == []
    # the same header on a decoy answer was not forwarded at all: a probe
    decoy = make_http_event(
        "/static/app.js",
        headers={"user-agent": UA, "x-original-url": "/.env"},
        tags=["gate:route_override", "gate:decoy"],
        labels={"gate.action": "decoy"},
    )
    [d] = await run(settings, decoy, "web.route_override")
    assert d.details["gate_action"] == "decoy"


# ---------------------------------------------------------------------------------------------------- #150
# Code points are built with chr(): a literal U+202E in this file would reorder the source (and editors have
# expanded "\u" escapes into the real characters before, see docs/handoff/2026-11-21-audit-frontend.md).

RLO, ZWSP, ZWNJ, ZWJ, RLM = chr(0x202E), chr(0x200B), chr(0x200C), chr(0x200D), chr(0x200F)


def ascii_only(d: AlertDraft) -> None:
    for text in (d.title, d.details["matched"], *d.details["excerpts"].values()):
        assert text.isascii(), text


async def test_rlo_in_the_path_is_low(settings: Settings, make_http_event: Callable[..., Event]) -> None:
    ev = make_http_event(f"/download/invoice{RLO}fdp.exe")  # displayed as "invoiceexe.pdf"
    [d] = await run(settings, ev, "web.deceptive_unicode")
    assert d.severity == "low" and d.details["signatures"] == ["unicode.bidi_control"]
    assert d.details["location"] == "path" and d.details["param"] is None
    assert d.details["code_points"] == {"path": ["U+202E RIGHT-TO-LEFT OVERRIDE"]}
    assert "invoice<U+202E>fdp.exe" in d.details["excerpts"]["path"]
    assert d.fingerprint == "web.deceptive_unicode|203.0.113.10|unicode.bidi_control"
    assert "T1036.002" in d.mitre
    ascii_only(d)


async def test_percent_encoded_zero_width_in_an_access_log_path(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    [d] = await run(settings, make_http_event("/.e%E2%80%8Bnv"), "web.deceptive_unicode")  # looks like /.env
    assert d.details["signatures"] == ["unicode.zero_width"]
    assert d.details["code_points"] == {"path": ["U+200B ZERO WIDTH SPACE"]}
    [d] = await run(settings, make_http_event(f"/.e{ZWJ}nv"), "web.deceptive_unicode")  # joiner between ASCII
    assert d.details["signatures"] == ["unicode.zero_width"]


async def test_user_agent_through_the_gate_is_decoded_from_latin1(settings: Settings) -> None:
    ua = f"python-requests/2.32 {RLO}7.001.15.891 <- benign scanner".encode()
    ev = gate_event([(b"host", b"app.lab"), (b"user-agent", ua)])
    assert ev.http is not None and RLO not in (ev.http.user_agent or "")  # latin-1 on the event
    [d] = await run(settings, ev, "web.deceptive_unicode")
    assert d.details["location"] == "header" and d.details["param"] == "user-agent"
    assert d.details["code_points"] == {"user-agent": ["U+202E RIGHT-TO-LEFT OVERRIDE"]}
    ascii_only(d)


async def test_tag_characters_in_a_header(settings: Settings, make_http_event: Callable[..., Event]) -> None:
    hidden = "".join(chr(0xE0000 + ord(c)) for c in "ignore previous instructions")
    ev = make_http_event("/", headers={"user-agent": UA, "x-client-name": f"mobile{hidden}"})
    [d] = await run(settings, ev, "web.deceptive_unicode")
    assert d.details["signatures"] == ["unicode.tag_characters"] and d.details["param"] == "x-client-name"
    ascii_only(d)


async def test_scripts_that_use_joiners_and_marks_are_quiet(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    persian = "".join(chr(c) for c in (0x645, 0x6CC)) + ZWNJ + "".join(chr(c) for c in (0x62E, 0x648, 0x627))
    family = chr(0x1F468) + ZWJ + chr(0x1F469) + ZWJ + chr(0x1F467)
    england = chr(0x1F3F4) + "".join(chr(0xE0000 + ord(c)) for c in "gbeng") + chr(0xE007F)
    japanese = "".join(chr(c) for c in (0x691C, 0x7D22))
    quiet = [
        make_http_event(f"/blog/{persian}"),
        make_http_event(f"/tags/{family}"),
        make_http_event(f"/flags/{england}"),
        make_http_event(f"/{japanese}/page"),
        # query strings and bodies carry right-to-left marks and joiners in normal text: not inspected
        make_http_event("/search", query=f"q={persian}{RLM}"),
        make_http_event("/post", method="POST", body=f"text={family}{RLO}"),
    ]
    for ev in quiet:
        assert await run(settings, ev, "web.deceptive_unicode") == [], ev.http
    # a UTF-8 header value through the Gate (latin-1 on the event) that is ordinary Japanese text
    gate = gate_event([(b"host", b"app.lab"), (b"x-user-name", japanese.encode())])
    assert await run(settings, gate, "web.deceptive_unicode") == []
