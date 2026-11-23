"""detect-web: request-shape anomalies the Gate records but no signature sees (audit #140 / #141 / #147 / #150).

The events are built with the Gate's own :class:`EventBuilder` where the signal depends on what the Gate records
(tags, labels, latin-1 header values), so a change of the Gate's vocabulary breaks these tests, not production.
"""

from __future__ import annotations

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
