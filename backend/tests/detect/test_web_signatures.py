"""detect-web: data-driven positive/negative tests for the web signature + recon detectors."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from tokiwa.config import Settings
from tokiwa.detect.base import Detector
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.engine import DetectionEngine
from tokiwa.schemas.events import Event

FIXTURES = Path(__file__).parent / "fixtures"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"

EXPECTED_IDS = {
    "web.sqli",
    "web.xss",
    "web.path_traversal",
    "web.lfi_rfi",
    "web.cmd_injection",
    "web.ssrf",
    "web.log4shell",
    "web.ssti",
    "web.xxe",
    "web.deserialization",
    "web.rsc_action_abuse",
    "web.sensitive_file_probe",
    "web.scanner_ua",
    "web.rare_method",
    "web.error_burst",
    "web.credential_stuffing",
    "web.request_flood",
}


def _load(name: str) -> list[dict[str, Any]]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))["cases"]


ATTACKS = _load("web_attacks.json")
BENIGN = _load("web_benign.json")


def build_event(make_http_event: Callable[..., Event], case: dict[str, Any]) -> Event:
    headers = {"user-agent": UA, **case.get("headers", {})}
    if "content_type" in case:
        headers["content-type"] = case["content_type"]
    ev = make_http_event(
        case.get("path", "/"),
        method=case.get("method", "GET"),
        query=case.get("query"),
        body=case.get("body"),
        status=case.get("status", 200),
        headers=headers,
        ua=headers["user-agent"],
    )
    if ev.http is not None and "response_content_type" in case:
        ev.http.response_content_type = case["response_content_type"]
    return ev


@pytest.fixture
def detectors(settings: Settings) -> dict[str, Detector]:
    return {k: v for k, v in DetectionEngine(settings).all_detectors().items() if k.startswith("web.")}


def test_all_web_detectors_registered(detectors: dict[str, Detector]) -> None:
    assert set(detectors) >= EXPECTED_IDS
    for det in detectors.values():
        assert det.mitre, det.id
        assert det.description, det.id


def test_every_signature_detector_has_positive_cases() -> None:
    covered = {c["detector"] for c in ATTACKS}
    stateful = {"web.error_burst", "web.credential_stuffing", "web.request_flood"}
    assert covered == EXPECTED_IDS - stateful


@pytest.mark.parametrize(
    "case", ATTACKS, ids=[f"{c['detector']}:{c.get('sig', '')}:{i}" for i, c in enumerate(ATTACKS)]
)
async def test_attack_case_detected(
    case: dict[str, Any],
    detectors: dict[str, Detector],
    settings: Settings,
    make_http_event: Callable[..., Event],
) -> None:
    ev = build_event(make_http_event, case)
    out = await detectors[case["detector"]].process(ev, DetectionContext(settings))
    assert len(out) == 1, f"no alert for {case}"
    draft = out[0]
    assert draft.rule_id == case["detector"]
    if "sig" in case:
        sigs = draft.details.get("signatures") or [
            e["kind"].split(":")[-1] for e in draft.details.get("evidence", [])
        ]
        assert case["sig"] in sigs, f"expected {case['sig']} in {sigs}"
    if "severity" in case:
        assert draft.severity == case["severity"]
    assert draft.evidence_event_ids == [ev.id]
    assert draft.fingerprint and draft.fingerprint.startswith(f"{case['detector']}|203.0.113.10|")
    assert draft.entities.get("host") == "app.lab"
    matched = draft.details.get("matched")
    assert isinstance(matched, str) and 0 < len(matched) <= 200


@pytest.mark.parametrize("case", BENIGN, ids=[c["name"] for c in BENIGN])
async def test_benign_traffic_is_quiet(
    case: dict[str, Any],
    detectors: dict[str, Detector],
    settings: Settings,
    make_http_event: Callable[..., Event],
) -> None:
    ev = build_event(make_http_event, case)
    ctx = DetectionContext(settings)
    fired = []
    for det in detectors.values():
        fired.extend(await det.process(ev, ctx))
    assert not fired, [(d.rule_id, d.details.get("signatures"), d.details.get("matched")) for d in fired]


async def test_alert_details_shape(
    detectors: dict[str, Detector], settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    ev = make_http_event("/items", query="id=1%20UNION%20SELECT%20null,version()--&sort=asc")
    [draft] = await detectors["web.sqli"].process(ev, DetectionContext(settings))
    assert draft.entities == {"path": "/items", "host": "app.lab", "param": "id"}
    assert draft.details["location"] == "query"
    assert draft.details["param"] == "id"
    assert "union select" in draft.details["matched"]
    assert draft.fingerprint == "web.sqli|203.0.113.10|/items"
    assert "T1190" in draft.mitre
    assert {"web", "sqli", "sqli.union_select"} <= set(draft.tags)
    # several distinct signatures raise confidence above the single best one
    assert draft.confidence >= 0.85


async def test_fingerprint_collapses_payload_variants(
    detectors: dict[str, Detector], settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    det = detectors["web.path_traversal"]
    fps = set()
    for p in ("/static/../../etc/passwd", "/static/../../../etc/shadow", "/static/..%2f..%2fetc/passwd"):
        [d] = await det.process(make_http_event(p), DetectionContext(settings))
        fps.add(d.fingerprint)
    assert fps == {"web.path_traversal|203.0.113.10|/static/{x}/etc"} or len(fps) <= 2


async def test_fragment_is_truncated_and_printable(
    detectors: dict[str, Detector], settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    payload = "A" * 500 + "%00%uD800<script>alert(1)</script>" + "B" * 500
    [d] = await detectors["web.xss"].process(
        make_http_event("/", query=f"q={payload}"), DetectionContext(settings)
    )
    frag = d.details["matched"]
    assert len(frag) <= 200 and "<script>" in frag
    json.dumps(d.model_dump(mode="json"))  # JSON-safe (no lone surrogates)


async def test_rsc_weak_indicators_need_context(
    detectors: dict[str, Detector], settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    det = detectors["web.rsc_action_abuse"]
    body = '{"_response":{"_prefix":"x","_formData":{}},"then":"$1"}'
    plain = make_http_event("/", method="POST", body=body, headers={"content-type": "application/json"})
    assert await det.process(plain, DetectionContext(settings)) == []
    hdrs = {"content-type": "application/json", "next-action": "7f3c2a9b1e4d5f60718293a4b5c6d7e8f9a0b1c2"}
    rsc = make_http_event("/", method="POST", body=body, headers=hdrs)
    [d] = await det.process(rsc, DetectionContext(settings))
    assert "rsc.internal_fields" in d.details["signatures"]
    assert d.details["rsc_context"] == "next-action header"
    assert "cve-2025-55182" in d.tags


async def test_sensitive_file_exposure_escalation(
    detectors: dict[str, Detector], settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    det = detectors["web.sensitive_file_probe"]

    async def run(status: int, rct: str | None) -> Any:
        ev = make_http_event("/.env", status=status)
        assert ev.http is not None
        ev.http.response_content_type = rct
        [d] = await det.process(ev, DetectionContext(settings))
        return d

    exposed = await run(200, "text/plain")
    assert exposed.severity == "critical" and exposed.details["exposure"] == "suspected"
    assert "exposure_suspected" in exposed.tags
    spa = await run(200, "text/html; charset=utf-8")
    assert spa.severity == "medium" and spa.details["exposure"].startswith("html_response")
    unknown = await run(200, None)
    assert unknown.severity == "high"
    missing = await run(404, "text/html")
    assert missing.severity == "medium" and missing.details["exposure"] == "none"
    assert missing.fingerprint == "web.sensitive_file_probe|203.0.113.10|file.secrets"


async def test_scanner_fingerprint_per_tool(
    detectors: dict[str, Detector], settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    det = detectors["web.scanner_ua"]
    ua = "sqlmap/1.7.2#stable (https://sqlmap.org)"
    [a] = await det.process(
        make_http_event("/a", ua=ua, headers={"user-agent": ua}), DetectionContext(settings)
    )
    [b] = await det.process(
        make_http_event("/b?id=1", ua=ua, headers={"user-agent": ua}), DetectionContext(settings)
    )
    assert a.fingerprint == b.fingerprint == "web.scanner_ua|203.0.113.10|sqlmap"
    assert a.details["tool"] == "sqlmap"


async def test_rare_method_allowlist_is_configurable(
    detectors: dict[str, Detector], settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    det = detectors["web.rare_method"]
    ev = make_http_event("/dav/", method="PROPFIND")
    assert len(await det.process(ev, DetectionContext(settings))) == 1
    settings.detection.web.allowed_methods.append("PROPFIND")
    assert await det.process(ev, DetectionContext(settings)) == []


async def test_non_http_events_ignored(detectors: dict[str, Detector], settings: Settings) -> None:
    from tokiwa.schemas.events import EventKind

    ev = Event(kind=EventKind.DNS, dataset="zeek.dns", message="' or 1=1 --")
    ctx = DetectionContext(settings)
    for det in detectors.values():
        if det.accepts(ev):
            assert await det.process(ev, ctx) == []


async def test_ingest_pipeline_creates_deduplicated_web_alerts(
    client: httpx.AsyncClient, ingest_headers: dict[str, str], make_http_event: Callable[..., Event]
) -> None:
    events = [
        make_http_event("/items", query=f"id={i}%20UNION%20SELECT%20null,version()--").model_dump(mode="json")
        for i in range(3)
    ]
    events.append(make_http_event("/search", query="q=how+to+select+a+dress").model_dump(mode="json"))
    r = await client.post("/api/v1/ingest/events", json={"events": events}, headers=ingest_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] == 4

    from sqlalchemy import select

    from tokiwa.db.models.detection import AlertRow
    from tokiwa.db.session import session_scope

    async with session_scope() as session:
        rows = (await session.execute(select(AlertRow).where(AlertRow.rule_id.like("web.%")))).scalars().all()
    # 3 SQLi variants on one route from one source -> one alert (count 3); the benign search -> nothing
    assert [(r.rule_id, r.count) for r in rows] == [("web.sqli", 3)]
    assert rows[0].fingerprint == "web.sqli|203.0.113.10|/items"
    assert rows[0].detector == "web.sqli"
