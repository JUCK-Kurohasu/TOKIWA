"""net.port_scan and net.ids_alert as pure detectors (no DB)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from tokiwa.config import Settings
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.detectors.net_ids import IdsAlertDetector
from tokiwa.detect.detectors.net_scan import PortScanDetector
from tokiwa.schemas.events import Endpoint, Event, EventKind, IdsInfo, NetworkInfo
from tokiwa.util import utcnow


def _conn(
    src: str,
    dst: str,
    port: int,
    *,
    seconds: float = 0,
    direction: str | None = None,
    state: str | None = None,
) -> Event:
    return Event(
        timestamp=utcnow() + timedelta(seconds=seconds),
        kind=EventKind.CONNECTION,
        dataset="zeek.conn",
        source=Endpoint(ip=src, port=40000),
        destination=Endpoint(ip=dst, port=port),
        network=NetworkInfo(transport="tcp", direction=direction, state=state),
    )


async def test_vertical_port_scan(settings: Settings) -> None:
    det, ctx = PortScanDetector(), DetectionContext(settings)
    drafts = []
    for i in range(25):
        drafts += await det.process(_conn("198.51.100.23", "10.0.0.5", 1000 + i, seconds=i, state="S0"), ctx)
    assert len(drafts) == 1  # one draft per source per window
    d = drafts[0]
    assert d.rule_id == "net.port_scan" and d.severity == "medium" and d.source_ip == "198.51.100.23"
    assert d.details["distinct_ports"] == settings.agent.scan_port_threshold
    assert "vertical" in d.tags and d.mitre == ["T1046"]
    assert d.confidence == 0.8  # failed (S0) probes raise confidence
    assert len(d.evidence_event_ids) == settings.agent.scan_port_threshold


async def test_horizontal_sweep_and_window_expiry(settings: Settings) -> None:
    det, ctx = PortScanDetector(), DetectionContext(settings)
    # spread over > window: never 10 distinct hosts inside 60 s
    out = []
    for i in range(12):
        out += await det.process(_conn("203.0.113.5", f"10.0.0.{i}", 22, seconds=i * 30), ctx)
    assert out == []
    ctx2 = DetectionContext(settings)
    for i in range(12):
        out += await det.process(_conn("203.0.113.5", f"10.0.0.{i}", 22, seconds=i), ctx2)
    assert len(out) == 1 and "horizontal" in out[0].tags


async def test_outbound_and_normal_traffic_ignored(settings: Settings) -> None:
    det, ctx = PortScanDetector(), DetectionContext(settings)
    out = []
    for i in range(40):
        out += await det.process(
            _conn("10.0.0.5", f"93.184.{i}.1", 443, seconds=i, direction="outbound"), ctx
        )
        out += await det.process(
            _conn("203.0.113.9", "10.0.0.5", 443, seconds=i), ctx
        )  # one service, many conns
    assert out == []


async def test_large_scan_is_high(settings: Settings) -> None:
    det, ctx = PortScanDetector(), DetectionContext(settings)
    src = "198.51.100.99"
    events = [_conn(src, "10.0.0.5", p) for p in range(1, 5 * settings.agent.scan_port_threshold + 1)]
    ctx.state.set(det.id, src, True, ttl=3600)  # pretend the medium alert was already raised
    for e in events[:-1]:
        assert await det.process(e, ctx) == []
    ctx.state.delete(det.id, src)
    drafts = await det.process(events[-1], ctx)
    assert len(drafts) == 1 and drafts[0].severity == "high"


def _ids(
    engine: str,
    signature: str,
    *,
    sid: int | None = None,
    severity: int | None = None,
    category: str | None = None,
    action: str | None = None,
) -> Event:
    return Event(
        kind=EventKind.IDS_ALERT,
        dataset=f"{engine}.x",
        source=Endpoint(ip="198.51.100.23"),
        destination=Endpoint(ip="10.0.0.5", port=80),
        ids=IdsInfo(
            engine=engine,
            signature=signature,
            signature_id=sid,
            severity=severity,
            category=category,
            action=action,
        ),
        message=signature,
    )


@pytest.mark.parametrize(
    ("event", "severity", "category"),
    [
        (
            _ids(
                "suricata",
                "ET EXPLOIT x",
                sid=1,
                severity=1,
                category="Attempted Administrator Privilege Gain",
            ),
            "high",
            "exploit_attempt",
        ),
        (
            _ids("suricata", "ET SCAN y", sid=2, severity=2, category="Detection of a Network Scan"),
            "medium",
            "scan",
        ),
        (_ids("suricata", "ET INFO z", sid=3, severity=3, category="Misc activity"), "low", "ids"),
        (_ids("suricata", "no sev", sid=4), "medium", "ids"),
        (_ids("zeek", "Scan::Port_Scan"), "medium", "scan"),
        (_ids("zeek", "SSH::Password_Guessing"), "high", "credential_attack"),
        (_ids("zeek", "CaptureLoss::Too_Much_Loss"), "info", "other"),
        (_ids("zeek", "Custom::Thing"), "medium", "ids"),
    ],
)
async def test_ids_alert_mapping(settings: Settings, event: Event, severity: str, category: str) -> None:
    drafts = await IdsAlertDetector().process(event, DetectionContext(settings))
    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == severity and d.category == category
    assert d.source_ip == "198.51.100.23" and d.entities["dest_port"] == "80"
    assert d.fingerprint and len(d.fingerprint) <= 128


async def test_ids_alert_rule_id_and_blocked_tag(settings: Settings) -> None:
    det = IdsAlertDetector()
    d = (
        await det.process(
            _ids("suricata", "ET X", sid=2010935, severity=1, action="blocked"), DetectionContext(settings)
        )
    )[0]
    assert d.rule_id == "suricata:2010935" and "blocked" in d.tags
    z = (await det.process(_ids("zeek", "Scan::Address_Scan"), DetectionContext(settings)))[0]
    assert z.rule_id == "zeek:Scan::Address_Scan" and z.mitre == ["T1046"]
    empty = Event(kind=EventKind.IDS_ALERT, dataset="x", ids=IdsInfo(engine="suricata"))
    assert await det.process(empty, DetectionContext(settings)) == []
