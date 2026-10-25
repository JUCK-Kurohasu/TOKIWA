"""Correlation service against a real (sqlite) database: linking, new incidents, boosts, publishing."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any

import pytest

from tokiwa.bus import bus
from tokiwa.correlate.service import correlate_alert, recompute_incident
from tokiwa.db.models.detection import AlertRow, IncidentRow
from tokiwa.db.models.intel import VulnRow
from tokiwa.db.models.telemetry import ActorSessionRow
from tokiwa.db.session import session_scope
from tokiwa.schemas.events import Endpoint, Event, EventKind, HostInfo, ListeningSocket, PortInfo
from tokiwa.util import utcnow

AddAlert = Callable[..., Awaitable[Any]]
AddEvents = Callable[..., Awaitable[list[str]]]

pytestmark = pytest.mark.usefixtures("db")


async def _alert_row(alert_id: str) -> AlertRow:
    async with session_scope() as s:
        row = await s.get(AlertRow, alert_id)
        assert row is not None
        return row


async def test_first_alert_creates_incident(add_alert: AddAlert) -> None:
    a = await add_alert(mitre=["T1190"])
    inc = await correlate_alert(a.id)
    assert inc is not None
    assert inc.alert_count == 1
    assert inc.severity == "medium"
    assert inc.kill_chain == ["initial_access"]
    assert inc.source_ips == ["203.0.113.10"]
    assert inc.status == "open"
    assert "203.0.113.10" in inc.title
    assert inc.summary  # rule summary until triage writes one
    assert (await _alert_row(a.id)).incident_id == inc.id


async def test_same_source_ip_links_and_aggregates(add_alert: AddAlert) -> None:
    recon = await add_alert(
        rule_id="web.sensitive_file_probe", category="recon", severity="low", mitre=["T1595"]
    )
    inc1 = await correlate_alert(recon.id)
    sqli = await add_alert(rule_id="web.sqli", severity="high", mitre=["T1190"])
    inc2 = await correlate_alert(sqli.id)
    assert inc1 is not None and inc2 is not None
    assert inc2.id == inc1.id
    assert inc2.alert_count == 2
    assert inc2.severity == "high"  # max(alert)
    assert inc2.kill_chain == ["reconnaissance", "initial_access"]
    assert inc2.mitre == ["T1595", "T1190"]
    assert inc2.category == "exploit_attempt"


async def test_different_source_creates_new_incident(add_alert: AddAlert) -> None:
    a = await add_alert(source_ip="203.0.113.10")
    b = await add_alert(source_ip="198.51.100.7")
    inc_a = await correlate_alert(a.id)
    inc_b = await correlate_alert(b.id)
    assert inc_a is not None and inc_b is not None
    assert inc_a.id != inc_b.id


async def test_same_session_links_across_ips(
    add_alert: AddAlert, add_events: AddEvents, make_http_event
) -> None:
    e1 = make_http_event("/a", ip="203.0.113.10", session_id="sess-1")
    e2 = make_http_event("/b", ip="203.0.113.99", session_id="sess-1")
    await add_events(e1, e2)
    async with session_scope() as s:
        now = utcnow()
        s.add(
            ActorSessionRow(
                id="sess-1",
                source_ip="203.0.113.10",
                client_fingerprint="fp",
                first_seen=now,
                last_seen=now,
                ai_score=0.2,
                classification="automated_scanner",
            )
        )
    a = await add_alert(source_ip="203.0.113.10", evidence=[e1.id])
    b = await add_alert(source_ip="203.0.113.99", evidence=[e2.id], rule_id="web.xss")
    inc_a = await correlate_alert(a.id)
    inc_b = await correlate_alert(b.id)
    assert inc_a is not None and inc_b is not None
    assert inc_b.id == inc_a.id
    assert set(inc_b.source_ips) == {"203.0.113.10", "203.0.113.99"}
    # the actor session got back-linked and its classification feeds attribution
    async with session_scope() as s:
        sess = await s.get(ActorSessionRow, "sess-1")
        assert sess is not None and sess.incident_id == inc_a.id
    assert inc_b.actor_type == "automated_scanner"


async def test_entity_keys_link(add_alert: AddAlert) -> None:
    a = await add_alert(source_ip="203.0.113.1", entities={"cve": "CVE-2021-44228"})
    b = await add_alert(source_ip="203.0.113.2", entities={"cve": "CVE-2021-44228"})
    c = await add_alert(
        source_ip=None, entities={"host": "web-1", "port": "8080"}, rule_id="port.public_exposure"
    )
    d = await add_alert(
        source_ip=None, entities={"host": "WEB-1", "port": "8080"}, rule_id="port.process_changed"
    )
    ia, ib = await correlate_alert(a.id), await correlate_alert(b.id)
    ic, id_ = await correlate_alert(c.id), await correlate_alert(d.id)
    assert ia is not None and ib is not None and ic is not None and id_ is not None
    assert ia.id == ib.id
    assert ic.id == id_.id
    assert ia.id != ic.id


async def test_window_expiry_and_closed_incidents(add_alert: AddAlert) -> None:
    old = await add_alert(first_seen=utcnow() - timedelta(hours=3))
    inc_old = await correlate_alert(old.id)
    fresh = await add_alert()
    inc_fresh = await correlate_alert(fresh.id)
    assert inc_old is not None and inc_fresh is not None
    assert inc_fresh.id != inc_old.id  # outside incident_window_minutes (60)

    async with session_scope() as s:
        row = await s.get(IncidentRow, inc_fresh.id)
        assert row is not None
        row.status = "resolved"
    again = await add_alert()
    inc_again = await correlate_alert(again.id)
    assert inc_again is not None and inc_again.id != inc_fresh.id  # resolved incidents are not reused


async def test_info_alert_does_not_open_incident(add_alert: AddAlert) -> None:
    info = await add_alert(severity="info", source_ip="192.0.2.1")
    assert await correlate_alert(info.id) is None
    assert (await _alert_row(info.id)).incident_id is None
    # ...but attaches to an existing one
    med = await add_alert(severity="medium", source_ip="192.0.2.1")
    inc = await correlate_alert(med.id)
    info2 = await add_alert(severity="info", source_ip="192.0.2.1", rule_id="web.rare_method")
    inc2 = await correlate_alert(info2.id)
    assert inc is not None and inc2 is not None and inc2.id == inc.id


async def test_ai_boost(add_alert: AddAlert) -> None:
    a = await add_alert(rule_id="ai.agent_session", category="ai_agent", severity="medium", ai_score=0.85)
    inc = await correlate_alert(a.id)
    assert inc is not None
    assert inc.severity == "high"  # one level up
    assert inc.ai_score == pytest.approx(0.85)
    assert inc.actor_type == "ai_agent"
    assert "ai_agent" in inc.tags


async def test_kev_boost(add_alert: AddAlert) -> None:
    async with session_scope() as s:
        s.add(VulnRow(id="CVE-2021-44228", kev=True))
        s.add(VulnRow(id="CVE-2020-0001", kev=False))
    kev_alert = await add_alert(
        source_ip="203.0.113.5", entities={"cve": "CVE-2021-44228"}, rule_id="web.log4shell"
    )
    plain = await add_alert(source_ip="203.0.113.6", entities={"cve": "CVE-2020-0001"})
    inc_kev = await correlate_alert(kev_alert.id)
    inc_plain = await correlate_alert(plain.id)
    assert inc_kev is not None and inc_plain is not None
    assert inc_kev.severity == "high" and "kev" in inc_kev.tags
    assert inc_plain.severity == "medium" and "kev" not in inc_plain.tags
    # boosts are recomputed, never accumulated
    again = await recompute_incident(inc_kev.id)
    assert again is not None and again.severity == "high"


def _port_change(port: int, host: str = "web-1") -> Event:
    sock = ListeningSocket(protocol="tcp", bind_ip="0.0.0.0", port=port)
    return Event(
        kind=EventKind.PORT_CHANGE,
        dataset="host.ports",
        host=HostInfo(name=host),
        port=PortInfo(change="opened", socket=sock),
    )


async def test_port_request_correlation(add_alert: AddAlert, add_events: AddEvents, make_http_event) -> None:
    pc = _port_change(4444)
    req = make_http_event("/shell", ip="198.51.100.20")
    req.destination = Endpoint(ip="10.0.0.5", port=4444)
    other = make_http_event("/x", ip="198.51.100.21")  # destination port 8080 (fixture default)
    await add_events(pc, req, other)

    listener = await add_alert(
        rule_id="port.unexpected_listener",
        category="port_deviation",
        severity="medium",
        source_ip=None,
        mitre=[],
        evidence=[pc.id],  # host/port come from the PORT_CHANGE evidence
        first_seen=utcnow() - timedelta(minutes=5),
    )
    inc_listener = await correlate_alert(listener.id)
    assert inc_listener is not None and inc_listener.kill_chain == ["persistence"]

    unrelated = await add_alert(source_ip="198.51.100.21", evidence=[other.id])
    inc_unrelated = await correlate_alert(unrelated.id)
    assert inc_unrelated is not None and inc_unrelated.id != inc_listener.id
    assert "correlated:port_request" not in inc_unrelated.tags

    hit = await add_alert(source_ip="198.51.100.20", evidence=[req.id], rule_id="web.cmd_injection")
    inc = await correlate_alert(hit.id)
    assert inc is not None
    assert inc.id == inc_listener.id  # no IP/session match -> joins the listener's incident
    assert "correlated:port_request" in inc.tags
    assert inc.severity == "high"  # medium + port-request boost
    assert inc.alert_count == 2


async def test_request_before_listener_is_not_port_request(
    add_alert: AddAlert, add_events: AddEvents, make_http_event
) -> None:
    req = make_http_event("/x", ip="198.51.100.30")
    req.destination = Endpoint(ip="10.0.0.5", port=5555)
    pc = _port_change(5555)
    await add_events(req, pc)
    hit = await add_alert(
        source_ip="198.51.100.30", evidence=[req.id], first_seen=utcnow() - timedelta(minutes=10)
    )
    await add_alert(
        rule_id="port.unexpected_listener",
        category="port_deviation",
        source_ip=None,
        evidence=[pc.id],
    )
    inc = await correlate_alert(hit.id)
    assert inc is not None and "correlated:port_request" not in inc.tags


async def test_publishes_created_then_updated_only_on_change(add_alert: AddAlert) -> None:
    seen: list[tuple[str, Any]] = []

    async def created(inc: Any) -> None:
        seen.append(("created", inc))

    async def updated(inc: Any) -> None:
        seen.append(("updated", inc))

    bus.subscribe("incident.created", created)
    bus.subscribe("incident.updated", updated)
    a = await add_alert()
    await correlate_alert(a.id)
    await bus.drain()
    assert [k for k, _ in seen] == ["created"]

    await correlate_alert(a.id)  # nothing changed -> no event
    await bus.drain()
    assert [k for k, _ in seen] == ["created"]

    b = await add_alert(severity="critical", rule_id="web.log4shell")
    await correlate_alert(b.id)
    await bus.drain()
    assert [k for k, _ in seen] == ["created", "updated"]
    assert seen[-1][1].severity == "critical"


async def test_false_positive_alerts_do_not_drive_severity(add_alert: AddAlert) -> None:
    low = await add_alert(severity="low", rule_id="web.rare_method")
    crit = await add_alert(severity="critical", rule_id="web.log4shell")
    await correlate_alert(low.id)
    inc = await correlate_alert(crit.id)
    assert inc is not None and inc.severity == "critical"
    async with session_scope() as s:
        row = await s.get(AlertRow, crit.id)
        assert row is not None
        row.status = "false_positive"
    inc2 = await correlate_alert(crit.id)
    assert inc2 is not None and inc2.severity == "low"
    assert inc2.alert_count == 2  # still linked, just not counted for severity
