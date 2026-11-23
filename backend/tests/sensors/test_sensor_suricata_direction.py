"""Audit #123: Suricata alerts attribute the attacker by rule target / flow direction, not by packet direction.

Record 1 is the official EVE alert example (Suricata userguide, output/eve/eve-json-format.rst), trimmed:
``direction: to_client`` with ``metadata.attack_target: [Client_Endpoint]`` - a malicious server answering one of
our clients, so the packet source *is* the attacker and must not be swapped.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tokiwa.config import Settings
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.detectors.net_ids import IdsAlertDetector
from tokiwa.schemas.events import Event, HostInfo
from tokiwa.sensors.logtail import FileTailer, LogSource
from tokiwa.sensors.normalize import ParseContext
from tokiwa.sensors.suricata import SuricataEveParser

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "logs" / "suricata_eve_direction.json"
SERVER, ATTACKER = "10.0.0.5", "203.0.113.66"


@pytest.fixture
def alerts() -> list[Event]:
    src = LogSource(
        FileTailer(FIXTURE, start_at="beginning"), SuricataEveParser(ParseContext(host=HostInfo()))
    )
    try:
        return src.poll_sync()
    finally:
        src.close()


def _ips(e: Event) -> tuple[str | None, str | None]:
    return (e.source.ip if e.source else None, e.destination.ip if e.destination else None)


def test_client_target_metadata_keeps_packet_direction(alerts: list[Event]) -> None:
    ev = alerts[0]
    assert _ips(ev) == ("142.11.240.191", "192.168.100.237")
    assert ev.source is not None and ev.source.port == 35361
    assert ev.labels["suricata.direction"] == "to_client"
    assert ev.labels["suricata.attribution"] == "attack_target_client" and "suricata.swapped" not in ev.labels


def test_server_response_alert_points_at_the_client(alerts: list[Event]) -> None:
    ev = alerts[1]  # GPL ATTACK_RESPONSE id check returned root: packet src is our web server
    assert _ips(ev) == (ATTACKER, SERVER)
    assert ev.source is not None and ev.source.port == 51515
    assert ev.destination is not None and ev.destination.port == 80
    assert ev.labels["suricata.attribution"] == "to_client" and ev.labels["suricata.swapped"] == "true"
    assert ev.raw is not None and ev.raw["src_ip"] == SERVER  # the original packet direction stays in raw


def test_rule_target_wins(alerts: list[Event]) -> None:
    ev = alerts[2]
    assert _ips(ev) == (ATTACKER, SERVER)
    assert ev.labels["suricata.attribution"] == "rule_target" and ev.labels["suricata.swapped"] == "true"


def test_to_server_alert_is_unchanged(alerts: list[Event]) -> None:
    ev = alerts[3]
    assert _ips(ev) == (ATTACKER, SERVER)
    assert ev.labels["suricata.direction"] == "to_server" and "suricata.swapped" not in ev.labels


async def test_ids_detector_attributes_the_attacker_not_our_server(
    alerts: list[Event], settings: Settings
) -> None:
    drafts = await IdsAlertDetector().process(alerts[1], DetectionContext(settings))
    assert drafts and drafts[0].source_ip == ATTACKER
    assert drafts[0].entities.get("source_ip") in (None, ATTACKER)
