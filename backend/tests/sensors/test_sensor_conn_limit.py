"""Audit #121: over-limit connections are prioritised, carried over (never marked known) and reported as a signal.

Port of docs/audit/2026-11/repro/L12/pass2/t_conn.py: 1200 half-open + loopback noise plus one C2 connection.
"""

from __future__ import annotations

import socket
from collections import namedtuple
from types import SimpleNamespace
from typing import Any

import psutil

from tokiwa.config import Settings
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.detectors.sensor_health import ConnectionsTruncatedDetector
from tokiwa.schemas.events import Event, EventKind
from tokiwa.sensors.host import HostSensor

C = namedtuple("C", "family type laddr raddr status pid")
TCP, V4 = socket.SOCK_STREAM, socket.AF_INET
LISTEN = C(V4, TCP, ("10.0.0.5", 22), None, "LISTEN", None)
C2 = C(V4, TCP, ("10.0.0.5", 45000), ("203.0.113.66", 443), "ESTABLISHED", None)
SYN_NOISE = [
    C(V4, TCP, ("10.0.0.5", 22), (f"198.51.100.{i % 250}", 10000 + i), "SYN_RECV", None) for i in range(600)
]
LOOP_NOISE = [
    C(V4, TCP, ("127.0.0.1", 20000 + i), ("127.0.0.1", 6379), "ESTABLISHED", None) for i in range(600)
]


def _sensor(state: dict[str, list[Any]], limit: int = 1000) -> HostSensor:
    ps = SimpleNamespace(
        net_connections=lambda kind="inet": state["conns"],
        net_if_addrs=lambda: {},
        process_iter=lambda: [],
        Process=lambda pid: None,
        AccessDenied=psutil.AccessDenied,
        NoSuchProcess=psutil.NoSuchProcess,
        ZombieProcess=psutil.ZombieProcess,
    )
    return HostSensor("s", "web-1", max_connections=limit, ephemeral_range=(32768, 60999), psutil_module=ps)


def _conns(events: list[Event]) -> list[Event]:
    return [e for e in events if e.kind == EventKind.CONNECTION]


def _has_c2(events: list[Event]) -> bool:
    return any(e.destination is not None and e.destination.ip == "203.0.113.66" for e in _conns(events))


async def test_c2_is_reported_first_and_noise_is_carried_over(settings: Settings) -> None:
    state: dict[str, list[Any]] = {"conns": [LISTEN]}
    sensor = _sensor(state)
    sensor.collect_events()

    # Cycle 2: the noise is enumerated before the C2 connection (the order the audit used).
    state["conns"] = [LISTEN, *SYN_NOISE, *LOOP_NOISE, C2]
    events = sensor.collect_events()
    assert len(_conns(events)) == 1000
    assert _has_c2(events)  # established outbound first, in the same cycle
    snap = events[0]
    assert snap.kind == EventKind.PORT_SNAPSHOT
    assert snap.labels["connections_new"] == "1201" and snap.labels["connections_truncated"] == "201"
    assert "connections_truncated" in snap.labels["degraded"]

    drafts = await ConnectionsTruncatedDetector().process(snap, DetectionContext(settings))
    assert len(drafts) == 1
    assert drafts[0].source_ip is None and drafts[0].entities == {"host": "web-1"}  # never a response target

    # Cycle 3: the 201 deferred connections are still open -> reported now, nothing is lost, no repeat.
    events = sensor.collect_events()
    assert len(_conns(events)) == 201 and not _has_c2(events)
    assert "connections_truncated" not in events[0].labels
    assert await ConnectionsTruncatedDetector().process(events[0], DetectionContext(settings)) == []

    # Cycle 4: everything is known now.
    assert _conns(sensor.collect_events()) == []


def test_deferred_connection_closed_before_next_cycle_is_not_reported_late() -> None:
    state: dict[str, list[Any]] = {"conns": [LISTEN]}
    sensor = _sensor(state, limit=10)
    sensor.collect_events()
    state["conns"] = [LISTEN, *LOOP_NOISE[:15], C2]
    assert _has_c2(sensor.collect_events())
    state["conns"] = [LISTEN, C2]  # noise gone; C2 already reported -> stays known
    assert _conns(sensor.collect_events()) == []
