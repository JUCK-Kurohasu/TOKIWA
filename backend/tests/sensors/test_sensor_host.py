"""HostSensor with a fake psutil: listeners, process details (incl. AccessDenied), connection diffs."""

from __future__ import annotations

import socket
from collections import namedtuple
from collections.abc import Callable
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any, ClassVar

import psutil
import pytest

from tokiwa.schemas.events import EventKind
from tokiwa.sensors.host import HostSensor

addr = namedtuple("addr", ["ip", "port"])
sconn = namedtuple("sconn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])
pconn = namedtuple("pconn", ["fd", "family", "type", "laddr", "raddr", "status"])
snicaddr = namedtuple("snicaddr", ["family", "address", "netmask", "broadcast", "ptp"])

TCP, UDP = socket.SOCK_STREAM, socket.SOCK_DGRAM
V4, V6 = socket.AF_INET, socket.AF_INET6


def listen(ip: str, port: int, pid: int | None, *, family: int = V4) -> Any:
    return sconn(3, family, TCP, addr(ip, port), (), "LISTEN", pid)


def udp(ip: str, port: int, pid: int | None) -> Any:
    return sconn(4, V4, UDP, addr(ip, port), (), "NONE", pid)


def conn(lip: str, lport: int, rip: str, rport: int, status: str, pid: int | None) -> Any:
    return sconn(5, V4, TCP, addr(lip, lport), addr(rip, rport), status, pid)


class FakeProcess:
    table: ClassVar[dict[int, dict[str, Any]]] = {}

    def __init__(self, pid: int) -> None:
        if pid not in self.table:
            raise psutil.NoSuchProcess(pid)
        self.pid = pid
        self._info = self.table[pid]

    @contextmanager
    def oneshot(self) -> Any:
        yield

    def _get(self, key: str) -> Any:
        value = self._info.get(key)
        if isinstance(value, Exception):
            raise value
        return value

    def name(self) -> Any:
        return self._get("name")

    def exe(self) -> Any:
        return self._get("exe")

    def cmdline(self) -> Any:
        return self._get("cmdline")

    def username(self) -> Any:
        return self._get("username")


def fake_psutil(conns: Callable[[], list[Any]], processes: dict[int, dict[str, Any]]) -> SimpleNamespace:
    FakeProcess.table = processes
    return SimpleNamespace(
        net_connections=lambda kind="inet": conns(),
        net_if_addrs=lambda: {
            "lo": [snicaddr(V4, "127.0.0.1", None, None, None)],
            "eth0": [
                snicaddr(V4, "10.0.0.5", None, None, None),
                snicaddr(V6, "fe80::1%eth0", None, None, None),
            ],
        },
        Process=FakeProcess,
        process_iter=lambda: [],
        AccessDenied=psutil.AccessDenied,
        NoSuchProcess=psutil.NoSuchProcess,
        ZombieProcess=psutil.ZombieProcess,
    )


PROCS: dict[int, dict[str, Any]] = {
    100: {
        "name": "nginx",
        "exe": "/usr/sbin/nginx",
        "cmdline": ["nginx", "-g", "daemon off;"],
        "username": "root",
    },
    200: {
        "name": "python3",
        "exe": psutil.AccessDenied(200),
        "cmdline": ["python3", "app.py", "--password=hunter22"],
        "username": "app",
    },
}


@pytest.mark.usefixtures("settings")
def test_snapshot_and_connections() -> None:
    sockets = [
        listen("0.0.0.0", 80, 100),
        listen("::", 80, 100, family=V6),
        listen("127.0.0.1", 8000, 200),
        listen("0.0.0.0", 22, None),  # other user's socket without root
        udp("0.0.0.0", 53, 100),
        udp("0.0.0.0", 45000, 200),  # ephemeral client UDP: ignored
        conn("10.0.0.5", 80, "203.0.113.9", 50000, "ESTABLISHED", 100),
        conn("10.0.0.5", 41000, "93.184.216.34", 443, "ESTABLISHED", 200),
        conn("10.0.0.5", 22, "198.51.100.1", 40000, "SYN_RECV", None),
        conn("10.0.0.5", 80, "203.0.113.9", 50001, "TIME_WAIT", None),  # not collected
    ]
    sensor = HostSensor(
        sensor_id="s1",
        hostname="web-1",
        ephemeral_range=(32768, 60999),
        psutil_module=fake_psutil(lambda: sockets, PROCS),
    )
    events = sensor.collect_events()
    snap = events[0]
    assert snap.kind == EventKind.PORT_SNAPSHOT and snap.dataset == "host.ports"
    assert snap.host is not None and snap.host.name == "web-1" and snap.host.ip == ["10.0.0.5"]
    assert snap.port is not None
    keys = [(s.protocol, s.bind_ip, s.port) for s in snap.port.listeners]
    assert keys == [
        ("tcp", "0.0.0.0", 22),
        ("tcp", "0.0.0.0", 80),
        ("tcp", "127.0.0.1", 8000),
        ("tcp6", "::", 80),
        ("udp", "0.0.0.0", 53),
    ]
    by_port = {(s.protocol, s.port): s for s in snap.port.listeners}
    nginx = by_port[("tcp", 80)].process
    assert nginx is not None and nginx.name == "nginx" and nginx.cmdline == "nginx -g daemon off;"
    py = by_port[("tcp", 8000)].process
    assert py is not None and py.name == "python3" and py.exe is None  # AccessDenied -> missing, not an error
    assert py.cmdline is not None and "hunter22" not in py.cmdline  # secrets in argv are masked
    assert by_port[("tcp", 22)].process is None
    assert snap.labels["process_info"] == "partial"
    assert "socket_owner_hidden" in snap.labels["degraded"]

    conns = [e for e in events if e.kind == EventKind.CONNECTION]
    assert len(conns) == 3
    inbound = next(e for e in conns if e.source and e.source.ip == "203.0.113.9")
    assert inbound.network is not None and inbound.network.direction == "inbound"
    assert inbound.destination is not None and inbound.destination.port == 80
    outbound = next(e for e in conns if e.destination and e.destination.ip == "93.184.216.34")
    assert outbound.network is not None and outbound.network.direction == "outbound"
    assert outbound.source is not None and outbound.source.ip == "10.0.0.5"
    syn = next(e for e in conns if e.network and e.network.state == "SYN_RECV")
    assert syn.source is not None and syn.source.ip == "198.51.100.1"

    # Second cycle: unchanged connections are not re-reported, a new one is
    sockets.append(conn("10.0.0.5", 80, "203.0.113.77", 50100, "ESTABLISHED", 100))
    events2 = sensor.collect_events()
    conns2 = [e for e in events2 if e.kind == EventKind.CONNECTION]
    assert [e.source.ip for e in conns2 if e.source] == ["203.0.113.77"]


@pytest.mark.usefixtures("settings")
def test_access_denied_falls_back_to_per_process(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied() -> list[Any]:
        raise psutil.AccessDenied()

    class P:
        def __init__(self, pid: int, conns: list[Any] | Exception) -> None:
            self.pid = pid
            self._conns = conns

        def net_connections(self, kind: str = "inet") -> list[Any]:
            if isinstance(self._conns, Exception):
                raise self._conns
            return self._conns

    ps = fake_psutil(denied, PROCS)
    ps.process_iter = lambda: [
        P(100, [pconn(3, V4, TCP, addr("0.0.0.0", 443), (), "LISTEN")]),
        P(300, psutil.AccessDenied(300)),
    ]
    sensor = HostSensor(hostname="mac-1", psutil_module=ps, collect_connections=False)
    events = sensor.collect_events()
    assert len(events) == 1
    snap = events[0]
    assert snap.port is not None and [
        (s.port, s.process.name if s.process else None) for s in snap.port.listeners
    ] == [(443, "nginx")]
    assert "net_connections" in snap.labels["degraded"]


@pytest.mark.usefixtures("settings")
def test_enumeration_failure_sends_no_snapshot() -> None:
    def broken() -> list[Any]:
        raise RuntimeError("boom")

    sensor = HostSensor(hostname="h", psutil_module=fake_psutil(broken, {}))
    assert sensor.collect_events() == []  # an empty snapshot would look like "every port closed"


@pytest.mark.usefixtures("settings")
async def test_poll_runs_in_thread_and_caps_connections() -> None:
    sockets = [listen("0.0.0.0", 80, None)] + [
        conn("10.0.0.5", 80, f"203.0.113.{i}", 50000 + i, "ESTABLISHED", None) for i in range(1, 30)
    ]
    sensor = HostSensor(hostname="h", max_connections=10, psutil_module=fake_psutil(lambda: sockets, {}))
    events = await sensor.poll()
    assert sum(1 for e in events if e.kind == EventKind.CONNECTION) == 10


@pytest.mark.usefixtures("settings")
def test_vanished_process_is_not_an_error() -> None:
    sockets = [listen("0.0.0.0", 9000, 999)]  # pid 999 unknown -> NoSuchProcess
    sensor = HostSensor(hostname="h", psutil_module=fake_psutil(lambda: sockets, {}))
    snap = sensor.collect_events()[0]
    assert snap.port is not None
    proc = snap.port.listeners[0].process
    assert proc is not None and proc.pid == 999 and proc.name is None
