"""Host sensor (FR-01): listening sockets and TCP connections via psutil.

Every cycle produces one ``PORT_SNAPSHOT`` (the full listener list; the server's ``ports`` enricher derives
opened/closed/process_changed from consecutive snapshots) plus ``CONNECTION`` events for ESTABLISHED /
SYN_RECV connections that were not present in the previous cycle.

Runs unprivileged: without root, Linux hides the owning process of other users' sockets (``pid=None``) and
macOS refuses ``net_connections`` entirely. Missing process details are recorded as absent (``process=None``
or a ``ProcessInfo`` with only ``pid``) and the snapshot carries ``labels["process_info"]="partial"``; it is
never an error. If sockets cannot be enumerated at all, no snapshot is sent — an empty snapshot would make the
server believe every port closed.

psutil calls block; use :meth:`HostSensor.poll` (``asyncio.to_thread``) from async code.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

from tokiwa.llm.redact import redact_text
from tokiwa.schemas.events import (
    Endpoint,
    Event,
    EventKind,
    HostInfo,
    ListeningSocket,
    NetworkInfo,
    PortInfo,
    ProcessInfo,
)
from tokiwa.sensors.normalize import normalize_ip
from tokiwa.util import utcnow

log = logging.getLogger(__name__)

CONNECTION_STATES = frozenset({"ESTABLISHED", "SYN_RECV"})
_CMDLINE_MAX = 512
_EPHEMERAL_DEFAULT = (32768, 60999)  # Linux default net.ipv4.ip_local_port_range
_PORT_RANGE_FILE = Path("/proc/sys/net/ipv4/ip_local_port_range")


@dataclass(frozen=True)
class RawConn:
    family: int
    type: int
    laddr: tuple[str, int] | None
    raddr: tuple[str, int] | None
    status: str
    pid: int | None


def _addr(a: Any) -> tuple[str, int] | None:
    if not a:
        return None
    try:
        return str(a[0]), int(a[1])
    except (TypeError, ValueError, IndexError):
        return None


def protocol_name(family: int, sock_type: int) -> str | None:
    if sock_type == socket.SOCK_STREAM:
        base = "tcp"
    elif sock_type == socket.SOCK_DGRAM:
        base = "udp"
    else:
        return None
    return f"{base}6" if family == socket.AF_INET6 else base


def _is_loopback(ip: str | None) -> bool:
    return bool(ip) and (str(ip).startswith("127.") or ip == "::1")


def _ephemeral_range() -> tuple[int, int]:
    try:
        lo, hi = _PORT_RANGE_FILE.read_text().split()
        return int(lo), int(hi)
    except (OSError, ValueError):
        return _EPHEMERAL_DEFAULT


class HostSensor:
    def __init__(
        self,
        sensor_id: str | None = None,
        hostname: str | None = None,
        *,
        collect_connections: bool = True,
        max_connections: int = 1000,
        ignore_ephemeral_udp: bool = True,
        ephemeral_range: tuple[int, int] | None = None,
        psutil_module: Any = psutil,
    ) -> None:
        self.hostname = hostname or socket.gethostname()
        self.sensor_id = sensor_id or self.hostname
        self.collect_connections = collect_connections
        self.max_connections = max_connections
        # Unconnected UDP sockets on ephemeral ports are mostly client sockets (resolvers, mDNS, QUIC);
        # reporting them as listeners would make PORT_CHANGE noisy. Trade-off: a UDP backdoor bound to an
        # ephemeral port is missed — disable via AgentSettings if that matters more.
        self.ignore_ephemeral_udp = ignore_ephemeral_udp
        self._ps = psutil_module
        self._seen_conns: set[tuple[str, str, int, str, int]] | None = None
        self._ephemeral = ephemeral_range or _ephemeral_range()
        self.degraded: set[str] = set()

    # -- host / process -------------------------------------------------------------------------------
    def host_info(self) -> HostInfo:
        ips: set[str] = set()
        try:
            for addrs in self._ps.net_if_addrs().values():
                for a in addrs:
                    if a.family not in (socket.AF_INET, socket.AF_INET6):
                        continue
                    ip = str(a.address).split("%", 1)[0]
                    if _is_loopback(ip) or ip.lower().startswith("fe80"):
                        continue
                    ips.add(ip)
        except Exception:
            log.debug("net_if_addrs failed", exc_info=True)
        return HostInfo(name=self.hostname, ip=sorted(ips)[:32], os=platform.system().lower() or None)

    def _process_info(self, pid: int | None, cache: dict[int, ProcessInfo | None]) -> ProcessInfo | None:
        if not pid:
            return None
        if pid in cache:
            return cache[pid]
        ps = self._ps
        info: ProcessInfo | None
        try:
            proc = ps.Process(pid)
            values: dict[str, Any] = {}
            with proc.oneshot():
                for attr in ("name", "exe", "cmdline", "username"):
                    try:
                        values[attr] = getattr(proc, attr)()
                    except (ps.AccessDenied, ps.ZombieProcess):
                        self.degraded.add("process_details")
                        values[attr] = None
            cmd = values.get("cmdline")
            cmdline = " ".join(str(c) for c in cmd) if isinstance(cmd, list | tuple) else cmd
            cmdline = redact_text(cmdline) if cmdline else None
            info = ProcessInfo(
                pid=pid,
                name=values.get("name") or None,
                exe=values.get("exe") or None,
                cmdline=cmdline[:_CMDLINE_MAX] if cmdline else None,
                username=values.get("username") or None,
            )
        except ps.NoSuchProcess:
            info = ProcessInfo(pid=pid)  # exited between enumeration and lookup
        except ps.AccessDenied:
            self.degraded.add("process_details")
            info = ProcessInfo(pid=pid)
        except Exception:
            log.debug("process lookup failed for pid %s", pid, exc_info=True)
            info = ProcessInfo(pid=pid)
        cache[pid] = info
        return info

    # -- sockets --------------------------------------------------------------------------------------
    def raw_connections(self) -> list[RawConn]:
        ps = self._ps
        try:
            return [
                RawConn(c.family, c.type, _addr(c.laddr), _addr(c.raddr), str(c.status), c.pid)
                for c in ps.net_connections(kind="inet")
            ]
        except ps.AccessDenied:
            # macOS / hardened kernels: fall back to the processes we are allowed to inspect.
            self.degraded.add("net_connections")
        out: list[RawConn] = []
        for proc in ps.process_iter():
            try:
                conns = proc.net_connections(kind="inet")
            except (ps.NoSuchProcess, ps.AccessDenied):
                continue
            for c in conns:
                out.append(RawConn(c.family, c.type, _addr(c.laddr), _addr(c.raddr), str(c.status), proc.pid))
        return out

    def _listeners(self, conns: list[RawConn], cache: dict[int, ProcessInfo | None]) -> list[ListeningSocket]:
        found: dict[tuple[str, str, int], ListeningSocket] = {}
        lo, hi = self._ephemeral
        for c in conns:
            proto = protocol_name(c.family, c.type)
            if proto is None or c.laddr is None:
                continue
            bind_ip, port = c.laddr
            if proto.startswith("tcp"):
                if c.status != "LISTEN":
                    continue
            else:
                if c.raddr is not None:
                    continue  # connected UDP socket = client
                if self.ignore_ephemeral_udp and lo <= port <= hi:
                    continue
            key = (proto, bind_ip, port)
            if c.pid is None:
                self.degraded.add("socket_owner_hidden")  # Linux without root: other users' sockets
            proc = self._process_info(c.pid, cache)
            existing = found.get(key)
            if existing is None or (existing.process is None and proc is not None):
                found[key] = ListeningSocket(protocol=proto, bind_ip=bind_ip, port=port, process=proc)
        return sorted(found.values(), key=lambda s: (s.protocol, s.port, s.bind_ip))

    def _connection_events(
        self,
        conns: list[RawConn],
        listeners: list[ListeningSocket],
        cache: dict[int, ProcessInfo | None],
        host: HostInfo,
    ) -> list[Event]:
        listen_ports = {s.port for s in listeners if s.protocol.startswith("tcp")}
        current: dict[tuple[str, str, int, str, int], RawConn] = {}
        for c in conns:
            if c.status not in CONNECTION_STATES or c.laddr is None or c.raddr is None:
                continue
            proto = protocol_name(c.family, c.type)
            if proto is None or not proto.startswith("tcp"):
                continue
            lip, rip = normalize_ip(c.laddr[0]) or c.laddr[0], normalize_ip(c.raddr[0]) or c.raddr[0]
            current[(proto, lip, c.laddr[1], rip, c.raddr[1])] = c
        previous = self._seen_conns or set()
        self._seen_conns = set(current)
        new_keys = [k for k in current if k not in previous]
        if len(new_keys) > self.max_connections:
            log.warning(
                "host sensor: %d new connections this cycle, reporting the first %d",
                len(new_keys),
                self.max_connections,
            )
            new_keys = new_keys[: self.max_connections]
        ts = utcnow()
        events: list[Event] = []
        for key in new_keys:
            proto, lip, lport, rip, rport = key
            c = current[key]
            inbound = c.status == "SYN_RECV" or lport in listen_ports
            direction = "internal" if _is_loopback(rip) else ("inbound" if inbound else "outbound")
            local, remote = Endpoint(ip=lip, port=lport), Endpoint(ip=rip, port=rport)
            src, dst = (remote, local) if inbound else (local, remote)
            proc = self._process_info(c.pid, cache)
            events.append(
                Event(
                    timestamp=ts,
                    kind=EventKind.CONNECTION,
                    dataset="host.connections",
                    sensor_id=self.sensor_id,
                    host=host,
                    source=src,
                    destination=dst,
                    network=NetworkInfo(transport="tcp", direction=direction, state=c.status, process=proc),
                    process=proc,
                    message=f"{direction} {src.ip}:{src.port} -> {dst.ip}:{dst.port} {c.status}",
                )
            )
        return events

    # -- entry points ---------------------------------------------------------------------------------
    def collect_events(self) -> list[Event]:
        """One collection cycle (blocking)."""
        self.degraded = set()
        try:
            conns = self.raw_connections()
        except Exception:
            log.exception("host sensor: cannot enumerate sockets; skipping this cycle")
            return []
        cache: dict[int, ProcessInfo | None] = {}
        host = self.host_info()
        listeners = self._listeners(conns, cache)
        labels: dict[str, str] = {}
        if self.degraded:
            labels["process_info"] = "partial"
            labels["degraded"] = ",".join(sorted(self.degraded))
        events = [
            Event(
                timestamp=utcnow(),
                kind=EventKind.PORT_SNAPSHOT,
                dataset="host.ports",
                sensor_id=self.sensor_id,
                host=host,
                port=PortInfo(listeners=listeners),
                message=f"{len(listeners)} listening sockets",
                labels=labels,
            )
        ]
        if self.collect_connections:
            events.extend(self._connection_events(conns, listeners, cache, host))
        return events

    async def poll(self) -> list[Event]:
        return await asyncio.to_thread(self.collect_events)
