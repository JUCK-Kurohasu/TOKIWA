"""Ports enricher (FR-01/02): PORT_SNAPSHOT -> ``host_ports`` state + derived PORT_CHANGE events.

For every snapshot the host's stored listeners are compared with the reported ones:

* ``opened``          listener not stored (or stored as closed)
* ``closed``          stored open listener missing from the snapshot
* ``process_changed`` same (protocol, bind_ip, port) but a different, known owning process

Derived events are inserted right after their snapshot **in the same batch list**, so the pipeline stores
and runs detection on them together. Detectors are pure (no DB), so each PORT_CHANGE carries what they need
from the baselines in ``labels``:

* ``baseline``                 ``allowed`` | ``none``
* ``baseline.allow_public``    ``true`` | ``false`` (when allowed)
* ``baseline.process_mismatch``  ``true`` when a baseline exists for the port but names another process
* ``port.initial``             ``true`` on the first snapshot of an unknown host (see
  ``AgentSettings.ports_first_snapshot``: ``info`` emits these at info severity, ``learn`` emits nothing)
* ``port.previous_process``    for process_changed

Host key = ``event.host.name`` (falls back to ``sensor_id``). State changes are committed in their own
transaction before the events are stored; a failed store therefore leaves ``host_ports`` one snapshot ahead,
which only means the next snapshot reports no difference.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from typing import ClassVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.config import get_settings
from tokiwa.db.models.telemetry import HostPortRow, PortBaselineRow
from tokiwa.db.session import session_scope
from tokiwa.enrich.base import Enricher, register_enricher
from tokiwa.schemas.events import (
    Endpoint,
    Event,
    EventKind,
    HostInfo,
    ListeningSocket,
    PortInfo,
    ProcessInfo,
)
from tokiwa.schemas.hosts import match_baseline
from tokiwa.util import new_id

log = logging.getLogger(__name__)

CHANGE_DATASET = "host.port_change"
Key = tuple[str, str, int]


def host_key(event: Event) -> str:
    if event.host is not None and event.host.name:
        return event.host.name[:255]
    return (event.sensor_id or "unknown")[:255]


def _dedupe(listeners: Sequence[ListeningSocket]) -> dict[Key, ListeningSocket]:
    out: dict[Key, ListeningSocket] = {}
    for s in listeners:
        key = (s.protocol.lower()[:8], s.bind_ip[:64], int(s.port))
        existing = out.get(key)
        if existing is None or (existing.process is None and s.process is not None):
            out[key] = s
    return out


def baseline_labels(baselines: Sequence[PortBaselineRow], host: str, sock: ListeningSocket) -> dict[str, str]:
    pname = sock.process.name if sock.process else None
    match = match_baseline(baselines, host=host, protocol=sock.protocol, port=sock.port, process_name=pname)
    labels = {"baseline": "allowed" if match is not None else "none"}
    if match is not None:
        labels["baseline.id"] = match.id
        labels["baseline.allow_public"] = "true" if match.allow_public else "false"
        if match.process_name:
            labels["baseline.process"] = match.process_name
    else:
        any_proc = match_baseline(
            baselines, host=host, protocol=sock.protocol, port=sock.port, process_name=None
        )
        if any_proc is not None and any_proc.process_name:
            labels["baseline.process_mismatch"] = "true"
            labels["baseline.process"] = any_proc.process_name
    return labels


def _change_event(
    snap: Event,
    host: str,
    change: str,
    sock: ListeningSocket,
    baselines: Sequence[PortBaselineRow],
    *,
    initial: bool,
    previous_process: str | None = None,
) -> Event:
    labels = baseline_labels(baselines, host, sock)
    labels["port.change"] = change
    labels["derived_from"] = snap.id
    if initial:
        labels["port.initial"] = "true"
    if previous_process:
        labels["port.previous_process"] = previous_process
    pname = sock.process.name if sock.process else None
    msg = f"{sock.protocol} {sock.bind_ip}:{sock.port} {change}"
    if change == "process_changed":
        msg += f" ({previous_process or '?'} -> {pname or '?'})"
    elif pname:
        msg += f" ({pname})"
    return Event(
        timestamp=snap.timestamp,
        ingested_at=snap.ingested_at,
        kind=EventKind.PORT_CHANGE,
        dataset=CHANGE_DATASET,
        sensor_id=snap.sensor_id,
        host=HostInfo(
            name=host,
            ip=list(snap.host.ip) if snap.host else [],
            os=snap.host.os if snap.host else None,
        ),
        destination=Endpoint(ip=sock.bind_ip, port=sock.port),
        port=PortInfo(change=change, socket=sock),
        process=sock.process,
        message=msg,
        tags=["derived"],
        labels=labels,
    )


async def apply_snapshot(session: AsyncSession, snap: Event, *, learn_first: bool) -> list[Event]:
    """Update ``host_ports`` for one snapshot and return the derived PORT_CHANGE events."""
    assert snap.port is not None
    host = host_key(snap)
    rows = (await session.execute(select(HostPortRow).where(HostPortRow.host == host))).scalars().all()
    baselines = (
        (await session.execute(select(PortBaselineRow).where(PortBaselineRow.host.in_([host, "*"]))))
        .scalars()
        .all()
    )
    initial = not rows
    emit = not (initial and learn_first)
    current = _dedupe(snap.port.listeners)
    stored: dict[Key, HostPortRow] = {(r.protocol, r.bind_ip, r.port): r for r in rows}
    ts = snap.timestamp
    derived: list[Event] = []

    for key, sock in current.items():
        pname = ((sock.process.name or "")[:255] or None) if sock.process else None
        pid = sock.process.pid if sock.process else None
        row = stored.get(key)
        if row is None:
            session.add(
                HostPortRow(
                    id=new_id(),
                    host=host,
                    protocol=key[0],
                    bind_ip=key[1],
                    port=key[2],
                    pid=pid,
                    process_name=pname,
                    first_seen=ts,
                    last_seen=ts,
                    open=True,
                )
            )
            if emit:
                derived.append(_change_event(snap, host, "opened", sock, baselines, initial=initial))
            continue
        if not row.open:
            row.open = True
            row.pid, row.process_name = pid, pname
            row.last_seen = ts
            derived.append(_change_event(snap, host, "opened", sock, baselines, initial=False))
            continue
        previous = row.process_name
        if pname and previous and pname != previous:
            derived.append(
                _change_event(
                    snap, host, "process_changed", sock, baselines, initial=False, previous_process=previous
                )
            )
        # An unprivileged agent may not see the owner: keep the last known process rather than erase it.
        if pname:
            row.process_name = pname
            row.pid = pid
        row.last_seen = ts

    for key, row in stored.items():
        if row.open and key not in current:
            row.open = False
            row.last_seen = ts
            sock = ListeningSocket(protocol=row.protocol, bind_ip=row.bind_ip, port=row.port)
            if row.process_name or row.pid:
                sock.process = ProcessInfo(pid=row.pid, name=row.process_name)
            derived.append(_change_event(snap, host, "closed", sock, baselines, initial=False))
    await session.flush()
    return derived


@register_enricher
class PortsEnricher(Enricher):
    id: ClassVar[str] = "ports"
    order: ClassVar[int] = 20

    def __init__(self) -> None:
        # Snapshots of one host arriving in concurrent requests must not interleave their read-modify-write.
        self._lock = asyncio.Lock()

    async def enrich(self, events: list[Event]) -> None:
        if not any(e.kind == EventKind.PORT_SNAPSHOT and e.port is not None for e in events):
            return
        learn_first = get_settings().agent.ports_first_snapshot == "learn"
        out: list[Event] = []
        async with self._lock, session_scope() as session:
            for e in events:
                out.append(e)
                if e.kind != EventKind.PORT_SNAPSHOT or e.port is None:
                    continue
                try:
                    out.extend(await apply_snapshot(session, e, learn_first=learn_first))
                except Exception:
                    log.exception("ports enricher failed for snapshot %s", e.id)
        events[:] = out
