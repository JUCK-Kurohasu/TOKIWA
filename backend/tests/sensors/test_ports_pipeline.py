"""Ports enricher + port detectors through the real ingest API (P1 acceptance criteria)."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from tokiwa.config import reset_settings_cache
from tokiwa.db.models.detection import AlertRow
from tokiwa.db.models.telemetry import EventRow, HostPortRow
from tokiwa.db.session import session_scope
from tokiwa.schemas.events import Event, EventKind, HostInfo, ListeningSocket, PortInfo, ProcessInfo
from tokiwa.util import utcnow

Listener = tuple[str, str, int, str | None]  # protocol, bind_ip, port, process name
BASE: list[Listener] = [("tcp", "0.0.0.0", 22, "sshd"), ("tcp", "127.0.0.1", 5432, "postgres")]


def snapshot(host: str, listeners: Sequence[Listener], *, minutes: int = 0) -> dict[str, Any]:
    socks = [
        ListeningSocket(
            protocol=proto,
            bind_ip=bind,
            port=port,
            process=ProcessInfo(pid=1000 + port, name=name) if name else None,
        )
        for proto, bind, port, name in listeners
    ]
    ev = Event(
        timestamp=utcnow() + timedelta(minutes=minutes),
        kind=EventKind.PORT_SNAPSHOT,
        dataset="host.ports",
        sensor_id="agent-web-1",
        host=HostInfo(name=host, ip=["10.0.0.5"]),
        port=PortInfo(listeners=socks),
    )
    return ev.model_dump(mode="json")


async def ingest(
    client: httpx.AsyncClient, headers: dict[str, str], *events: dict[str, Any]
) -> dict[str, Any]:
    r = await client.post("/api/v1/ingest/events", json={"events": list(events)}, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


async def alerts(rule_id: str | None = None) -> list[AlertRow]:
    async with session_scope() as s:
        q = select(AlertRow)
        if rule_id:
            q = q.where(AlertRow.rule_id == rule_id)
        return list((await s.execute(q)).scalars().all())


async def port_changes() -> list[dict[str, Any]]:
    async with session_scope() as s:
        rows = (await s.execute(select(EventRow).where(EventRow.kind == "port_change"))).scalars().all()
        return [r.data for r in rows]


async def test_new_listener_on_second_snapshot_alerts(
    client: httpx.AsyncClient, ingest_headers: dict[str, str]
) -> None:
    first = await ingest(client, ingest_headers, snapshot("web-1", BASE))
    # default "info": first snapshot emits initial PORT_CHANGE and info-level alerts
    assert first["accepted"] == 3  # snapshot + 2 derived PORT_CHANGE events
    initial = await alerts("port.unexpected_listener")
    assert {a.severity for a in initial} == {"info"}
    assert all("initial" in a.tags for a in initial)

    second = await ingest(
        client, ingest_headers, snapshot("web-1", [*BASE, ("tcp", "0.0.0.0", 4444, "nc")], minutes=1)
    )
    assert second["accepted"] == 2 and second["alerts"] == 1
    hits = [a for a in await alerts("port.unexpected_listener") if a.entities.get("port") == "4444"]
    assert len(hits) == 1
    a = hits[0]
    assert a.severity == "high" and a.category == "port_deviation"
    assert a.entities["host"] == "web-1" and a.entities["process"] == "nc"
    assert a.id in second["alert_ids"]
    # the derived PORT_CHANGE event was stored and is the alert's evidence
    changes = [c for c in await port_changes() if c["port"]["socket"]["port"] == 4444]
    assert len(changes) == 1 and changes[0]["labels"]["baseline"] == "none"
    assert a.evidence_event_ids == [changes[0]["id"]]
    async with session_scope() as s:
        row = (await s.execute(select(HostPortRow).where(HostPortRow.port == 4444))).scalar_one()
        assert row.open and row.host == "web-1" and row.process_name == "nc"


async def test_baselined_listener_does_not_alert(
    client: httpx.AsyncClient, ingest_headers: dict[str, str], admin_headers: dict[str, str]
) -> None:
    r = await client.post(
        "/api/v1/hosts/baselines",
        json={"host": "web-1", "protocol": "tcp", "port": 4444, "allow_public": True},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    await ingest(client, ingest_headers, snapshot("web-1", BASE))
    second = await ingest(
        client, ingest_headers, snapshot("web-1", [*BASE, ("tcp", "0.0.0.0", 4444, "nc")], minutes=1)
    )
    assert second["alerts"] == 0
    assert not [a for a in await alerts("port.unexpected_listener") if a.entities.get("port") == "4444"]
    assert not await alerts("port.public_exposure")


async def test_learn_mode_first_snapshot_is_silent(
    client: httpx.AsyncClient, ingest_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TOKIWA_AGENT__PORTS_FIRST_SNAPSHOT", "learn")
    reset_settings_cache()
    first = await ingest(client, ingest_headers, snapshot("db-1", BASE))
    assert first["accepted"] == 1 and first["alerts"] == 0
    second = await ingest(
        client, ingest_headers, snapshot("db-1", [*BASE, ("tcp", "0.0.0.0", 8080, "java")], minutes=1)
    )
    assert second["alerts"] == 1


async def test_public_exposure_process_change_and_close(
    client: httpx.AsyncClient, ingest_headers: dict[str, str], admin_headers: dict[str, str]
) -> None:
    for body in (
        {"protocol": "tcp", "port": 5432, "allow_public": False},  # host "*" (all hosts)
        {"host": "web-1", "protocol": "tcp", "port": 22, "process_name": "sshd", "allow_public": True},
    ):
        r = await client.post("/api/v1/hosts/baselines", json=body, headers=admin_headers)
        assert r.status_code == 200, r.text
    await ingest(client, ingest_headers, snapshot("web-1", BASE))
    assert not await alerts()  # everything baselined: no alerts even on the first snapshot

    # postgres re-binds to all interfaces, sshd replaced by an unexpected binary
    changed = [("tcp", "0.0.0.0", 22, "dropbear"), ("tcp", "0.0.0.0", 5432, "postgres")]
    await ingest(client, ingest_headers, snapshot("web-1", changed, minutes=1))
    exposure = await alerts("port.public_exposure")
    assert len(exposure) == 1 and exposure[0].severity == "high" and exposure[0].entities["port"] == "5432"
    proc = await alerts("port.process_changed")
    assert len(proc) == 1 and proc[0].severity == "high"  # baseline expects sshd
    assert proc[0].entities["previous_process"] == "sshd" and proc[0].entities["process"] == "dropbear"
    # 127.0.0.1:5432 disappeared -> closed change recorded, no alert for closing
    changes = await port_changes()
    closed = [c for c in changes if c["port"]["change"] == "closed"]
    assert len(closed) == 1 and closed[0]["port"]["socket"]["bind_ip"] == "127.0.0.1"
    async with session_scope() as s:
        row = (
            await s.execute(
                select(HostPortRow).where(HostPortRow.port == 5432, HostPortRow.bind_ip == "127.0.0.1")
            )
        ).scalar_one()
        assert row.open is False

    # reopening the closed listener is an "opened" change again (baselined -> no unexpected alert)
    await ingest(
        client,
        ingest_headers,
        snapshot("web-1", [*changed, ("tcp", "127.0.0.1", 5432, "postgres")], minutes=2),
    )
    reopened = [
        c
        for c in await port_changes()
        if c["port"]["change"] == "opened" and c["labels"].get("port.initial") is None
    ]
    assert any(c["port"]["socket"]["bind_ip"] == "127.0.0.1" for c in reopened)
    assert not await alerts("port.unexpected_listener")


async def test_unknown_owner_keeps_last_known_process(
    client: httpx.AsyncClient, ingest_headers: dict[str, str]
) -> None:
    await ingest(client, ingest_headers, snapshot("web-2", [("tcp", "0.0.0.0", 80, "nginx")]))
    # an unprivileged agent restart cannot see the owner: not a process change
    await ingest(client, ingest_headers, snapshot("web-2", [("tcp", "0.0.0.0", 80, None)], minutes=1))
    assert not await alerts("port.process_changed")
    async with session_scope() as s:
        row = (await s.execute(select(HostPortRow).where(HostPortRow.host == "web-2"))).scalar_one()
        assert row.process_name == "nginx"
