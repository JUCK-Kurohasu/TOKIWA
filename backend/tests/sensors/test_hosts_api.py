"""/api/v1/hosts: summaries, port listing with ``allowed``, baseline CRUD and learn."""

from __future__ import annotations

from typing import Any

import httpx

from tokiwa.schemas.events import Event, EventKind, HostInfo, ListeningSocket, PortInfo, ProcessInfo


def _snapshot(host: str, listeners: list[tuple[str, str, int, str | None]]) -> dict[str, Any]:
    return Event(
        kind=EventKind.PORT_SNAPSHOT,
        dataset="host.ports",
        host=HostInfo(name=host),
        port=PortInfo(
            listeners=[
                ListeningSocket(
                    protocol=p, bind_ip=b, port=n, process=ProcessInfo(pid=n, name=name) if name else None
                )
                for p, b, n, name in listeners
            ]
        ),
    ).model_dump(mode="json")


LISTENERS = [
    ("tcp", "0.0.0.0", 22, "sshd"),
    ("tcp", "0.0.0.0", 80, "nginx"),
    ("tcp6", "::", 80, "nginx"),
    ("tcp", "127.0.0.1", 6379, "redis-server"),
    ("udp", "0.0.0.0", 53, None),
]


async def _seed(client: httpx.AsyncClient, ingest_headers: dict[str, str]) -> None:
    r = await client.post(
        "/api/v1/ingest/events",
        json={
            "events": [
                _snapshot("web-1", LISTENERS),
                _snapshot("db-1", [("tcp", "10.0.0.6", 5432, "postgres")]),
            ]
        },
        headers=ingest_headers,
    )
    assert r.status_code == 200, r.text


async def test_requires_auth(client: httpx.AsyncClient) -> None:
    assert (await client.get("/api/v1/hosts")).status_code == 401
    assert (await client.post("/api/v1/hosts/baselines", json={"port": 22})).status_code == 401


async def test_hosts_ports_baselines_learn(
    client: httpx.AsyncClient, ingest_headers: dict[str, str], admin_headers: dict[str, str]
) -> None:
    await _seed(client, ingest_headers)
    h = admin_headers

    hosts = (await client.get("/api/v1/hosts", headers=h)).json()
    assert [x["host"] for x in hosts] == ["db-1", "web-1"]
    web = hosts[1]
    assert web["ports_open"] == 5 and web["deviations"] == 5 and web["last_seen"]

    # global baseline for ssh
    r = await client.post(
        "/api/v1/hosts/baselines", json={"protocol": "TCP6", "port": 22, "allow_public": True}, headers=h
    )
    assert r.status_code == 200, r.text
    ssh = r.json()
    assert ssh["host"] == "*" and ssh["protocol"] == "tcp" and ssh["process_name"] is None
    # idempotent upsert
    again = await client.post(
        "/api/v1/hosts/baselines",
        json={"protocol": "tcp", "port": 22, "allow_public": True, "note": "ops"},
        headers=h,
    )
    assert again.json()["id"] == ssh["id"] and again.json()["note"] == "ops"
    bad = await client.post("/api/v1/hosts/baselines", json={"protocol": "icmp", "port": 1}, headers=h)
    assert bad.status_code == 422

    ports = (await client.get("/api/v1/hosts/ports", params={"host": "web-1"}, headers=h)).json()
    assert len(ports) == 5
    allowed = {(p["protocol"], p["port"]): p["allowed"] for p in ports}
    assert allowed[("tcp", 22)] is True and allowed[("tcp", 80)] is False
    first = ports[0]
    for field in (
        "host",
        "protocol",
        "bind_ip",
        "port",
        "pid",
        "process_name",
        "first_seen",
        "last_seen",
        "open",
    ):
        assert field in first
    assert (await client.get("/api/v1/hosts", headers=h)).json()[1]["deviations"] == 4

    learned = await client.post("/api/v1/hosts/baselines/learn", json={"host": "web-1"}, headers=h)
    assert learned.status_code == 200, learned.text
    entries = {(b["protocol"], b["port"]): b for b in learned.json()}
    # ssh already allowed; tcp/80 (0.0.0.0 + ::) collapses into one public entry
    assert set(entries) == {("tcp", 80), ("tcp", 6379), ("udp", 53)}
    assert entries[("tcp", 80)]["allow_public"] is True and entries[("tcp", 80)]["process_name"] == "nginx"
    assert entries[("tcp", 6379)]["allow_public"] is False
    assert all(b["host"] == "web-1" for b in entries.values())
    assert (await client.get("/api/v1/hosts", headers=h)).json()[1]["deviations"] == 0
    # learning twice creates nothing new
    assert (
        await client.post("/api/v1/hosts/baselines/learn", json={"host": "web-1"}, headers=h)
    ).json() == []
    missing = await client.post("/api/v1/hosts/baselines/learn", json={"host": "nope"}, headers=h)
    assert missing.status_code == 404

    listed = (await client.get("/api/v1/hosts/baselines", headers=h)).json()
    assert len(listed) == 4
    only_db = (await client.get("/api/v1/hosts/baselines", params={"host": "db-1"}, headers=h)).json()
    assert [b["port"] for b in only_db] == [22]  # the "*" entry applies to every host

    d = await client.delete(f"/api/v1/hosts/baselines/{ssh['id']}", headers=h)
    assert d.status_code == 204
    assert (await client.delete(f"/api/v1/hosts/baselines/{ssh['id']}", headers=h)).status_code == 404
    assert (await client.get("/api/v1/hosts", headers=h)).json()[1]["deviations"] == 1

    closed_filter = (await client.get("/api/v1/hosts/ports", params={"open": "false"}, headers=h)).json()
    assert closed_filter == []
