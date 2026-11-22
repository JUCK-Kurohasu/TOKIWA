"""Ingest provenance and token binding (audit #40, repro docs/audit/2026-11/repro/L07/scripts/frame.py).

The repro: an ingest-only token sends ``gate.http`` events claiming ``sensor_id=gate-prod-1`` and an innocent
``source.ip`` hitting decoy paths -> critical incident + block_ip proposal against the victim. These tests pin
what the server does about it now:

- every stored event names the delivering token (server-owned ``ingest.*`` labels, client values dropped);
- a token bound with ``allowed_datasets`` / ``allowed_sensor_ids`` cannot send gate telemetry or claim another
  sensor's id (batch refused / sensor_id forced);
- gate-only telemetry from a token without the ``gate`` scope is marked ``ingest.trust=low``.
"""

from __future__ import annotations

from typing import Any

import httpx

from tokiwa.cli import _create_token

VICTIM = "198.51.100.23"
UA = "python-requests/2.31.0"
FRAME_PATHS = ["/.env", "/backup.sql", "/.git/config", "/api/users", "/etc/passwd", "/../../etc/passwd"]


def _frame_events(dataset: str = "gate.http", sensor_id: str = "gate-prod-1") -> list[dict[str, Any]]:
    return [
        {
            "kind": "http",
            "dataset": dataset,
            "sensor_id": sensor_id,
            "source": {"ip": VICTIM, "port": 40000 + i},
            "destination": {"ip": "10.0.0.5", "port": 443},
            "http": {
                "method": "GET",
                "path": p,
                "user_agent": UA,
                "status": 404,
                "headers": {"user-agent": UA},
            },
            # a forger pre-seeding the server-owned labels must not survive ingest
            "labels": {"ingest.token": "gate-prod-1", "ingest.trust": "high", "app": "kept"},
        }
        for i, p in enumerate(FRAME_PATHS)
    ]


async def _stored(client: httpx.AsyncClient, headers: dict[str, str]) -> list[dict[str, Any]]:
    r = await client.get("/api/v1/events", params={"source_ip": VICTIM, "limit": 100}, headers=headers)
    assert r.status_code == 200, r.text
    items: list[dict[str, Any]] = r.json()["items"]
    return items


async def test_every_event_records_the_delivering_token(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    token = await _create_token("host-agent-1", ["ingest"])
    r = await client.post(
        "/api/v1/ingest/events", json={"events": _frame_events()}, headers={"X-Tokiwa-Token": token}
    )
    assert r.status_code == 200, r.text
    tokens = (await client.get("/api/v1/tokens", headers=admin_headers)).json()
    token_id = next(t["id"] for t in tokens if t["name"] == "host-agent-1")

    stored = await _stored(client, admin_headers)
    assert len(stored) == len(FRAME_PATHS)
    # read back the persisted document, not the in-memory batch
    one = (await client.get(f"/api/v1/events/{stored[0]['id']}", headers=admin_headers)).json()
    for ev in [*stored, one]:
        labels = ev["labels"]
        assert labels["ingest.token_id"] == token_id
        assert labels["ingest.token"] == "host-agent-1"  # the forged value is gone
        assert labels["ingest.trust"] == "low"  # gate.http from a token without the gate scope
        assert labels["app"] == "kept"
        # unbound token: the claimed sensor id is kept (backwards compatible), provenance says who sent it
        assert ev["sensor_id"] == "gate-prod-1"


async def test_gate_scoped_token_is_not_marked_low_trust(
    client: httpx.AsyncClient, admin_headers: dict[str, str], ingest_headers: dict[str, str]
) -> None:
    r = await client.post(
        "/api/v1/ingest/events", json={"events": _frame_events()[:1]}, headers=ingest_headers
    )
    assert r.status_code == 200, r.text
    labels = (await _stored(client, admin_headers))[0]["labels"]
    assert labels["ingest.token"] == "test-sensor"
    assert "ingest.trust" not in labels  # the forged "high" was dropped, nothing re-added


async def test_bound_token_cannot_send_gate_telemetry(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    token = await _create_token(
        "agent-web01", ["ingest"], allowed_sensor_ids=["web01"], allowed_datasets=["nginx.access", "host.*"]
    )
    r = await client.post(
        "/api/v1/ingest/events", json={"events": _frame_events()}, headers={"X-Tokiwa-Token": token}
    )
    assert r.status_code == 403 and "gate.http" in r.json()["detail"]
    assert await _stored(client, admin_headers) == []  # nothing of the batch was stored
    alerts = (await client.get("/api/v1/alerts", params={"limit": 100}, headers=admin_headers)).json()
    assert VICTIM not in str(alerts)

    # an allowed dataset is accepted, but the token cannot pose as another sensor
    r = await client.post(
        "/api/v1/ingest/events",
        json={"events": _frame_events(dataset="nginx.access")},
        headers={"X-Tokiwa-Token": token},
    )
    assert r.status_code == 200, r.text
    stored = await _stored(client, admin_headers)
    assert {e["sensor_id"] for e in stored} == {"web01"}
    assert {e["labels"]["ingest.claimed_sensor_id"] for e in stored} == {"gate-prod-1"}
    assert all("ingest.trust" not in e["labels"] for e in stored)


async def test_bound_sensor_id_in_list_is_kept_and_missing_one_is_filled(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    token = await _create_token("pair", ["ingest"], allowed_sensor_ids=["web01", "web02"])
    events = _frame_events(dataset="nginx.access", sensor_id="web02")[:2]
    events[1].pop("sensor_id")
    r = await client.post("/api/v1/ingest/events", json={"events": events}, headers={"X-Tokiwa-Token": token})
    assert r.status_code == 200, r.text
    stored = sorted(await _stored(client, admin_headers), key=lambda e: e["http"]["path"])
    by_path = {e["http"]["path"]: e for e in stored}
    assert by_path[FRAME_PATHS[0]]["sensor_id"] == "web02"
    assert by_path[FRAME_PATHS[1]]["sensor_id"] == "web01"  # missing -> first allowed id
    assert all("ingest.claimed_sensor_id" not in e["labels"] for e in stored)


async def test_token_binding_via_api_and_validation(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.post(
        "/api/v1/tokens",
        json={
            "name": "bound",
            "scopes": ["ingest"],
            "allowed_sensor_ids": ["web01", "web01"],
            "allowed_datasets": ["nginx.*"],
        },
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["allowed_sensor_ids"] == ["web01"] and body["allowed_datasets"] == ["nginx.*"]
    # [] would mean "deny everything" -> refused; null/omitted = unrestricted
    for field in ("allowed_sensor_ids", "allowed_datasets"):
        bad = await client.post(
            "/api/v1/tokens", json={"name": "x", "scopes": ["ingest"], field: []}, headers=admin_headers
        )
        assert bad.status_code == 422, field
    bad = await client.post(
        "/api/v1/tokens",
        json={"name": "x", "scopes": ["ingest"], "allowed_datasets": ["gate http; drop"]},
        headers=admin_headers,
    )
    assert bad.status_code == 422
    unbound = await client.post(
        "/api/v1/tokens", json={"name": "u", "scopes": ["ingest"]}, headers=admin_headers
    )
    assert unbound.json()["allowed_datasets"] is None and unbound.json()["allowed_sensor_ids"] is None
