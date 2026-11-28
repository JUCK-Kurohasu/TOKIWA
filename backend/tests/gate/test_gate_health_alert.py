"""Audit #55 (server side): the Gate's drop report raises ``sensor.events_dropped`` and is accepted by bound tokens."""

from __future__ import annotations

from typing import Any

import httpx
from sqlalchemy import select

from tokiwa.cli import _create_token
from tokiwa.db.models.detection import AlertRow
from tokiwa.db.session import session_scope


def _report(dropped: int, notable_total: int) -> dict[str, Any]:
    return {
        "kind": "custom",
        "dataset": "gate.health",
        "sensor_id": "edge-gate",
        "message": f"Gate shipper lost {dropped} event(s)",
        "labels": {"health.dropped": str(dropped), "health.dropped_notable_total": str(notable_total)},
    }


async def _alerts() -> list[AlertRow]:
    async with session_scope() as s:
        return list(
            (await s.execute(select(AlertRow).where(AlertRow.rule_id == "sensor.events_dropped"))).scalars()
        )


async def test_drop_report_raises_sensor_alert(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    # A token bound to gate.http still gets the report through (refusing it would stall the Gate's shipper).
    token = await _create_token("edge-gate", ["ingest", "gate"], allowed_datasets=["gate.http"])
    headers = {"X-Tokiwa-Token": token}
    r = await client.post("/api/v1/ingest/events", json={"events": [_report(120, 0)]}, headers=headers)
    assert r.status_code == 200, r.text
    (alert,) = await _alerts()
    assert alert.severity == "medium"
    assert alert.source_ip is None  # about the sensor: nothing may be proposed against an address

    r = await client.post("/api/v1/ingest/events", json={"events": [_report(5, 3)]}, headers=headers)
    assert r.status_code == 200
    (alert,) = await _alerts()  # same sensor: one alert, escalated
    assert alert.severity == "high"


async def test_report_without_drops_is_quiet(
    client: httpx.AsyncClient, ingest_headers: dict[str, str]
) -> None:
    r = await client.post("/api/v1/ingest/events", json={"events": [_report(0, 0)]}, headers=ingest_headers)
    assert r.status_code == 200
    assert await _alerts() == []
