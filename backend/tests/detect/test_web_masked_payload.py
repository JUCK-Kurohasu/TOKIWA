"""ADR-0007 C (server side): ``web.masked_payload`` honours the Gate's label only from gate-scoped senders."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from sqlalchemy import select

from tokiwa.api.routes import ingest
from tokiwa.cli import _create_token
from tokiwa.db.models.detection import AlertRow
from tokiwa.db.session import session_scope
from tokiwa.detect.detectors import web_masked_payload


def _gate_event(label: str) -> dict[str, Any]:
    return {
        "kind": "http",
        "dataset": "gate.http",
        "source": {"ip": "203.0.113.70"},
        "http": {"method": "GET", "path": "/search", "query": "q=token:[REDACTED:secret]", "status": 200},
        "labels": {"gate.hidden_signals": label},
    }


async def _alerts() -> list[AlertRow]:
    async with session_scope() as s:
        return list(
            (await s.execute(select(AlertRow).where(AlertRow.rule_id == "web.masked_payload"))).scalars()
        )


def test_trust_label_constants_match_ingest() -> None:
    assert web_masked_payload.TRUST_LABEL == ingest.LABEL_TRUST
    assert web_masked_payload.TRUST_LOW == ingest.TRUST_LOW


async def test_gate_scoped_sender_raises_medium(
    client: httpx.AsyncClient, ingest_headers: dict[str, str]
) -> None:
    r = await client.post(
        "/api/v1/ingest/events", json={"events": [_gate_event("sqli@query")]}, headers=ingest_headers
    )
    assert r.status_code == 200, r.text
    (alert,) = await _alerts()
    assert alert.severity == "medium"
    assert "sqli" in alert.tags and alert.details["hidden_signals"] == ["sqli@query"]


@pytest.mark.usefixtures("admin_headers")
async def test_ingest_only_token_cannot_forge_it(client: httpx.AsyncClient) -> None:
    token = await _create_token("not-a-gate", ["ingest"])
    r = await client.post(
        "/api/v1/ingest/events",
        json={"events": [_gate_event("sqli@query,cmdi@header:cookie")]},
        headers={"X-Tokiwa-Token": token},
    )
    assert r.status_code == 200
    assert await _alerts() == []
