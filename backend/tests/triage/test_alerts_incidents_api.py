"""Alerts / incidents REST API (docs/api-contract.md): filters, detail, PATCH + audit, roles, forced triage."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from sqlalchemy import select

from tokiwa.auth.security import create_access_token, hash_password
from tokiwa.bus import bus
from tokiwa.db.models.core import AuditRow, UserRow
from tokiwa.db.models.response import ResponseActionRow
from tokiwa.db.session import session_scope
from tokiwa.llm.mock import MockProvider
from tokiwa.util import new_id, utcnow

AddAlert = Callable[..., Awaitable[Any]]


async def _viewer_headers() -> dict[str, str]:
    row = UserRow(
        id=new_id(), username="viewer1", password_hash=hash_password("viewer-password"), role="viewer"
    )
    async with session_scope() as s:
        s.add(row)
    token, _ = create_access_token(row.id, row.username, row.role)
    return {"Authorization": f"Bearer {token}"}


async def _audit_actions() -> list[str]:
    async with session_scope() as s:
        return [r.action for r in (await s.execute(select(AuditRow).order_by(AuditRow.created_at))).scalars()]


async def test_list_and_filter_alerts(
    client: httpx.AsyncClient, admin_headers: dict[str, str], add_alert: AddAlert
) -> None:
    await add_alert(
        severity="high",
        category="exploit_attempt",
        source_ip="203.0.113.1",
        ai_score=0.9,
        title="SQLi on /login",
    )
    await add_alert(
        severity="low",
        category="recon",
        source_ip="203.0.113.2",
        rule_id="web.sensitive_file_probe",
        title="probe /.env",
    )
    await add_alert(
        severity="critical",
        category="ai_agent",
        source_ip="203.0.113.3",
        status="resolved",
        rule_id="ai.agent_session",
    )

    async def get(params: dict[str, Any]) -> dict[str, Any]:
        r = await client.get("/api/v1/alerts", params=params, headers=admin_headers)
        assert r.status_code == 200, r.text
        return r.json()

    assert (await get({}))["total"] == 3
    assert (await get({"severity": "high,critical"}))["total"] == 2
    assert (await get({"status": "new"}))["total"] == 2
    assert (await get({"category": "recon"}))["items"][0]["source_ip"] == "203.0.113.2"
    assert (await get({"source_ip": "203.0.113.1"}))["total"] == 1
    assert (await get({"min_ai_score": 0.5}))["total"] == 1
    assert (await get({"q": ".env"}))["total"] == 1
    assert (await get({"q": "100%"}))["total"] == 0  # LIKE wildcards are escaped
    page = await get({"limit": 2, "offset": 2})
    assert page["limit"] == 2 and page["offset"] == 2 and len(page["items"]) == 1
    bad = await client.get("/api/v1/alerts", params={"severity": "urgent"}, headers=admin_headers)
    assert bad.status_code == 422
    assert (await client.get("/api/v1/alerts")).status_code == 401


async def test_alert_detail_patch_and_audit(
    client: httpx.AsyncClient, admin_headers: dict[str, str], add_alert: AddAlert, add_events, make_http_event
) -> None:
    ev = make_http_event("/x")
    await add_events(ev)
    a = await add_alert(evidence=[ev.id, "missing-id"])
    r = await client.get(f"/api/v1/alerts/{a.id}", headers=admin_headers)
    assert r.status_code == 200
    detail = r.json()
    assert [e["id"] for e in detail["evidence"]] == [ev.id]
    assert (await client.get("/api/v1/alerts/nope", headers=admin_headers)).status_code == 404

    seen: list[Any] = []

    async def on_update(alert: Any) -> None:
        seen.append(alert)

    bus.subscribe("alert.updated", on_update)
    r = await client.patch(
        f"/api/v1/alerts/{a.id}",
        json={"status": "acknowledged", "tags": ["keep", " keep ", ""]},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "acknowledged" and r.json()["tags"] == ["keep"]
    await bus.drain()
    assert seen and seen[0].status == "acknowledged"
    assert "alert.update" in await _audit_actions()

    viewer = await _viewer_headers()
    assert (await client.get(f"/api/v1/alerts/{a.id}", headers=viewer)).status_code == 200
    assert (
        await client.patch(f"/api/v1/alerts/{a.id}", json={"status": "resolved"}, headers=viewer)
    ).status_code == 403
    assert (await client.post(f"/api/v1/alerts/{a.id}/triage", headers=viewer)).status_code == 403


async def test_force_triage_alert(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    add_alert: AddAlert,
    add_events,
    make_http_event,
    mock_llm: MockProvider,
) -> None:
    ev = make_http_event("/x")
    await add_events(ev)
    a = await add_alert(severity="low", evidence=[ev.id])  # below min_severity_for_llm, but forced
    r = await client.post(f"/api/v1/alerts/{a.id}/triage", params={"tier": "deep"}, headers=admin_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "triaged"
    assert body["triage"]["tier"] == "deep" and body["triage"]["model"] == "claude-opus-5-5"
    assert [c["model"] for c in mock_llm.calls] == ["claude-opus-5-5"]
    assert "alert.triage" in await _audit_actions()
    assert (await client.post("/api/v1/alerts/nope/triage", headers=admin_headers)).status_code == 404
    bad = await client.post(f"/api/v1/alerts/{a.id}/triage", params={"tier": "huge"}, headers=admin_headers)
    assert bad.status_code == 422


async def test_incidents_api(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    add_alert: AddAlert,
    add_events,
    make_http_event,
    mock_llm: MockProvider,
) -> None:
    from tokiwa.correlate.service import correlate_alert

    ev = make_http_event("/x", ip="203.0.113.50")
    await add_events(ev)
    a = await add_alert(source_ip="203.0.113.50", evidence=[ev.id], severity="medium", ai_score=0.95)
    b = await add_alert(source_ip="198.51.100.9", severity="low", rule_id="web.rare_method")
    inc = await correlate_alert(a.id)
    other = await correlate_alert(b.id)
    assert inc is not None and other is not None
    async with session_scope() as s:
        now = utcnow()
        s.add(
            ResponseActionRow(
                id=new_id(),
                created_at=now,
                updated_at=now,
                action_type="deceive",
                target="203.0.113.50",
                reason="test",
                proposed_by="llm",
                incident_id=inc.id,
                status="proposed",
            )
        )
    await bus.drain()

    page = (await client.get("/api/v1/incidents", headers=admin_headers)).json()
    assert page["total"] == 2
    ai_only = (
        await client.get("/api/v1/incidents", params={"actor_type": "ai_agent"}, headers=admin_headers)
    ).json()
    assert [i["id"] for i in ai_only["items"]] == [inc.id]
    assert (await client.get("/api/v1/incidents", params={"severity": "low"}, headers=admin_headers)).json()[
        "total"
    ] == 1
    assert (
        await client.get("/api/v1/incidents", params={"status": "bogus"}, headers=admin_headers)
    ).status_code == 422

    detail = (await client.get(f"/api/v1/incidents/{inc.id}", headers=admin_headers)).json()
    assert [x["id"] for x in detail["alerts"]] == [a.id]
    assert detail["actions"][0]["action_type"] == "deceive" and detail["actions"][0]["status"] == "proposed"
    assert (await client.get("/api/v1/incidents/nope", headers=admin_headers)).status_code == 404

    r = await client.patch(
        f"/api/v1/incidents/{inc.id}",
        json={"status": "investigating", "assignee": "alice", "tags": ["ai_agent", "case-42"]},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "investigating" and r.json()["assignee"] == "alice"
    r = await client.patch(f"/api/v1/incidents/{inc.id}", json={"assignee": None}, headers=admin_headers)
    assert r.json()["assignee"] is None
    assert (await _audit_actions()).count("incident.update") == 2

    r = await client.post(f"/api/v1/incidents/{inc.id}/triage", headers=admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["triage"]["prompt_version"] == "triage.incident@1"
    assert r.json()["status"] == "investigating"  # triage never changes the analyst-owned status
    assert "incident.triage" in await _audit_actions()
    viewer = await _viewer_headers()
    assert (
        await client.patch(f"/api/v1/incidents/{inc.id}", json={"status": "resolved"}, headers=viewer)
    ).status_code == 403
