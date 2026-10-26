"""Rules / detectors API: CRUD, validation, approval, immediate effect on detection, persistence of overrides."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
from sqlalchemy import select

from tokiwa.api.routes.detectors import OVERRIDES_KEY, restore_detector_overrides
from tokiwa.auth.security import create_access_token, hash_password
from tokiwa.db.models.core import AuditRow, SettingRow, UserRow
from tokiwa.db.models.detection import AlertRow, RuleRow
from tokiwa.db.session import session_scope
from tokiwa.detect.engine import get_detection_engine, reset_detection_engine
from tokiwa.detect.sigma import get_rule_store
from tokiwa.detect.sigma.loader import _sigma_startup
from tokiwa.schemas.events import Event
from tokiwa.util import new_id, utcnow

MakeEvent = Callable[..., Event]
SCANNER_RULE = "004869cf-0236-45b7-875f-9f40dab81dca"  # rules/sigma/web/web_scanner_useragent.yml

USER_RULE = """
title: Lab marker path
id: 9a3e0c5e-1111-4222-8333-944455566677
status: test
level: high
description: test rule created through the API
tags: [attack.initial_access, attack.t1190]
falsepositives: [none]
logsource:
  category: webserver
  product: tokiwa
detection:
  selection:
    cs-uri-stem|startswith: /__sigma_api_marker
  condition: selection
"""
USER_RULE_KEY = "9a3e0c5e-1111-4222-8333-944455566677"


async def ingest(client: httpx.AsyncClient, headers: dict[str, str], *events: Event) -> dict[str, Any]:
    r = await client.post(
        "/api/v1/ingest/events", json={"events": [e.model_dump(mode="json") for e in events]}, headers=headers
    )
    assert r.status_code == 200, r.text
    return dict(r.json())


async def hits(rule_key: str) -> int:
    async with session_scope() as s:
        rows = (
            (await s.execute(select(AlertRow).where(AlertRow.rule_id == f"sigma:{rule_key}"))).scalars().all()
        )
        return sum(r.count for r in rows)


async def audit_actions() -> list[str]:
    async with session_scope() as s:
        return [r.action for r in (await s.execute(select(AuditRow))).scalars().all()]


async def viewer_headers() -> dict[str, str]:
    async with session_scope() as s:
        row = UserRow(
            id=new_id(),
            username="viewer1",
            password_hash=hash_password("x" * 12),
            role="viewer",
            created_at=utcnow(),
        )
        s.add(row)
    token, _ = create_access_token(row.id, row.username, row.role)
    return {"Authorization": f"Bearer {token}"}


async def test_builtin_rules_are_synced_and_listed(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.get("/api/v1/rules", params={"source": "builtin", "limit": 500}, headers=admin_headers)
    assert r.status_code == 200, r.text
    page = r.json()
    assert page["total"] >= 15
    by_key = {it["meta"]["rule_key"]: it for it in page["items"]}
    scanner = by_key[SCANNER_RULE]
    assert scanner["status"] == "active" and scanner["source"] == "builtin"
    assert scanner["meta"]["mitre"] == ["T1595.002"] and scanner["meta"]["level"] == "medium"
    assert scanner["meta"]["path"] == "web/web_scanner_useragent.yml"
    store = get_rule_store()
    assert store.db_loaded and len(store.rules()) == page["total"]
    assert all(lr.db_id for lr in store.rules())
    # paging + filters
    r2 = await client.get(
        "/api/v1/rules", params={"limit": 2, "offset": 1, "q": "SQL"}, headers=admin_headers
    )
    assert r2.json()["limit"] == 2 and r2.json()["total"] >= 2


async def test_validate_endpoint(client: httpx.AsyncClient, admin_headers: dict[str, str]) -> None:
    ok = await client.post("/api/v1/rules/validate", json={"content": USER_RULE}, headers=admin_headers)
    assert ok.json() == {"valid": True, "errors": [], "title": "Lab marker path"}
    bad = await client.post(
        "/api/v1/rules/validate",
        json={"content": USER_RULE.replace("startswith", "beginswith")},
        headers=admin_headers,
    )
    body = bad.json()
    assert body["valid"] is False and body["title"] == "Lab marker path"
    assert any("beginswith" in e for e in body["errors"])


async def test_invalid_rule_is_rejected_with_422(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    for content in ["title: [broken", USER_RULE.replace("condition: selection", "condition: nope")]:
        r = await client.post("/api/v1/rules", json={"content": content}, headers=admin_headers)
        assert r.status_code == 422, r.text
        assert r.json()["detail"].startswith("invalid Sigma rule")


async def test_created_rule_takes_effect_immediately(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    ingest_headers: dict[str, str],
    make_http_event: MakeEvent,
) -> None:
    marker = make_http_event("/__sigma_api_marker/x")
    await ingest(client, ingest_headers, marker)
    assert await hits(USER_RULE_KEY) == 0

    r = await client.post("/api/v1/rules", json={"content": USER_RULE}, headers=admin_headers)
    assert r.status_code == 200, r.text
    rule = r.json()
    assert rule["source"] == "user" and rule["status"] == "active" and rule["title"] == "Lab marker path"
    assert rule["meta"]["sigma_id"] == USER_RULE_KEY and rule["meta"]["created_by"] == "admin"

    await ingest(client, ingest_headers, make_http_event("/__sigma_api_marker/y"))
    assert await hits(USER_RULE_KEY) == 1
    async with session_scope() as s:
        alert = (
            await s.execute(select(AlertRow).where(AlertRow.rule_id == f"sigma:{USER_RULE_KEY}"))
        ).scalar_one()
    assert alert.detector == "sigma" and alert.severity == "high" and alert.mitre == ["T1190"]
    assert alert.category == "exploit_attempt" and alert.details["rule_ref"] == rule["id"]
    assert alert.details["matched"] == ["selection"] and alert.details["falsepositives"] == ["none"]

    # hit counts are batched in memory and flushed when the API reads them
    assert get_rule_store().pending_hits().get(rule["id"]) == 1
    got = await client.get(f"/api/v1/rules/{rule['id']}", headers=admin_headers)
    assert got.json()["hit_count"] == 1
    assert get_rule_store().pending_hits() == {}
    assert "rule.create" in await audit_actions()

    dup = await client.post("/api/v1/rules", json={"content": USER_RULE}, headers=admin_headers)
    assert dup.status_code == 409


async def test_update_disable_and_delete_user_rule(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    ingest_headers: dict[str, str],
    make_http_event: MakeEvent,
) -> None:
    rid = (await client.post("/api/v1/rules", json={"content": USER_RULE}, headers=admin_headers)).json()[
        "id"
    ]

    bad = await client.patch(f"/api/v1/rules/{rid}", json={"content": "title: x"}, headers=admin_headers)
    assert bad.status_code == 422

    new_content = USER_RULE.replace("/__sigma_api_marker", "/__sigma_api_other").replace(
        "Lab marker path", "Lab other path"
    )
    upd = await client.patch(f"/api/v1/rules/{rid}", json={"content": new_content}, headers=admin_headers)
    assert upd.status_code == 200 and upd.json()["title"] == "Lab other path"
    await ingest(client, ingest_headers, make_http_event("/__sigma_api_marker/z"))
    assert await hits(USER_RULE_KEY) == 0
    await ingest(client, ingest_headers, make_http_event("/__sigma_api_other"))
    assert await hits(USER_RULE_KEY) == 1

    dis = await client.patch(f"/api/v1/rules/{rid}", json={"status": "disabled"}, headers=admin_headers)
    assert dis.json()["status"] == "disabled"
    await ingest(client, ingest_headers, make_http_event("/__sigma_api_other", ip="198.51.100.20"))
    assert await hits(USER_RULE_KEY) == 1

    assert (await client.delete(f"/api/v1/rules/{rid}", headers=admin_headers)).status_code == 204
    assert (await client.get(f"/api/v1/rules/{rid}", headers=admin_headers)).status_code == 404
    assert (await client.delete(f"/api/v1/rules/{rid}", headers=admin_headers)).status_code == 404
    actions = await audit_actions()
    assert actions.count("rule.update") == 2 and "rule.delete" in actions


async def test_proposed_rule_fires_only_after_approval(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    ingest_headers: dict[str, str],
    make_http_event: MakeEvent,
) -> None:
    # Simulate the intel advisor: an LLM-drafted rule stored directly as proposed.
    now = utcnow()
    async with session_scope() as s:
        row = RuleRow(
            id=new_id(),
            created_at=now,
            updated_at=now,
            kind="sigma",
            title="LLM draft",
            content=USER_RULE,
            status="proposed",
            source="llm",
            meta={},
        )
        s.add(row)
    await get_rule_store().reload()
    await ingest(client, ingest_headers, make_http_event("/__sigma_api_marker"))
    assert await hits(USER_RULE_KEY) == 0

    r = await client.post(f"/api/v1/rules/{row.id}/approve", headers=admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "active" and r.json()["meta"]["approved_by"] == "admin"
    await ingest(client, ingest_headers, make_http_event("/__sigma_api_marker"))
    assert await hits(USER_RULE_KEY) == 1

    again = await client.post(f"/api/v1/rules/{row.id}/approve", headers=admin_headers)
    assert again.status_code == 409
    assert "rule.approve" in await audit_actions()


async def test_invalid_proposed_rule_cannot_be_approved(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    async with session_scope() as s:
        row = RuleRow(
            id=new_id(), kind="sigma", title="bad", content="title: bad", status="proposed", source="llm"
        )
        s.add(row)
    r = await client.post(f"/api/v1/rules/{row.id}/approve", headers=admin_headers)
    assert r.status_code == 422


async def test_builtin_rule_status_toggle_and_content_is_read_only(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    ingest_headers: dict[str, str],
    make_http_event: MakeEvent,
) -> None:
    items = (
        await client.get("/api/v1/rules", params={"source": "builtin", "limit": 500}, headers=admin_headers)
    ).json()["items"]
    rid = next(it["id"] for it in items if it["meta"]["rule_key"] == SCANNER_RULE)

    assert (
        await client.patch(f"/api/v1/rules/{rid}", json={"content": USER_RULE}, headers=admin_headers)
    ).status_code == 409
    assert (await client.delete(f"/api/v1/rules/{rid}", headers=admin_headers)).status_code == 409

    await ingest(client, ingest_headers, make_http_event("/", ua="sqlmap/1.8 (https://sqlmap.org)"))
    assert await hits(SCANNER_RULE) == 1

    await client.patch(f"/api/v1/rules/{rid}", json={"status": "disabled"}, headers=admin_headers)
    await ingest(client, ingest_headers, make_http_event("/", ua="sqlmap/1.8", ip="198.51.100.9"))
    assert await hits(SCANNER_RULE) == 1

    await client.patch(f"/api/v1/rules/{rid}", json={"status": "active"}, headers=admin_headers)
    await ingest(client, ingest_headers, make_http_event("/", ua="sqlmap/1.8", ip="198.51.100.9"))
    assert await hits(SCANNER_RULE) == 2

    # status survives a re-sync from files (startup / reload endpoint)
    await client.patch(f"/api/v1/rules/{rid}", json={"status": "disabled"}, headers=admin_headers)
    rl = await client.post("/api/v1/rules/reload", headers=admin_headers)
    assert rl.status_code == 200 and rl.json()["errors"] == {}
    assert (await client.get(f"/api/v1/rules/{rid}", headers=admin_headers)).json()["status"] == "disabled"
    assert get_rule_store().get(SCANNER_RULE) is None


async def test_viewer_can_read_but_not_write(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    vh = await viewer_headers()
    assert (await client.get("/api/v1/rules", headers=vh)).status_code == 200
    assert (await client.get("/api/v1/detectors", headers=vh)).status_code == 200
    assert (await client.post("/api/v1/rules", json={"content": USER_RULE}, headers=vh)).status_code == 403
    assert (await client.post("/api/v1/rules/validate", json={"content": "x"}, headers=vh)).status_code == 403
    assert (
        await client.patch("/api/v1/detectors/sigma", json={"enabled": False}, headers=vh)
    ).status_code == 403
    assert (await client.get("/api/v1/rules")).status_code == 401


async def test_detectors_toggle_persists_across_restart(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    ingest_headers: dict[str, str],
    make_http_event: MakeEvent,
) -> None:
    dets = (await client.get("/api/v1/detectors", headers=admin_headers)).json()
    sigma = next(d for d in dets if d["id"] == "sigma")
    assert sigma["enabled"] is True and sigma["name"] == "Sigma rules"

    assert (
        await client.patch("/api/v1/detectors/nope.nope", json={"enabled": False}, headers=admin_headers)
    ).status_code == 404
    r = await client.patch("/api/v1/detectors/sigma", json={"enabled": False}, headers=admin_headers)
    assert r.status_code == 200 and r.json()["enabled"] is False

    attack = make_http_event("/", ua="sqlmap/1.8")
    await ingest(client, ingest_headers, attack)
    assert await hits(SCANNER_RULE) == 0

    async with session_scope() as s:
        stored = await s.get(SettingRow, OVERRIDES_KEY)
        assert stored is not None and stored.value == {"sigma": False}

    # "restart": fresh engine, then the startup hooks
    reset_detection_engine()
    assert get_detection_engine().overrides == {}
    await restore_detector_overrides()
    await _sigma_startup()
    assert get_detection_engine().overrides == {"sigma": False}
    await ingest(client, ingest_headers, make_http_event("/", ua="sqlmap/1.8"))
    assert await hits(SCANNER_RULE) == 0
    listed = (await client.get("/api/v1/detectors", headers=admin_headers)).json()
    assert next(d for d in listed if d["id"] == "sigma")["enabled"] is False

    await client.patch("/api/v1/detectors/sigma", json={"enabled": True}, headers=admin_headers)
    await ingest(client, ingest_headers, make_http_event("/", ua="sqlmap/1.8"))
    assert await hits(SCANNER_RULE) == 1
    assert (await audit_actions()).count("detector.update") == 2
