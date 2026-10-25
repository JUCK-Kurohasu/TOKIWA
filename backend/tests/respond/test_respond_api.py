"""/api/v1/response/*: end-to-end through the real gate executors and the Gate policy endpoint."""

from __future__ import annotations

import httpx

from tokiwa.db.models.core import AuditRow
from tokiwa.db.session import session_scope


async def test_full_flow_propose_approve_policy_revert(
    client: httpx.AsyncClient, make_user, ingest_headers: dict[str, str]
) -> None:  # type: ignore[no-untyped-def]
    analyst = await make_user("analyst")
    r = await client.post(
        "/api/v1/response/actions",
        json={
            "action_type": "rate_limit",
            "target": "203.0.113.0/24",
            "params": {"requests_per_minute": 12},
            "reason": "AI agent burst",
            "ttl_minutes": 15,
        },
        headers=analyst,
    )
    assert r.status_code == 200, r.text
    action = r.json()
    assert action["status"] == "proposed" and action["params"] == {"requests_per_minute": 12}
    policy = (await client.get("/api/v1/gate/policy", headers=ingest_headers)).json()
    assert policy["rate_limited"] == {}  # not enforced before approval

    approved = await client.post(f"/api/v1/response/actions/{action['id']}/approve", headers=analyst)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "active" and approved.json()["expires_at"]
    policy = (await client.get("/api/v1/gate/policy", headers=ingest_headers)).json()
    assert policy["rate_limited"] == {"203.0.113.0/24": 12}

    got = await client.get(f"/api/v1/response/actions/{action['id']}", headers=analyst)
    assert got.status_code == 200 and got.json()["approved_by"].startswith("analyst-")

    reverted = await client.post(f"/api/v1/response/actions/{action['id']}/revert", headers=analyst)
    assert reverted.status_code == 200 and reverted.json()["status"] == "reverted"
    policy = (await client.get("/api/v1/gate/policy", headers=ingest_headers)).json()
    assert policy["rate_limited"] == {}

    async with session_scope() as s:
        from sqlalchemy import select

        actions = (
            (await s.execute(select(AuditRow.action).where(AuditRow.target == action["id"]))).scalars().all()
        )
    assert set(actions) >= {"response.propose", "response.approve", "response.execute", "response.revert"}


async def test_errors_and_listing(client: httpx.AsyncClient, make_user) -> None:  # type: ignore[no-untyped-def]
    analyst = await make_user("analyst")
    viewer = await make_user("viewer")
    bad = await client.post(
        "/api/v1/response/actions",
        json={"action_type": "block_ip", "target": "127.0.0.1", "reason": "x"},
        headers=analyst,
    )
    assert bad.status_code == 422 and "protected" in bad.json()["detail"]
    unknown_type = await client.post(
        "/api/v1/response/actions",
        json={"action_type": "run_command", "target": "203.0.113.9", "reason": "x"},
        headers=analyst,
    )
    assert unknown_type.status_code == 422

    created = await client.post(
        "/api/v1/response/actions",
        json={"action_type": "block_ip", "target": "203.0.113.9", "reason": "x", "incident_id": "incX"},
        headers=analyst,
    )
    aid = created.json()["id"]
    assert (await client.post("/api/v1/response/actions/nope/approve", headers=analyst)).status_code == 404
    assert (await client.post(f"/api/v1/response/actions/{aid}/revert", headers=analyst)).status_code == 409

    rej = await client.post(
        f"/api/v1/response/actions/{aid}/reject", json={"reason": "false positive"}, headers=analyst
    )
    assert rej.status_code == 200 and rej.json()["status"] == "rejected"
    assert rej.json()["result"]["rejection_reason"] == "false positive"
    assert (await client.post(f"/api/v1/response/actions/{aid}/approve", headers=analyst)).status_code == 409

    # viewers can read but not write
    listed = await client.get("/api/v1/response/actions", params={"status": "rejected"}, headers=viewer)
    assert listed.status_code == 200
    body = listed.json()
    assert body["total"] == 1 and body["items"][0]["id"] == aid and body["limit"] == 50
    by_incident = await client.get("/api/v1/response/actions", params={"incident_id": "incX"}, headers=viewer)
    assert by_incident.json()["total"] == 1
    assert (
        await client.get("/api/v1/response/actions", params={"limit": 501}, headers=viewer)
    ).status_code == 422
    write = await client.post(
        "/api/v1/response/actions",
        json={"action_type": "block_ip", "target": "203.0.113.10", "reason": "x"},
        headers=viewer,
    )
    assert write.status_code == 403
    assert (await client.post(f"/api/v1/response/actions/{aid}/reject", headers=viewer)).status_code == 403
    assert (await client.get("/api/v1/response/actions")).status_code == 401


async def test_reject_without_body(client: httpx.AsyncClient, make_user) -> None:  # type: ignore[no-untyped-def]
    analyst = await make_user("analyst")
    created = await client.post(
        "/api/v1/response/actions",
        json={"action_type": "tarpit", "target": "203.0.113.11", "reason": "x"},
        headers=analyst,
    )
    aid = created.json()["id"]
    r = await client.post(f"/api/v1/response/actions/{aid}/reject", headers=analyst)
    assert r.status_code == 200 and r.json()["status"] == "rejected"
