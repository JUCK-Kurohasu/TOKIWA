"""GET /api/v1/gate/status (#145): an approved block is only enforced once a Gate pulls a policy containing it."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import httpx
import pytest

from tokiwa.api.routes import gate as gate_routes
from tokiwa.db.models.gate_status import GatePollRow
from tokiwa.db.session import session_scope
from tokiwa.util import utcnow


async def _approved_block(client: httpx.AsyncClient, analyst: dict[str, str], target: str) -> dict[str, Any]:
    r = await client.post(
        "/api/v1/response/actions",
        json={"action_type": "block_ip", "target": target, "reason": "test", "ttl_minutes": 30},
        headers=analyst,
    )
    assert r.status_code == 200, r.text
    approved = await client.post(f"/api/v1/response/actions/{r.json()['id']}/approve", headers=analyst)
    assert approved.status_code == 200 and approved.json()["status"] == "active", approved.text
    return approved.json()


async def _status(client: httpx.AsyncClient, headers: dict[str, str]) -> dict[str, Any]:
    r = await client.get("/api/v1/gate/status", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def _reflection(status: dict[str, Any], action_id: str) -> dict[str, Any]:
    return next(a for a in status["actions"] if a["action_id"] == action_id)


async def test_active_block_without_any_gate_is_not_reflected(
    client: httpx.AsyncClient, make_user, ingest_headers: dict[str, str]
) -> None:  # type: ignore[no-untyped-def]
    analyst = await make_user("analyst")
    viewer = await make_user("viewer")
    action = await _approved_block(client, analyst, "198.51.100.8")

    st = await _status(client, viewer)  # any logged-in role may read it
    assert st["gates"] == []
    assert st["stale_after_seconds"] >= 120
    ref = _reflection(st, action["id"])
    assert ref["gates_applied"] == 0 and ref["last_applied_at"] is None

    # A Gate pulls the policy -> the block is reflected by one fresh Gate.
    policy = await client.get("/api/v1/gate/policy", headers=ingest_headers)
    assert policy.status_code == 200 and "198.51.100.8" in policy.json()["blocked"]
    st = await _status(client, viewer)
    assert len(st["gates"]) == 1
    gate = st["gates"][0]
    assert gate["token_name"] == "test-sensor" and gate["current"] is True and gate["stale"] is False
    assert gate["last_status"] == 200 and gate["fetch_count"] == 1
    ref = _reflection(st, action["id"])
    assert (ref["gates_applied"], ref["gates_applied_fresh"]) == (1, 1)
    assert ref["last_applied_at"] is not None


async def test_304_polls_are_recorded_and_new_actions_wait_for_the_next_poll(
    client: httpx.AsyncClient, make_user, ingest_headers: dict[str, str]
) -> None:  # type: ignore[no-untyped-def]
    analyst = await make_user("analyst")
    first = await _approved_block(client, analyst, "198.51.100.9")
    r = await client.get("/api/v1/gate/policy", headers=ingest_headers)
    etag = r.headers["ETag"]
    r304 = await client.get("/api/v1/gate/policy", headers={**ingest_headers, "If-None-Match": etag})
    assert r304.status_code == 304
    st = await _status(client, analyst)
    assert st["gates"][0]["fetch_count"] == 2 and st["gates"][0]["last_status"] == 304

    second = await _approved_block(client, analyst, "198.51.100.10")
    st = await _status(client, analyst)
    assert _reflection(st, first["id"])["gates_applied"] == 1
    assert _reflection(st, second["id"])["gates_applied"] == 0  # approved after the Gate's last poll
    assert st["gates"][0]["current"] is False  # the policy changed since

    await client.get("/api/v1/gate/policy", headers={**ingest_headers, "If-None-Match": etag})
    st = await _status(client, analyst)
    assert _reflection(st, second["id"])["gates_applied"] == 1
    assert st["gates"][0]["current"] is True


async def test_stale_gate_is_flagged(
    client: httpx.AsyncClient, make_user, ingest_headers: dict[str, str]
) -> None:  # type: ignore[no-untyped-def]
    analyst = await make_user("analyst")
    action = await _approved_block(client, analyst, "198.51.100.11")
    await client.get("/api/v1/gate/policy", headers=ingest_headers)
    async with session_scope() as s:
        row = (await s.execute(GatePollRow.__table__.select())).first()
        assert row is not None
        polled = await s.get(GatePollRow, row.id)
        assert polled is not None
        polled.last_seen = utcnow() - timedelta(seconds=gate_routes.stale_after_seconds() + 60)
        polled.first_seen = polled.last_seen
    st = await _status(client, analyst)
    assert st["gates"][0]["stale"] is True
    ref = _reflection(st, action["id"])
    # The old poll predates the approval, so the stale Gate does not hold it either.
    assert (ref["gates_applied"], ref["gates_applied_fresh"]) == (0, 0)


async def test_policy_is_served_even_if_recording_fails(
    client: httpx.AsyncClient, ingest_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_scope() -> Any:
        raise RuntimeError("db down")

    monkeypatch.setattr(gate_routes, "session_scope", broken_scope)
    r = await client.get("/api/v1/gate/policy", headers=ingest_headers)
    assert r.status_code == 200 and "version" in r.json()


async def test_status_requires_login(client: httpx.AsyncClient, ingest_headers: dict[str, str]) -> None:
    assert (await client.get("/api/v1/gate/status")).status_code == 401
    # A Gate token is not a user session.
    assert (await client.get("/api/v1/gate/status", headers=ingest_headers)).status_code == 401
