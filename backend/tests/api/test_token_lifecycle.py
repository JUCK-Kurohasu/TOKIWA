"""API token expiry, owner and rotation (audit #163)."""

from __future__ import annotations

from datetime import datetime, timedelta

import httpx
from sqlalchemy import update

from tokiwa.db.models.core import ApiTokenRow
from tokiwa.db.session import session_scope
from tokiwa.util import ensure_utc, utcnow


async def _set_expiry(token_id: str, delta: timedelta) -> None:
    async with session_scope() as s:
        await s.execute(
            update(ApiTokenRow).where(ApiTokenRow.id == token_id).values(expires_at=utcnow() + delta)
        )


def ensure_utc_iso(value: str) -> datetime:
    return ensure_utc(datetime.fromisoformat(value))


async def _ingest(client: httpx.AsyncClient, token: str) -> int:
    r = await client.post("/api/v1/ingest/events", json={"events": []}, headers={"X-Tokiwa-Token": token})
    return r.status_code


async def test_expiry_owner_and_401_when_expired(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.post(
        "/api/v1/tokens", json={"name": "agent", "expires_in_days": 30}, headers=admin_headers
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["created_by"] == "admin"
    left = ensure_utc_iso(body["expires_at"]) - utcnow()
    assert timedelta(days=29) < left <= timedelta(days=30)
    never = (await client.post("/api/v1/tokens", json={"name": "n"}, headers=admin_headers)).json()
    assert never["expires_at"] is None  # default stays "never expires" (backwards compatible)
    for bad in (0, 3651):
        assert (
            await client.post(
                "/api/v1/tokens", json={"name": "x", "expires_in_days": bad}, headers=admin_headers
            )
        ).status_code == 422

    assert await _ingest(client, body["token"]) == 200
    await _set_expiry(body["id"], timedelta(seconds=-1))
    denied = await client.post(
        "/api/v1/ingest/events", json={"events": []}, headers={"X-Tokiwa-Token": body["token"]}
    )
    assert denied.status_code == 401 and denied.json()["detail"] == "API token expired"


async def test_rotate_keeps_old_token_for_grace_period(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    created = (
        await client.post(
            "/api/v1/tokens",
            json={"name": "gate-1", "scopes": ["ingest", "gate"], "allowed_datasets": ["gate.*"]},
            headers=admin_headers,
        )
    ).json()
    r = await client.post(
        f"/api/v1/tokens/{created['id']}/rotate", json={"grace_hours": 1}, headers=admin_headers
    )
    assert r.status_code == 201, r.text
    new = r.json()
    assert new["token"] != created["token"] and new["rotated_from"] == created["id"]
    assert new["scopes"] == ["ingest", "gate"] and new["allowed_datasets"] == ["gate.*"]
    # both work during the grace period
    assert await _ingest(client, created["token"]) == 200
    assert await _ingest(client, new["token"]) == 200
    listed = {t["id"]: t for t in (await client.get("/api/v1/tokens", headers=admin_headers)).json()}
    assert listed[created["id"]]["expires_at"] is not None and listed[new["id"]]["expires_at"] is None
    assert "token" not in listed[new["id"]]

    # after the grace period only the new one works
    await _set_expiry(created["id"], timedelta(seconds=-1))
    assert await _ingest(client, created["token"]) == 401
    assert await _ingest(client, new["token"]) == 200
    # an expired / revoked token cannot be rotated; unknown id is 404
    assert (
        await client.post(f"/api/v1/tokens/{created['id']}/rotate", headers=admin_headers)
    ).status_code == 409
    assert (await client.post("/api/v1/tokens/nope/rotate", headers=admin_headers)).status_code == 404

    audit = (
        await client.get("/api/v1/audit", params={"action": "token.rotate"}, headers=admin_headers)
    ).json()
    assert audit["total"] == 1 and audit["items"][0]["details"]["new_token_id"] == new["id"]
    assert new["token"] not in str(audit)


async def test_rotate_with_zero_grace_revokes_and_requires_admin(
    client: httpx.AsyncClient, admin_headers: dict[str, str], ingest_headers: dict[str, str]
) -> None:
    created = (await client.post("/api/v1/tokens", json={"name": "a"}, headers=admin_headers)).json()
    r = await client.post(
        f"/api/v1/tokens/{created['id']}/rotate", json={"grace_hours": 0}, headers=admin_headers
    )
    assert r.status_code == 201
    assert await _ingest(client, created["token"]) == 401
    assert await _ingest(client, r.json()["token"]) == 200
    # API tokens cannot manage tokens
    assert (
        await client.post(f"/api/v1/tokens/{created['id']}/rotate", headers=ingest_headers)
    ).status_code == 401
