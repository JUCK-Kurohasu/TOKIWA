"""/api/v1/notify/channels: admin-only CRUD, secret masking, test sends (HTTP mocked)."""

from __future__ import annotations

import json

import httpx
import respx

from tokiwa.auth.security import create_access_token, hash_password
from tokiwa.db.models.core import UserRow
from tokiwa.db.models.response import NotificationChannelRow
from tokiwa.db.session import session_scope
from tokiwa.util import new_id, utcnow

SECRET_URL = "https://hooks.slack.com/services/T000/B000/VERYSECRET"


async def _analyst_headers() -> dict[str, str]:
    row = UserRow(
        id=new_id(),
        username=f"analyst-{new_id()[:8]}",
        password_hash=hash_password("correct-horse-battery"),
        role="analyst",
        created_at=utcnow(),
    )
    async with session_scope() as s:
        s.add(row)
    token, _ = create_access_token(row.id, row.username, row.role)
    return {"Authorization": f"Bearer {token}"}


async def test_channel_crud_masks_secrets(client: httpx.AsyncClient, admin_headers: dict[str, str]) -> None:
    r = await client.post(
        "/api/v1/notify/channels",
        json={"kind": "slack", "name": "soc", "config": {"url": SECRET_URL}, "min_severity": "medium"},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    created = r.json()
    assert "VERYSECRET" not in r.text
    assert created["config"]["url"] == "https://hooks.slack.com/********"
    cid = created["id"]

    listed = await client.get("/api/v1/notify/channels", headers=admin_headers)
    assert listed.status_code == 200 and "VERYSECRET" not in listed.text
    assert [c["id"] for c in listed.json()] == [cid]

    # PATCH echoing the masked config keeps the stored secret.
    p = await client.patch(
        f"/api/v1/notify/channels/{cid}",
        json={"name": "soc-renamed", "config": created["config"], "enabled": False},
        headers=admin_headers,
    )
    assert p.status_code == 200, p.text
    assert p.json()["name"] == "soc-renamed" and p.json()["enabled"] is False
    async with session_scope() as s:
        row = await s.get(NotificationChannelRow, cid)
        assert row is not None and row.config["url"] == SECRET_URL

    d = await client.delete(f"/api/v1/notify/channels/{cid}", headers=admin_headers)
    assert d.status_code == 204
    assert (await client.delete(f"/api/v1/notify/channels/{cid}", headers=admin_headers)).status_code == 404


async def test_invalid_config_is_422_without_echoing_secret(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.post(
        "/api/v1/notify/channels",
        json={"kind": "webhook", "name": "x", "config": {"url": "ftp://x/VERYSECRET", "nope": 1}},
        headers=admin_headers,
    )
    assert r.status_code == 422
    assert "VERYSECRET" not in r.text


async def test_test_endpoint(client: httpx.AsyncClient, admin_headers: dict[str, str]) -> None:
    r = await client.post(
        "/api/v1/notify/channels",
        json={"kind": "discord", "name": "d", "config": {"url": SECRET_URL}},
        headers=admin_headers,
    )
    cid = r.json()["id"]
    with respx.mock() as mock:
        route = mock.post(SECRET_URL).mock(return_value=httpx.Response(204))
        ok = await client.post(f"/api/v1/notify/channels/{cid}/test", headers=admin_headers)
        assert ok.json() == {"ok": True, "error": None}
        assert "embeds" in json.loads(route.calls.last.request.content)
        route.mock(return_value=httpx.Response(404))
        bad = await client.post(f"/api/v1/notify/channels/{cid}/test", headers=admin_headers)
        assert bad.json() == {"ok": False, "error": "HTTP 404"}
    missing = await client.post("/api/v1/notify/channels/nope/test", headers=admin_headers)
    assert missing.status_code == 404


async def test_notify_routes_are_admin_only(client: httpx.AsyncClient, admin_headers: dict[str, str]) -> None:
    analyst = await _analyst_headers()
    assert (await client.get("/api/v1/notify/channels", headers=analyst)).status_code == 403
    assert (await client.get("/api/v1/notify/channels")).status_code == 401
    r = await client.post(
        "/api/v1/notify/channels",
        json={"kind": "webhook", "name": "x", "config": {"url": SECRET_URL}},
        headers=analyst,
    )
    assert r.status_code == 403
