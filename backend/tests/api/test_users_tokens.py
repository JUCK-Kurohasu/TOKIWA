"""Users and API tokens (admin only): CRUD, last-admin protection, one-time token plaintext, audit."""

from __future__ import annotations

import httpx
import pytest

from tokiwa.db.models.core import AuditRow
from tokiwa.db.session import session_scope

from .conftest import PASSWORD, MakeUser


async def _me(client: httpx.AsyncClient, headers: dict[str, str]) -> dict[str, str]:
    r = await client.get("/api/v1/auth/me", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


async def _audit_actions() -> list[str]:
    from sqlalchemy import select

    async with session_scope() as s:
        return list((await s.execute(select(AuditRow.action).order_by(AuditRow.created_at))).scalars())


# --- users ------------------------------------------------------------------------------------------------


async def test_list_and_create_users(client: httpx.AsyncClient, admin_headers: dict[str, str]) -> None:
    r = await client.get("/api/v1/users", headers=admin_headers)
    assert r.status_code == 200
    assert [u["username"] for u in r.json()] == ["admin"]

    r = await client.post(
        "/api/v1/users",
        json={"username": "alice", "password": PASSWORD, "role": "viewer"},
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["username"] == "alice" and body["role"] == "viewer"
    assert "password" not in body and "password_hash" not in body

    dup = await client.post(
        "/api/v1/users", json={"username": "alice", "password": PASSWORD}, headers=admin_headers
    )
    assert dup.status_code == 409
    bad = await client.post(
        "/api/v1/users", json={"username": "bad name!", "password": "short"}, headers=admin_headers
    )
    assert bad.status_code == 422

    names = [u["username"] for u in (await client.get("/api/v1/users", headers=admin_headers)).json()]
    assert names == ["admin", "alice"]
    assert "user.create" in await _audit_actions()


async def test_new_user_can_log_in_with_role(client: httpx.AsyncClient, make_user: MakeUser) -> None:
    headers = await make_user("analyst", "bob")
    me = await _me(client, headers)
    assert me["username"] == "bob" and me["role"] == "analyst"


async def test_last_admin_cannot_be_demoted(client: httpx.AsyncClient, admin_headers: dict[str, str]) -> None:
    admin = await _me(client, admin_headers)
    r = await client.patch(f"/api/v1/users/{admin['id']}", json={"role": "viewer"}, headers=admin_headers)
    assert r.status_code == 409
    assert (await _me(client, admin_headers))["role"] == "admin"


async def test_demote_and_promote_take_effect_immediately(
    client: httpx.AsyncClient, admin_headers: dict[str, str], make_user: MakeUser
) -> None:
    second_admin = await make_user("admin", "admin2")
    admin = await _me(client, admin_headers)
    # With two admins, one may be demoted (even by themselves).
    r = await client.patch(f"/api/v1/users/{admin['id']}", json={"role": "analyst"}, headers=admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "analyst"
    # The existing JWT is re-checked against the DB role -> admin endpoints are now forbidden.
    assert (await client.get("/api/v1/users", headers=admin_headers)).status_code == 403
    # ...and admin2 is now the last admin.
    admin2 = await _me(client, second_admin)
    r = await client.patch(f"/api/v1/users/{admin2['id']}", json={"role": "viewer"}, headers=second_admin)
    assert r.status_code == 409
    # Promote back.
    r = await client.patch(f"/api/v1/users/{admin['id']}", json={"role": "admin"}, headers=second_admin)
    assert r.status_code == 200
    assert (await client.get("/api/v1/users", headers=admin_headers)).status_code == 200


async def test_password_reset(
    client: httpx.AsyncClient, admin_headers: dict[str, str], make_user: MakeUser
) -> None:
    headers = await make_user("viewer", "carol")
    carol = await _me(client, headers)
    new_password = "another-long-password"
    r = await client.patch(
        f"/api/v1/users/{carol['id']}", json={"password": new_password}, headers=admin_headers
    )
    assert r.status_code == 200
    old = await client.post("/api/v1/auth/login", json={"username": "carol", "password": PASSWORD})
    assert old.status_code == 401
    new = await client.post("/api/v1/auth/login", json={"username": "carol", "password": new_password})
    assert new.status_code == 200
    short = await client.patch(f"/api/v1/users/{carol['id']}", json={"password": "x"}, headers=admin_headers)
    assert short.status_code == 422
    # A no-op update succeeds without writing an audit entry.
    noop = await client.patch(f"/api/v1/users/{carol['id']}", json={"role": "viewer"}, headers=admin_headers)
    assert noop.status_code == 200 and noop.json()["role"] == "viewer"
    assert (await _audit_actions()).count("user.update") == 1  # only the password change


async def test_delete_user(
    client: httpx.AsyncClient, admin_headers: dict[str, str], make_user: MakeUser
) -> None:
    admin = await _me(client, admin_headers)
    assert (await client.delete(f"/api/v1/users/{admin['id']}", headers=admin_headers)).status_code == 400
    assert (await client.delete("/api/v1/users/nope", headers=admin_headers)).status_code == 404
    assert (await client.patch("/api/v1/users/nope", json={}, headers=admin_headers)).status_code == 404

    headers = await make_user("analyst", "dave")
    dave = await _me(client, headers)
    r = await client.delete(f"/api/v1/users/{dave['id']}", headers=admin_headers)
    assert r.status_code == 204
    # A deleted user's token stops working.
    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 401
    names = [u["username"] for u in (await client.get("/api/v1/users", headers=admin_headers)).json()]
    assert "dave" not in names
    assert "user.delete" in await _audit_actions()


# --- tokens -----------------------------------------------------------------------------------------------


async def test_token_lifecycle(client: httpx.AsyncClient, admin_headers: dict[str, str]) -> None:
    r = await client.post(
        "/api/v1/tokens", json={"name": "gate-1", "scopes": ["ingest", "ingest"]}, headers=admin_headers
    )
    assert r.status_code == 201, r.text
    created = r.json()
    plaintext = created["token"]
    assert plaintext.startswith("tkw_")
    assert created["prefix"] == plaintext[:10]
    assert created["scopes"] == ["ingest"]
    assert created["revoked"] is False
    assert "token_hash" not in created

    listed = (await client.get("/api/v1/tokens", headers=admin_headers)).json()
    assert [t["id"] for t in listed] == [created["id"]]
    assert "token" not in listed[0] and "token_hash" not in listed[0]
    assert plaintext not in (await client.get("/api/v1/tokens", headers=admin_headers)).text

    ingest = {"X-Tokiwa-Token": plaintext}
    ok = await client.post("/api/v1/ingest/events", json={"events": []}, headers=ingest)
    assert ok.status_code == 200, ok.text

    assert (await client.delete(f"/api/v1/tokens/{created['id']}", headers=admin_headers)).status_code == 204
    # idempotent
    assert (await client.delete(f"/api/v1/tokens/{created['id']}", headers=admin_headers)).status_code == 204
    assert (await client.delete("/api/v1/tokens/nope", headers=admin_headers)).status_code == 404

    denied = await client.post("/api/v1/ingest/events", json={"events": []}, headers=ingest)
    assert denied.status_code == 401
    listed = (await client.get("/api/v1/tokens", headers=admin_headers)).json()
    assert listed[0]["revoked"] is True

    actions = await _audit_actions()
    assert actions.count("token.create") == 1
    assert actions.count("token.revoke") == 1
    # The plaintext secret never reaches the audit trail.
    audit = (await client.get("/api/v1/audit", headers=admin_headers)).text
    assert plaintext not in audit


async def test_token_default_scopes_and_validation(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.post("/api/v1/tokens", json={"name": "agent"}, headers=admin_headers)
    assert r.status_code == 201
    assert sorted(r.json()["scopes"]) == ["gate", "ingest"]
    empty = await client.post("/api/v1/tokens", json={"name": "x", "scopes": []}, headers=admin_headers)
    assert empty.status_code == 422
    bogus = await client.post("/api/v1/tokens", json={"name": "x", "scopes": ["root"]}, headers=admin_headers)
    assert bogus.status_code == 422
    noname = await client.post("/api/v1/tokens", json={"name": ""}, headers=admin_headers)
    assert noname.status_code == 422


# --- permissions ------------------------------------------------------------------------------------------

ADMIN_ONLY = [
    ("GET", "/api/v1/users", None),
    ("POST", "/api/v1/users", {"username": "mallory", "password": PASSWORD, "role": "admin"}),
    ("PATCH", "/api/v1/users/x", {"role": "admin"}),
    ("DELETE", "/api/v1/users/x", None),
    ("GET", "/api/v1/tokens", None),
    ("POST", "/api/v1/tokens", {"name": "t"}),
    ("DELETE", "/api/v1/tokens/x", None),
]


@pytest.mark.parametrize(("method", "path", "body"), ADMIN_ONLY)
async def test_admin_only_endpoints(
    client: httpx.AsyncClient,
    role_headers: dict[str, dict[str, str]],
    method: str,
    path: str,
    body: dict[str, str] | None,
) -> None:
    assert (await client.request(method, path, json=body)).status_code == 401
    for role in ("viewer", "analyst"):
        r = await client.request(method, path, json=body, headers=role_headers[role])
        assert r.status_code == 403, (role, r.text)
    r = await client.request(method, path, json=body, headers=role_headers["admin"])
    assert r.status_code not in (401, 403), r.text
