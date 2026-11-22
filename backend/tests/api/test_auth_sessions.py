"""JWT revocation (#34): password/role change, logout and admin "revoke sessions" end existing logins."""

from __future__ import annotations

from datetime import timedelta

import httpx
import jwt
from sqlalchemy import select

from tokiwa.auth.security import create_access_token, secret_key
from tokiwa.db.models.core import AuditRow
from tokiwa.db.session import session_scope
from tokiwa.util import utcnow

from .conftest import PASSWORD, MakeUser


async def _login(client: httpx.AsyncClient, username: str, password: str = PASSWORD) -> dict[str, str]:
    r = await client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def _me(client: httpx.AsyncClient, headers: dict[str, str]) -> httpx.Response:
    return await client.get("/api/v1/auth/me", headers=headers)


async def _audit_actions() -> list[str]:
    async with session_scope() as s:
        return list((await s.execute(select(AuditRow.action).order_by(AuditRow.created_at))).scalars())


async def test_password_change_revokes_old_tokens(
    client: httpx.AsyncClient, admin_headers: dict[str, str], make_user: MakeUser
) -> None:
    old = await make_user("analyst", "frank")
    frank = (await _me(client, old)).json()
    r = await client.patch(
        f"/api/v1/users/{frank['id']}", json={"password": "a-brand-new-password"}, headers=admin_headers
    )
    assert r.status_code == 200
    stale = await _me(client, old)
    assert stale.status_code == 401 and stale.json()["detail"] == "token revoked"
    fresh = await _login(client, "frank", "a-brand-new-password")
    assert (await _me(client, fresh)).status_code == 200


async def test_role_change_revokes_old_tokens(
    client: httpx.AsyncClient, admin_headers: dict[str, str], make_user: MakeUser
) -> None:
    old = await make_user("analyst", "grace")
    grace = (await _me(client, old)).json()
    r = await client.patch(f"/api/v1/users/{grace['id']}", json={"role": "viewer"}, headers=admin_headers)
    assert r.status_code == 200
    assert (await _me(client, old)).status_code == 401
    assert (await _me(client, await _login(client, "grace"))).json()["role"] == "viewer"


async def test_logout_ends_every_session_of_the_user(
    client: httpx.AsyncClient, admin_headers: dict[str, str], make_user: MakeUser
) -> None:
    laptop = await make_user("analyst", "heidi")
    phone = await _login(client, "heidi")
    other_user = await make_user("analyst", "ivan")
    assert (await client.post("/api/v1/auth/logout", headers=laptop)).status_code == 204
    assert (await _me(client, laptop)).status_code == 401
    assert (await _me(client, phone)).status_code == 401
    assert (await _me(client, other_user)).status_code == 200, "other users are not affected"
    assert (await _me(client, await _login(client, "heidi"))).status_code == 200
    assert (await client.post("/api/v1/auth/logout")).status_code == 401
    assert "auth.logout" in await _audit_actions()


async def test_admin_can_revoke_another_users_sessions(
    client: httpx.AsyncClient, admin_headers: dict[str, str], make_user: MakeUser
) -> None:
    target = await make_user("analyst", "judy")
    analyst = await make_user("analyst", "mallory")
    judy = (await _me(client, target)).json()
    path = f"/api/v1/users/{judy['id']}/revoke-sessions"
    assert (await client.post(path, headers=analyst)).status_code == 403
    assert (await client.post("/api/v1/users/nope/revoke-sessions", headers=admin_headers)).status_code == 404
    assert (await client.post(path, headers=admin_headers)).status_code == 204
    assert (await _me(client, target)).status_code == 401
    assert (await _me(client, admin_headers)).status_code == 200
    assert "user.sessions_revoked" in await _audit_actions()


async def test_tokens_from_before_versioning_still_work(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    admin = (await _me(client, admin_headers)).json()
    now = utcnow()
    legacy = {  # what v0.1 issued: no "ver" claim
        "sub": admin["id"],
        "name": "admin",
        "role": "admin",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "typ": "access",
    }
    token = jwt.encode(legacy, secret_key(), algorithm="HS256")
    assert (await _me(client, {"Authorization": f"Bearer {token}"})).status_code == 200
    # ...until the user's sessions are revoked.
    await client.post("/api/v1/auth/logout", headers=admin_headers)
    assert (await _me(client, {"Authorization": f"Bearer {token}"})).status_code == 401

    bad = jwt.encode({**legacy, "ver": "0"}, secret_key(), algorithm="HS256")
    assert (await _me(client, {"Authorization": f"Bearer {bad}"})).status_code == 401


async def test_token_ttl_default_unchanged(settings: object) -> None:
    _, ttl = create_access_token("u", "name", "viewer")
    assert ttl == 12 * 60 * 60
