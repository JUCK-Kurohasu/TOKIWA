"""Copilot role gate and per-user message rate limit (audit #164, finding L10-08)."""

from __future__ import annotations

import httpx
import pytest

from tokiwa.api.routes import copilot as copilot_routes
from tokiwa.api.routes.copilot import UserRateLimiter
from tokiwa.auth.security import create_access_token, hash_password
from tokiwa.config import reset_settings_cache
from tokiwa.db.models.core import UserRow
from tokiwa.db.models.llm import CopilotConversationRow
from tokiwa.db.session import session_scope
from tokiwa.util import new_id, utcnow

BASE = "/api/v1/copilot"


async def _user(role: str) -> tuple[str, dict[str, str]]:
    row = UserRow(
        id=new_id(),
        username=f"{role}-{new_id()[-8:]}",
        password_hash=hash_password("x" * 12),
        role=role,
        created_at=utcnow(),
    )
    async with session_scope() as s:
        s.add(row)
    token, _ = create_access_token(row.id, row.username, row.role)
    return row.id, {"Authorization": f"Bearer {token}"}


async def test_viewer_cannot_start_or_post_by_default(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    viewer_id, viewer = await _user("viewer")
    r = await client.post(f"{BASE}/conversations", json={}, headers=viewer)
    assert r.status_code == 403 and "analyst" in r.json()["detail"]
    # a conversation that already exists (e.g. created before the upgrade) stays readable but not writable
    conv_id = new_id()
    async with session_scope() as s:
        s.add(
            CopilotConversationRow(
                id=conv_id, owner=viewer_id, title="old", created_at=utcnow(), updated_at=utcnow()
            )
        )
    assert (await client.get(f"{BASE}/conversations", headers=viewer)).status_code == 200
    assert (await client.get(f"{BASE}/conversations/{conv_id}", headers=viewer)).status_code == 200
    posted = await client.post(
        f"{BASE}/conversations/{conv_id}/messages", json={"content": "hi"}, headers=viewer
    )
    assert posted.status_code == 403

    _, analyst = await _user("analyst")
    assert (await client.post(f"{BASE}/conversations", json={}, headers=analyst)).status_code == 201

    # the role is configurable
    monkeypatch.setenv("TOKIWA_COPILOT__MIN_ROLE", "viewer")
    reset_settings_cache()
    assert (await client.post(f"{BASE}/conversations", json={}, headers=viewer)).status_code == 201
    monkeypatch.setenv("TOKIWA_COPILOT__MIN_ROLE", "admin")
    reset_settings_cache()
    assert (await client.post(f"{BASE}/conversations", json={}, headers=analyst)).status_code == 403


async def test_messages_per_minute_per_user(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [1000.0]
    monkeypatch.setattr(copilot_routes, "message_limiter", UserRateLimiter(clock=lambda: now[0]))
    monkeypatch.setenv("TOKIWA_COPILOT__MESSAGES_PER_MINUTE", "2")
    reset_settings_cache()
    _, alice = await _user("analyst")
    _, bob = await _user("analyst")

    async def post(headers: dict[str, str]) -> httpx.Response:
        conv = (await client.post(f"{BASE}/conversations", json={}, headers=headers)).json()
        return await client.post(
            f"{BASE}/conversations/{conv['id']}/messages", json={"content": "hi"}, headers=headers
        )

    assert (await post(alice)).status_code == 200
    now[0] += 10
    assert (await post(alice)).status_code == 200
    limited = await post(alice)  # a new conversation does not reset the per-user limit
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "50"
    assert (await post(bob)).status_code == 200  # per user
    now[0] += 51
    assert (await post(alice)).status_code == 200  # the first hit left the window


def test_rate_limiter_window_and_unlimited() -> None:
    now = [0.0]
    lim = UserRateLimiter(clock=lambda: now[0], max_users=2)
    assert lim.check("u", 0) is None and lim.check("u", 0) is None  # 0 = unlimited, nothing recorded
    assert lim.check("u", 1) is None
    assert lim.check("u", 1) == pytest.approx(60.0)
    now[0] = 60.0
    assert lim.check("u", 1) is None
    for k in ("a", "b", "c"):
        lim.check(k, 5)
    now[0] = 200.0
    lim.check("d", 5)  # over max_users: idle keys are forgotten
    assert set(lim._hits) == {"d"}
