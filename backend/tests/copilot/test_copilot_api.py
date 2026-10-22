"""Copilot HTTP API: conversation CRUD, ownership, and the SSE message stream."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from tokiwa.auth.security import create_access_token, hash_password
from tokiwa.config import reset_settings_cache
from tokiwa.db.models.core import UserRow
from tokiwa.db.session import session_scope
from tokiwa.util import new_id, utcnow

from .conftest import ATTACKER_IP, ScriptedProvider, Step, text_turn, tool_turn

BASE = "/api/v1/copilot"


async def _user_headers(username: str, role: str) -> dict[str, str]:
    row = UserRow(
        id=new_id(), username=username, password_hash=hash_password("x" * 12), role=role, created_at=utcnow()
    )
    async with session_scope() as s:
        s.add(row)
    token, _ = create_access_token(row.id, row.username, row.role)
    return {"Authorization": f"Bearer {token}"}


def _sse_events(r: httpx.Response) -> list[dict[str, Any]]:
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/event-stream")
    return [json.loads(line[5:].strip()) for line in r.text.splitlines() if line.startswith("data:")]


async def test_conversation_crud_and_ownership(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    analyst = await _user_headers("alice", "analyst")

    r = await client.post(f"{BASE}/conversations", json={"title": "Admin chat"}, headers=admin_headers)
    assert r.status_code == 201, r.text
    admin_conv = r.json()
    assert admin_conv["title"] == "Admin chat" and admin_conv["context"] == {}

    r = await client.post(
        f"{BASE}/conversations",
        json={"context": {"incident_id": "inc-x", "junk": "ignored"}},
        headers=analyst,
    )
    assert r.status_code == 201
    mine = r.json()
    assert mine["title"] == "New conversation"
    assert mine["context"] == {"incident_id": "inc-x"}  # internal snapshot key is never exposed

    # Analysts only see their own conversations; the admin's is invisible (404, not 403).
    assert [c["id"] for c in (await client.get(f"{BASE}/conversations", headers=analyst)).json()] == [
        mine["id"]
    ]
    assert (await client.get(f"{BASE}/conversations/{admin_conv['id']}", headers=analyst)).status_code == 404
    assert (
        await client.delete(f"{BASE}/conversations/{admin_conv['id']}", headers=analyst)
    ).status_code == 404

    # Admins read everything, but list only their own unless ?all=true, and cannot post as the owner.
    assert len((await client.get(f"{BASE}/conversations", headers=admin_headers)).json()) == 1
    assert len((await client.get(f"{BASE}/conversations?all=true", headers=admin_headers)).json()) == 2
    assert len((await client.get(f"{BASE}/conversations?all=true", headers=analyst)).json()) == 1
    detail = await client.get(f"{BASE}/conversations/{mine['id']}", headers=admin_headers)
    assert detail.status_code == 200 and detail.json()["messages"] == []
    r = await client.post(
        f"{BASE}/conversations/{mine['id']}/messages", json={"content": "hi"}, headers=admin_headers
    )
    assert r.status_code == 403

    assert (await client.delete(f"{BASE}/conversations/{mine['id']}", headers=analyst)).status_code == 204
    assert (await client.get(f"{BASE}/conversations/{mine['id']}", headers=analyst)).status_code == 404


async def test_post_message_streams_tool_loop(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    seeded: dict[str, Any],
    scripted: Callable[[list[Step]], ScriptedProvider],
) -> None:
    scripted(
        [
            tool_turn(("toolu_1", "get_session", {"session_id": seeded["session_id"]})),
            text_turn("Session sess-ai-1 looks like an autonomous agent (ai_score 0.87)."),
        ]
    )
    conv = (await client.post(f"{BASE}/conversations", json={}, headers=admin_headers)).json()
    r = await client.post(
        f"{BASE}/conversations/{conv['id']}/messages",
        json={"content": f"Summarize the AI-like session from {ATTACKER_IP}"},
        headers=admin_headers,
    )
    events = _sse_events(r)
    assert [e["type"] for e in events] == ["text", "tool_call", "tool_result", "text", "done"]
    assert events[1]["name"] == "get_session" and events[2]["ok"] is True
    assert events[-1]["stop_reason"] == "end_turn"

    detail = (await client.get(f"{BASE}/conversations/{conv['id']}", headers=admin_headers)).json()
    assert detail["conversation"]["title"].startswith("Summarize the AI-like session")
    msgs = detail["messages"]
    assert [m["role"] for m in msgs] == ["user", "assistant", "tool", "assistant"]
    assert msgs[1]["tool_calls"] == [
        {"id": "toolu_1", "name": "get_session", "input": {"session_id": "sess-ai-1"}}
    ]
    assert msgs[2]["tool_results"][0]["name"] == "get_session" and msgs[2]["tool_results"][0]["ok"] is True
    assert "autonomous agent" in msgs[3]["content"]


async def test_post_message_without_llm_returns_guidance(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    conv = (await client.post(f"{BASE}/conversations", json={}, headers=admin_headers)).json()
    r = await client.post(
        f"{BASE}/conversations/{conv['id']}/messages", json={"content": "hello"}, headers=admin_headers
    )
    events = _sse_events(r)
    assert [e["type"] for e in events] == ["text", "done"]
    assert "ANTHROPIC_API_KEY" in events[0]["text"]
    assert events[1]["stop_reason"] == "llm_not_configured"


async def test_post_message_validation_and_auth(
    client: httpx.AsyncClient, admin_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    conv = (await client.post(f"{BASE}/conversations", json={}, headers=admin_headers)).json()
    url = f"{BASE}/conversations/{conv['id']}/messages"
    assert (await client.post(url, json={"content": "   "}, headers=admin_headers)).status_code == 422
    assert (await client.post(url, json={"content": "x" * 8001}, headers=admin_headers)).status_code == 422
    assert (await client.post(url, json={"content": "hi"})).status_code == 401
    missing = f"{BASE}/conversations/does-not-exist/messages"
    assert (await client.post(missing, json={"content": "hi"}, headers=admin_headers)).status_code == 404

    monkeypatch.setenv("TOKIWA_COPILOT__ENABLED", "false")
    reset_settings_cache()
    assert (await client.post(url, json={"content": "hi"}, headers=admin_headers)).status_code == 503
