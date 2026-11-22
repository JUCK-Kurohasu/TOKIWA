"""Copilot tool runs are recorded in the read-access log (audit #167)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

from .conftest import ScriptedProvider, Step, text_turn, tool_turn

BASE = "/api/v1/copilot"


async def test_tool_runs_are_access_logged(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    seeded: dict[str, Any],
    scripted: Callable[[list[Step]], ScriptedProvider],
) -> None:
    scripted(
        [
            tool_turn(("toolu_1", "get_session", {"session_id": seeded["session_id"]})),
            text_turn("done"),
        ]
    )
    conv = (await client.post(f"{BASE}/conversations", json={}, headers=admin_headers)).json()
    r = await client.post(
        f"{BASE}/conversations/{conv['id']}/messages",
        json={"content": "what happened?"},
        headers=admin_headers,
    )
    assert r.status_code == 200
    rows = (
        await client.get("/api/v1/audit/access", params={"route": "copilot.tool.*"}, headers=admin_headers)
    ).json()["items"]
    assert len(rows) == 1
    assert rows[0]["route"] == "copilot.tool.get_session" and rows[0]["actor"] == "admin"
    assert rows[0]["filters"]["session_id"] == seeded["session_id"]  # what was looked up
