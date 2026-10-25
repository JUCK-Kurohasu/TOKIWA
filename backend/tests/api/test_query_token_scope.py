"""The ?access_token= query form must only work on the SSE stream (JWT leakage into logs otherwise)."""

from __future__ import annotations

import httpx


async def test_query_token_rejected_on_regular_endpoints(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    token = admin_headers["Authorization"].split(" ", 1)[1]
    assert (await client.get("/api/v1/auth/me", headers=admin_headers)).status_code == 200
    r = await client.get("/api/v1/auth/me", params={"access_token": token})
    assert r.status_code == 401
