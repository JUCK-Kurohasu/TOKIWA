"""Fixtures for api-core tests: per-role users and a streaming SSE client.

httpx's ASGITransport buffers the whole response body, so it cannot read an endless SSE stream.
:class:`SSEConnection` drives the ASGI app directly in the test's event loop instead, which also lets the test
publish on the in-process bus and observe the disconnect cleanup.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest
from fastapi import FastAPI

from tokiwa.api.routes import dashboard

PASSWORD = "correct-horse-battery"

MakeUser = Callable[..., Awaitable[dict[str, str]]]


@pytest.fixture(autouse=True)
def _clear_dashboard_cache() -> None:
    dashboard.clear_cache()


@pytest.fixture
async def make_user(client: httpx.AsyncClient, admin_headers: dict[str, str]) -> MakeUser:
    """Create a user with ``role`` (as admin) and return its Authorization header."""

    async def _make(role: str, username: str | None = None) -> dict[str, str]:
        username = username or f"{role}-{uuid.uuid4().hex[:8]}"
        r = await client.post(
            "/api/v1/users",
            json={"username": username, "password": PASSWORD, "role": role},
            headers=admin_headers,
        )
        assert r.status_code == 201, r.text
        login = await client.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD})
        assert login.status_code == 200, login.text
        return {"Authorization": f"Bearer {login.json()['access_token']}"}

    return _make


@pytest.fixture
async def viewer_headers(make_user: MakeUser) -> dict[str, str]:
    return await make_user("viewer")


@pytest.fixture
async def analyst_headers(make_user: MakeUser) -> dict[str, str]:
    return await make_user("analyst")


@pytest.fixture
def role_headers(
    admin_headers: dict[str, str], analyst_headers: dict[str, str], viewer_headers: dict[str, str]
) -> dict[str, dict[str, str]]:
    return {"admin": admin_headers, "analyst": analyst_headers, "viewer": viewer_headers}


class SSEConnection:
    """Minimal streaming HTTP client for one GET request against an ASGI app."""

    def __init__(
        self,
        app: FastAPI,
        path: str,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.app = app
        self.path = path
        self.query = urlencode(params or {}).encode()
        self.request_headers = [(b"host", b"testserver"), (b"accept", b"text/event-stream")]
        self.request_headers += [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
        self.status: int | None = None
        self.headers: dict[str, str] = {}
        self._chunks: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._started = asyncio.Event()
        self._disconnect = asyncio.Event()
        self._buffer = ""
        self._task: asyncio.Task[None] | None = None

    async def __aenter__(self) -> SSEConnection:
        self._task = asyncio.create_task(self._run())
        await asyncio.wait_for(self._started.wait(), timeout=5)
        return self

    async def __aexit__(self, *exc: object) -> None:
        self._disconnect.set()
        if self._task is not None:
            await asyncio.wait_for(self._task, timeout=5)

    async def _run(self) -> None:
        scope: dict[str, Any] = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": self.path,
            "raw_path": self.path.encode(),
            "query_string": self.query,
            "root_path": "",
            "headers": self.request_headers,
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }
        request_sent = False

        async def receive() -> dict[str, Any]:
            nonlocal request_sent
            if not request_sent:
                request_sent = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await self._disconnect.wait()
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                self.status = message["status"]
                self.headers = {k.decode(): v.decode() for k, v in message.get("headers", [])}
                self._started.set()
            elif message["type"] == "http.response.body":
                if message.get("body"):
                    await self._chunks.put(message["body"])

        try:
            await self.app(scope, receive, send)  # type: ignore[arg-type]
        finally:
            self._started.set()
            await self._chunks.put(None)

    async def next_event(self, timeout: float = 5.0) -> dict[str, str]:
        """Next SSE block as ``{"comment": ..., "data": ...}`` (keys present only when set)."""
        while "\n\n" not in self._buffer:
            chunk = await asyncio.wait_for(self._chunks.get(), timeout=timeout)
            if chunk is None:
                raise EOFError("stream closed")
            self._buffer += chunk.decode().replace("\r\n", "\n")
        block, self._buffer = self._buffer.split("\n\n", 1)
        out: dict[str, str] = {}
        for line in block.split("\n"):
            if line.startswith(":"):
                out["comment"] = line[1:].strip()
            elif line.startswith("data:"):
                out["data"] = out.get("data", "") + line[5:].strip()
        return out

    async def next_message(self, timeout: float = 5.0) -> dict[str, Any]:
        """Next ``data:`` payload decoded as JSON, skipping comments (keep-alives)."""
        while True:
            ev = await self.next_event(timeout)
            if "data" in ev:
                return json.loads(ev["data"])

    async def body(self, timeout: float = 5.0) -> bytes:
        """Whole body of a finite (e.g. error) response."""
        parts: list[bytes] = []
        while (chunk := await asyncio.wait_for(self._chunks.get(), timeout=timeout)) is not None:
            parts.append(chunk)
        return b"".join(parts)


OpenSSE = Callable[..., SSEConnection]


@pytest.fixture
def open_sse(app: FastAPI) -> OpenSSE:
    def _open(
        path: str = "/api/v1/stream",
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> SSEConnection:
        return SSEConnection(app, path, params, headers)

    return _open
