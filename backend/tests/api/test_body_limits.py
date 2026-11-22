"""#57: request bodies above server.max_body_bytes / server.max_ingest_body_bytes are refused with 413."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable, Iterator

import httpx
import pytest

from tokiwa.api.middleware import BodySizeLimitMiddleware
from tokiwa.config import ServerSettings, Settings, get_settings, reset_settings_cache
from tokiwa.schemas.events import Event

SMALL = 4096
INGEST = 64 * 1024


@pytest.fixture
def settings(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """Small limits so the tests stay fast (the app reads them at creation)."""
    monkeypatch.setenv("TOKIWA_SERVER__MAX_BODY_BYTES", str(SMALL))
    monkeypatch.setenv("TOKIWA_SERVER__MAX_INGEST_BODY_BYTES", str(INGEST))
    reset_settings_cache()
    yield get_settings()


def test_defaults() -> None:
    s = ServerSettings()
    assert s.max_body_bytes == 1024 * 1024
    assert s.max_ingest_body_bytes == 32 * 1024 * 1024


async def test_declared_content_length_over_limit_is_413(client: httpx.AsyncClient) -> None:
    body = json.dumps({"username": "admin", "password": "x" * (SMALL * 2)})
    r = await client.post("/api/v1/auth/login", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 413
    assert "too large" in r.json()["detail"]


async def test_chunked_body_over_limit_is_413(client: httpx.AsyncClient) -> None:
    """No Content-Length (chunked): the bytes actually received are counted."""

    async def chunks() -> AsyncIterator[bytes]:
        yield b'{"username": "admin", "password": "'
        for _ in range(4):
            yield b"x" * SMALL
        yield b'"}'

    r = await client.post(
        "/api/v1/auth/login", content=chunks(), headers={"content-type": "application/json"}
    )
    assert r.status_code == 413
    assert "too large" in r.json()["detail"]


async def test_small_bodies_pass(client: httpx.AsyncClient) -> None:
    r = await client.post("/api/v1/auth/login", json={"username": "nobody", "password": "wrong-password"})
    assert r.status_code == 401


async def test_ingest_has_its_own_larger_limit(
    client: httpx.AsyncClient, ingest_headers: dict[str, str], make_http_event: Callable[..., Event]
) -> None:
    ev = make_http_event("/ok", body="b" * (SMALL * 2)).model_dump(mode="json")
    r = await client.post("/api/v1/ingest/events", json={"events": [ev]}, headers=ingest_headers)
    assert r.status_code == 200, r.text  # above max_body_bytes, below max_ingest_body_bytes

    too_big = make_http_event("/big", body="b" * (INGEST * 2)).model_dump(mode="json")
    r = await client.post("/api/v1/ingest/events", json={"events": [too_big]}, headers=ingest_headers)
    assert r.status_code == 413


async def test_absurd_content_length_header_is_413_not_500() -> None:
    sent: list[dict[str, object]] = []

    async def app(scope: object, receive: object, send: object) -> None:  # pragma: no cover - never reached
        raise AssertionError("app must not be called")

    mw = BodySizeLimitMiddleware(app, default_limit=SMALL)  # type: ignore[arg-type]
    scope = {"type": "http", "path": "/api/v1/x", "headers": [(b"content-length", b"9" * 5000)]}

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    await mw(scope, receive, send)  # type: ignore[arg-type]
    assert sent[0]["status"] == 413


def test_longest_prefix_wins() -> None:
    mw = BodySizeLimitMiddleware(
        lambda *a: None,  # type: ignore[arg-type]
        default_limit=1,
        prefix_limits=[("/api/", 2), ("/api/v1/ingest/", 3)],
    )
    assert mw.limit_for("/api/v1/ingest/events") == 3
    assert mw.limit_for("/api/v1/alerts") == 2
    assert mw.limit_for("/assets/x.js") == 1
