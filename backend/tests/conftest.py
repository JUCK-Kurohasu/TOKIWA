"""Shared fixtures.

- ``settings``      isolated Settings (tmp data dir + sqlite file); env vars are reset per test
- ``db``            initialized database (tables created)
- ``app``/``client``  FastAPI app with lifespan + httpx AsyncClient (jobs disabled)
- ``admin_headers`` Authorization header for a freshly created admin
- ``ingest_headers`` X-Tokiwa-Token header with scopes ingest+gate
- ``mock_llm``      installs a MockProvider-backed gateway, returns the MockProvider
- ``make_http_event`` factory for HTTP events
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from tokiwa.auth import security
from tokiwa.bus import bus
from tokiwa.config import Settings, get_settings, reset_settings_cache
from tokiwa.db import session as dbsession
from tokiwa.detect.engine import reset_detection_engine
from tokiwa.llm import gateway as gw
from tokiwa.llm.mock import MockProvider
from tokiwa.pipeline.service import reset_enrichers
from tokiwa.schemas.events import Endpoint, Event, EventKind, HttpInfo
from tokiwa.util import utcnow

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    for key in list(os.environ):
        if key.startswith("TOKIWA_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("TOKIWA_ENV", "test")
    monkeypatch.setenv("TOKIWA_CONFIG", str(tmp_path / "none.yaml"))
    monkeypatch.setenv("TOKIWA_SERVER__DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("TOKIWA_DATABASE__URL", f"sqlite+aiosqlite:///{tmp_path / 'tokiwa.db'}")
    monkeypatch.setenv("TOKIWA_LLM__PROVIDER", "mock")
    monkeypatch.setenv("TOKIWA_DETECTION__SIGMA_RULE_DIRS", f'["{REPO_ROOT / "rules" / "sigma"}"]')
    reset_settings_cache()
    security.reset_secret_cache()
    reset_detection_engine()
    reset_enrichers()
    gw.set_gateway(None)
    bus.clear()
    yield get_settings()
    reset_settings_cache()
    reset_detection_engine()
    reset_enrichers()
    gw.set_gateway(None)
    bus.clear()


@pytest.fixture
async def db(settings: Settings) -> AsyncIterator[None]:
    dbsession.init_engine()
    await dbsession.create_all()
    yield
    await bus.drain()
    await dbsession.dispose_engine()


@pytest.fixture
async def app(settings: Settings) -> AsyncIterator[FastAPI]:
    from tokiwa.api.app import create_app

    application = create_app(run_jobs=False)
    async with application.router.lifespan_context(application):
        yield application
        await bus.drain()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


@pytest.fixture
async def admin_headers(client: httpx.AsyncClient) -> dict[str, str]:
    r = await client.post(
        "/api/v1/auth/setup", json={"username": "admin", "password": "correct-horse-battery"}
    )
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
async def ingest_headers(client: httpx.AsyncClient) -> dict[str, str]:
    from tokiwa.cli import _create_token

    token = await _create_token("test-sensor", ["ingest", "gate"])
    return {"X-Tokiwa-Token": token}


@pytest.fixture
def mock_llm(settings: Settings) -> MockProvider:
    provider = MockProvider()
    gw.set_gateway(gw.LLMGateway(provider=provider, settings=settings))
    return provider


@pytest.fixture
def make_http_event() -> Callable[..., Event]:
    def _make(
        path: str = "/",
        *,
        method: str = "GET",
        query: str | None = None,
        ip: str = "203.0.113.10",
        ua: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36",
        status: int = 200,
        body: str | None = None,
        headers: dict[str, str] | None = None,
        ts: datetime | None = None,
        **extra: Any,
    ) -> Event:
        return Event(
            timestamp=ts or utcnow(),
            kind=EventKind.HTTP,
            dataset="gate.http",
            source=Endpoint(ip=ip, port=50000),
            destination=Endpoint(ip="10.0.0.5", port=8080),
            http=HttpInfo(
                method=method,
                scheme="http",
                host="app.lab",
                path=path,
                query=query,
                user_agent=ua,
                status=status,
                request_body=body,
                request_body_size=len(body) if body else 0,
                headers=headers or {"user-agent": ua},
            ),
            **extra,
        )

    return _make
