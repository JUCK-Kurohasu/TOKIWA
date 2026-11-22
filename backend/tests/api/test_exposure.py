"""#93: unknown /api/* paths are JSON 404s (not the SPA shell), docs can be turned off, /health hides the version."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from tokiwa import __version__
from tokiwa.config import ServerSettings, Settings, get_settings, reset_settings_cache

INDEX = "<!doctype html><title>TOKIWA</title><div id=root></div>"


@pytest.fixture
def static_dir(tmp_path: Path) -> Path:
    root = tmp_path / "dist"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text(INDEX)
    (root / "favicon.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'/>")
    (root / "assets" / "app.js").write_text("console.log('ok')")
    return root


@pytest.fixture
def settings(settings: Settings, static_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    monkeypatch.setenv("TOKIWA_SERVER__STATIC_DIR", str(static_dir))
    reset_settings_cache()
    yield get_settings()


async def _client_for(monkeypatch: pytest.MonkeyPatch, **env: str) -> AsyncIterator[httpx.AsyncClient]:
    from tokiwa.api.app import create_app

    for key, value in env.items():
        monkeypatch.setenv(key, value)
    reset_settings_cache()
    app: FastAPI = create_app(run_jobs=False)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
            yield c


async def test_unknown_api_path_is_json_404(client: httpx.AsyncClient) -> None:
    for path in ("/api/v1/nonexistent", "/api/v1/alerts/x/y/z", "/api", "/api/", "/api/v2/anything"):
        r = await client.get(path)
        assert r.status_code == 404, (path, r.status_code)
        assert r.headers["content-type"].startswith("application/json"), path
        assert r.json() == {"detail": "Not Found"}


async def test_spa_still_serves_ui_routes_and_files(client: httpx.AsyncClient) -> None:
    for path in ("/", "/alerts", "/incidents/abc", "/apiary", "/redoc"):
        r = await client.get(path)
        assert r.status_code == 200, path
        assert r.text == INDEX, path
    assert "svg" in (await client.get("/favicon.svg")).text
    assert (await client.get("/assets/app.js")).status_code == 200


async def test_spa_traversal_still_blocked(client: httpx.AsyncClient) -> None:
    for path in ("/..%2f..%2fetc%2fpasswd", "/%2e%2e/%2e%2e/etc/passwd", "/..%5c..%5cetc%5cpasswd"):
        r = await client.get(path)
        assert "root:" not in r.text
        assert r.status_code in (200, 404)


async def test_docs_exposed_by_default(client: httpx.AsyncClient) -> None:
    assert (
        ServerSettings().expose_docs is True
    )  # backwards compatible default (AGENTS.md / wiki link /api/docs)
    assert (await client.get("/api/docs")).status_code == 200
    assert (await client.get("/api/openapi.json")).status_code == 200
    # ReDoc is gone; /redoc is just a UI route of the SPA now.
    assert (await client.get("/redoc")).text == INDEX
    assert (await client.get("/docs/oauth2-redirect")).text == INDEX
    assert (await client.get("/api/docs/oauth2-redirect")).status_code == 200


async def test_docs_can_be_disabled(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    async for c in _client_for(monkeypatch, TOKIWA_SERVER__EXPOSE_DOCS="false"):
        for path in ("/api/docs", "/api/openapi.json", "/api/docs/oauth2-redirect"):
            r = await c.get(path)
            assert r.status_code == 404, path
            assert r.json() == {"detail": "Not Found"}
        assert (await c.get("/api/v1/health")).status_code == 200


async def test_health_hides_version_from_anonymous_callers(
    client: httpx.AsyncClient, admin_headers: dict[str, str], ingest_headers: dict[str, str]
) -> None:
    anon = await client.get("/api/v1/health")
    assert anon.status_code == 200
    assert anon.json() == {"status": "ok"}
    bad = await client.get("/api/v1/health", headers={"Authorization": "Bearer not-a-jwt"})
    assert bad.status_code == 200 and bad.json() == {"status": "ok"}
    api_token = await client.get(
        "/api/v1/health", headers={"Authorization": f"Bearer {ingest_headers['X-Tokiwa-Token']}"}
    )
    assert api_token.json() == {"status": "ok"}
    signed_in = await client.get("/api/v1/health", headers=admin_headers)
    assert signed_in.json() == {"status": "ok", "version": __version__}
