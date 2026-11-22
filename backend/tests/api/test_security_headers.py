"""#66: CSP, frame, nosniff and referrer headers on UI / API / docs responses; no caching of index.html."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from tokiwa.api.middleware import API_CSP, DOCS_CSP, SPA_CSP
from tokiwa.config import Settings, get_settings, reset_settings_cache


@pytest.fixture
def settings(settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    root = tmp_path / "dist"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text("<!doctype html><div id=root></div>")
    (root / "assets" / "index-abc123.js").write_text("console.log(1)")
    monkeypatch.setenv("TOKIWA_SERVER__STATIC_DIR", str(root))
    reset_settings_cache()
    yield get_settings()


def _assert_common(r: httpx.Response) -> None:
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


async def test_spa_shell_and_assets(client: httpx.AsyncClient) -> None:
    for path in ("/", "/alerts/123", "/index.html"):
        r = await client.get(path)
        assert r.status_code == 200
        _assert_common(r)
        assert r.headers["content-security-policy"] == SPA_CSP
        assert r.headers["cache-control"] == "no-store", path
    asset = await client.get("/assets/index-abc123.js")
    _assert_common(asset)
    assert "immutable" in asset.headers["cache-control"]


def test_spa_csp_allows_no_inline_or_remote_script() -> None:
    script_src = next(d for d in SPA_CSP.split("; ") if d.startswith("script-src"))
    assert script_src == "script-src 'self'"
    assert "object-src 'none'" in SPA_CSP and "base-uri 'none'" in SPA_CSP


async def test_api_responses(client: httpx.AsyncClient, admin_headers: dict[str, str]) -> None:
    for r in (
        await client.get("/api/v1/health"),
        await client.get("/api/v1/alerts", headers=admin_headers),
        await client.get("/api/v1/nonexistent"),
        await client.get("/api/v1/alerts"),  # 401
    ):
        _assert_common(r)
        assert r.headers["content-security-policy"] == API_CSP


async def test_docs_get_the_docs_policy(client: httpx.AsyncClient) -> None:
    r = await client.get("/api/docs")
    assert r.status_code == 200
    _assert_common(r)
    assert r.headers["content-security-policy"] == DOCS_CSP
    # Every external origin the Swagger page references must be allowed by the docs policy.
    for origin in ("https://cdn.jsdelivr.net", "https://fastapi.tiangolo.com"):
        if origin in r.text:
            assert origin in DOCS_CSP
    oauth = await client.get("/api/docs/oauth2-redirect")
    assert oauth.headers["content-security-policy"] == DOCS_CSP


async def test_route_set_headers_are_not_overridden(client: httpx.AsyncClient) -> None:
    """The middleware only fills in missing headers (e.g. SSE keeps its own Cache-Control)."""
    r = await client.get("/")
    assert r.headers.get_list("cache-control") == ["no-store"]
    assert len(r.headers.get_list("content-security-policy")) == 1


async def test_413_also_carries_headers(client: httpx.AsyncClient) -> None:
    r = await client.post(
        "/api/v1/auth/login",
        content=b"x" * (2 * 1024 * 1024),
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 413
    _assert_common(r)


async def test_headers_can_be_turned_off(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    from tokiwa.api.app import create_app

    monkeypatch.setenv("TOKIWA_SERVER__SECURITY_HEADERS", "false")
    reset_settings_cache()
    app = create_app(run_jobs=False)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://t") as c,
    ):
        r = await c.get("/api/v1/health")
    assert "content-security-policy" not in r.headers
    assert "x-frame-options" not in r.headers
