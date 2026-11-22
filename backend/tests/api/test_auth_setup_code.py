"""One-time setup code for the unauthenticated first-run setup (#95)."""

from __future__ import annotations

import stat
from pathlib import Path

import httpx
import pytest

from tokiwa.auth import setup_code
from tokiwa.auth.files import create_private_file
from tokiwa.config import Settings, reset_settings_cache

BODY = {"username": "admin", "password": "correct-horse-battery"}


def _code_file(settings: Settings) -> Path:
    return Path(settings.server.data_dir) / setup_code.FILE_NAME


async def test_setup_requires_the_code_from_the_server(client: httpx.AsyncClient, settings: Settings) -> None:
    status = (await client.get("/api/v1/auth/status")).json()
    assert status["setup_required"] is True and status["setup_code_required"] is True
    path = _code_file(settings)
    assert path.is_file(), "startup writes the code to data_dir/setup-code"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    code = path.read_text().strip()

    assert (await client.post("/api/v1/auth/setup", json=BODY)).status_code == 403
    wrong = await client.post("/api/v1/auth/setup", json={**BODY, "setup_code": "AAAA-AAAA-AAAA-AAAA"})
    assert wrong.status_code == 403
    assert (await client.get("/api/v1/auth/status")).json()["setup_required"] is True

    # Case, spaces and dashes do not matter (typed from a log line).
    typed = code.lower().replace("-", " ")
    ok = await client.post("/api/v1/auth/setup", json={**BODY, "setup_code": typed})
    assert ok.status_code == 200, ok.text
    assert not path.exists(), "the code is single-use"
    status = (await client.get("/api/v1/auth/status")).json()
    assert status == {**status, "setup_required": False, "setup_code_required": False}
    again = await client.post("/api/v1/auth/setup", json={**BODY, "setup_code": code})
    assert again.status_code == 409


async def test_startup_logs_the_setup_url(settings: Settings, caplog: pytest.LogCaptureFixture) -> None:
    from tokiwa.api.app import create_app

    app = create_app(run_jobs=False)
    with caplog.at_level("WARNING", logger="tokiwa.auth.setup_code"):
        async with app.router.lifespan_context(app):
            code = setup_code.current_setup_code()
    assert code and f"/setup#code={code}" in caplog.text
    # A restart before setup re-announces the same code instead of making a new one.
    caplog.clear()
    with caplog.at_level("WARNING", logger="tokiwa.auth.setup_code"):
        async with app.router.lifespan_context(app):
            assert setup_code.current_setup_code() == code
    assert code in caplog.text


async def test_missing_code_file_is_recreated_and_announced(
    client: httpx.AsyncClient, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    _code_file(settings).unlink()
    with caplog.at_level("WARNING", logger="tokiwa.auth.setup_code"):
        r = await client.post("/api/v1/auth/setup", json={**BODY, "setup_code": "whatever"})
    assert r.status_code == 403
    new_code = setup_code.current_setup_code()
    assert new_code and new_code in caplog.text
    ok = await client.post("/api/v1/auth/setup", json={**BODY, "setup_code": new_code})
    assert ok.status_code == 200


async def test_setup_code_can_be_disabled(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, client: httpx.AsyncClient
) -> None:
    monkeypatch.setenv("TOKIWA_AUTH__SETUP_CODE_REQUIRED", "false")
    reset_settings_cache()
    assert (await client.get("/api/v1/auth/status")).json()["setup_code_required"] is False
    assert (await client.post("/api/v1/auth/setup", json=BODY)).status_code == 200


def test_create_private_file_is_exclusive(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "secret"
    assert create_private_file(target, "first") is True
    assert create_private_file(target, "second") is False
    assert target.read_text() == "first"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
    assert [p.name for p in target.parent.iterdir()] == ["secret"], "no temp files left behind"
