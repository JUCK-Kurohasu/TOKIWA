"""JWT signing key and data-dir file permissions (#102)."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest
from pydantic import ValidationError

from tokiwa.auth import security
from tokiwa.config import Settings, get_settings, reset_settings_cache
from tokiwa.db import session as dbsession


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_generated_key_file_is_private_from_the_start(settings: Settings) -> None:
    data_dir = Path(settings.server.data_dir)
    assert not data_dir.exists()
    key = security.secret_key()
    path = data_dir / "secret.key"
    assert len(key) >= 32 and path.read_text().strip() == key
    assert _mode(path) == 0o600
    assert _mode(data_dir) == 0o700, "a data dir created by TOKIWA is private"
    assert sorted(p.name for p in data_dir.iterdir()) == ["secret.key"], "no temp file left behind"
    # Restart: the same key is read back.
    security.reset_secret_cache()
    assert security.secret_key() == key


def test_existing_data_dir_mode_is_left_alone(settings: Settings) -> None:
    data_dir = Path(settings.server.data_dir)
    data_dir.mkdir(mode=0o750)
    data_dir.chmod(0o750)  # e.g. the Docker image's /data
    security.secret_key()
    assert _mode(data_dir) == 0o750


def test_empty_env_key_means_unset(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOKIWA_SERVER__SECRET_KEY", "")
    reset_settings_cache()
    assert get_settings().server.secret_key is None
    assert security.secret_key() == (Path(settings.server.data_dir) / "secret.key").read_text().strip()


def test_short_configured_key_is_refused(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOKIWA_SERVER__SECRET_KEY", "changeme")
    reset_settings_cache()
    with pytest.raises(ValidationError, match="at least 32 characters"):
        get_settings()


def test_long_configured_key_is_used_verbatim(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    key = "k" * 40 + " "
    monkeypatch.setenv("TOKIWA_SERVER__SECRET_KEY", key)
    reset_settings_cache()
    assert security.secret_key() == key
    assert not (Path(settings.server.data_dir) / "secret.key").exists()


def test_empty_key_file_is_an_error_not_a_silent_new_key(settings: Settings) -> None:
    path = Path(settings.server.data_dir) / "secret.key"
    path.parent.mkdir(parents=True)
    path.write_text("")
    with pytest.raises(RuntimeError, match="is empty"):
        security.secret_key()


async def test_new_sqlite_database_file_is_private(settings: Settings, tmp_path: Path) -> None:
    db_path = tmp_path / "fresh" / "tokiwa.db"
    dbsession.init_engine(f"sqlite+aiosqlite:///{db_path}")
    try:
        await dbsession.create_all()
    finally:
        await dbsession.dispose_engine()
    assert _mode(db_path) == 0o600
    assert _mode(db_path.parent) == 0o700
