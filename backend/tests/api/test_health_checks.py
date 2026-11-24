"""#177: /health reports a Sigma rule set that silently detects nothing - to signed-in users only.

Unauthenticated callers (Docker HEALTHCHECK, load balancers, scanners) keep getting ``{"status": "ok"}`` with 200:
a restart cannot fix a missing rule directory, and "Sigma is off" is not something to tell an anonymous caller.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from tokiwa.config import Settings, reset_settings_cache
from tokiwa.detect.engine import reset_detection_engine


def _env(monkeypatch: pytest.MonkeyPatch, key: str, value: str) -> None:
    """Change a setting before the app (requested after this fixture) starts."""
    monkeypatch.setenv(key, value)
    reset_settings_cache()
    reset_detection_engine()


@pytest.fixture
def missing_sigma_dir(settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[str]:
    path = str(tmp_path / "no-such-rules")
    _env(monkeypatch, "TOKIWA_DETECTION__SIGMA_RULE_DIRS", f'["{path}"]')
    yield path


@pytest.fixture
def empty_sigma_dir(settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[str]:
    path = tmp_path / "empty-rules"
    path.mkdir()
    (path / "broken.yml").write_text("title: [unclosed\n", encoding="utf-8")
    _env(monkeypatch, "TOKIWA_DETECTION__SIGMA_RULE_DIRS", f'["{path}"]')
    yield str(path)


@pytest.fixture
def sigma_disabled(settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    _env(monkeypatch, "TOKIWA_DETECTION__SIGMA_RULE_DIRS", f'["{tmp_path / "gone"}"]')
    _env(monkeypatch, "TOKIWA_DETECTION__DISABLED_DETECTORS", '["sigma"]')
    yield


async def _anonymous_is_plain_ok(client: httpx.AsyncClient) -> None:
    r = await client.get("/api/v1/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


async def test_shipped_rules_are_ok(
    client: httpx.AsyncClient, admin_headers: dict[str, str], viewer_headers: dict[str, str]
) -> None:
    body = (await client.get("/api/v1/health", headers=admin_headers)).json()
    sigma = body["checks"]["sigma"]
    assert body["status"] == "ok" and sigma["status"] == "ok"
    assert sigma["missing_dirs"] == 0 and sigma["file_rules_found"] >= 20
    assert sigma["file_rules_active"] == sigma["file_rules_found"]
    viewer = (await client.get("/api/v1/health", headers=viewer_headers)).json()
    assert viewer["checks"]["sigma"]["status"] == "ok"
    await _anonymous_is_plain_ok(client)


async def test_missing_rule_dir_is_degraded_for_signed_in_users_only(
    missing_sigma_dir: str,
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    r = await client.get("/api/v1/health", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "degraded"
    sigma = body["checks"]["sigma"]
    assert sigma["status"] == "degraded" and sigma["missing_dirs"] == 1 and sigma["file_rules_found"] == 0
    assert sigma["missing_dir_paths"] == [missing_sigma_dir]  # admins see where it looked
    viewer = (await client.get("/api/v1/health", headers=viewer_headers)).json()
    assert viewer["status"] == "degraded" and "missing_dir_paths" not in viewer["checks"]["sigma"]
    await _anonymous_is_plain_ok(client)


async def test_directory_without_valid_rules_is_degraded(
    empty_sigma_dir: str, client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    body = (await client.get("/api/v1/health", headers=admin_headers)).json()
    sigma = body["checks"]["sigma"]
    assert body["status"] == "degraded" and sigma["status"] == "degraded"
    assert sigma["missing_dirs"] == 0 and sigma["file_rules_found"] == 0 and sigma["file_rules_invalid"] == 1
    await _anonymous_is_plain_ok(client)


async def test_disabled_sigma_detector_is_not_degraded(
    sigma_disabled: None, client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    body = (await client.get("/api/v1/health", headers=admin_headers)).json()
    assert body["status"] == "ok" and body["checks"]["sigma"]["status"] == "disabled"


async def test_builtin_rule_disabled_by_an_operator_is_not_missing(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    rules = (await client.get("/api/v1/rules", params={"limit": 200}, headers=admin_headers)).json()
    items = rules["items"] if isinstance(rules, dict) else rules
    builtin = next(r for r in items if r.get("source") == "builtin")
    r = await client.patch(
        f"/api/v1/rules/{builtin['id']}", json={"status": "disabled"}, headers=admin_headers
    )
    assert r.status_code == 200, r.text
    sigma = (await client.get("/api/v1/health", headers=admin_headers)).json()["checks"]["sigma"]
    assert sigma["status"] == "ok"
    assert sigma["file_rules_active"] == sigma["file_rules_found"] - 1
