"""#172: UI overrides vs env / YAML - pinning (llm.allow_ui_override), startup warning, reset."""

from __future__ import annotations

import logging

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select

from tokiwa.config import Settings, reset_settings_cache
from tokiwa.db.models.core import AuditRow
from tokiwa.db.session import session_scope
from tokiwa.llm import gateway as gw
from tokiwa.llm import settings as llm_settings
from tokiwa.llm.settings import LLMConfigUpdate, UIOverrideLockedError, apply_overlay
from tokiwa.settings_store import get_setting, set_setting

SECRET = "sk-ant-api03-OVERRIDE-SECRET-VALUE-000000000"
STORED = {
    "provider": "openai_compat",
    "openai_base_url": "http://127.0.0.1:22849/v1",  # unused local port: nothing is sent anywhere
    "model_fast": "claude-haiku-5-5",  # same as the static default -> not "different"
    "anthropic_api_key": SECRET,
}


def _pin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restart-equivalent: the operator sets TOKIWA_LLM__ALLOW_UI_OVERRIDE=false (and provider=mock is already set)."""
    monkeypatch.setenv("TOKIWA_LLM__ALLOW_UI_OVERRIDE", "false")
    reset_settings_cache()
    gw.set_gateway(None)


def test_pinned_settings_ignore_the_overlay(settings: Settings) -> None:
    pinned = settings.model_copy(update={"llm": settings.llm.model_copy(update={"allow_ui_override": False})})
    assert apply_overlay(pinned, STORED) is pinned
    assert apply_overlay(settings, STORED).llm.provider == "openai_compat"
    # The flag itself can never come from the UI / the database.
    with pytest.raises(ValueError):
        LLMConfigUpdate.model_validate({"allow_ui_override": True})
    assert apply_overlay(pinned, {"allow_ui_override": True, "provider": "anthropic"}) is pinned
    assert "allow_ui_override" not in llm_settings.clean_overlay(settings.llm, {"allow_ui_override": False})


@pytest.mark.usefixtures("db")
async def test_env_pin_survives_restart_with_old_overrides(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The audit repro: provider=mock in env, openai_compat saved from the UI, restart -> mock must win when pinned."""
    await set_setting(llm_settings.LLM_CONFIG_KEY, dict(STORED))
    await llm_settings.apply_stored_config()
    assert (
        gw.get_gateway().provider.name == "openai_compat"
    )  # default: UI overrides win (backward compatible)

    _pin(monkeypatch)
    with caplog.at_level(logging.WARNING, logger="tokiwa.llm.settings"):
        await llm_settings.apply_stored_config()
    assert gw.get_gateway().provider.name == "mock"
    assert "ignoring LLM settings saved from the UI" in caplog.text
    assert SECRET not in caplog.text and "22849" not in caplog.text

    view = await llm_settings.config_view()
    assert view.ui_override_allowed is False
    assert view.active_provider == "mock" and view.overridden == []
    assert set(view.ignored_overrides) == set(STORED)
    assert view.anthropic_api_key_set is False

    with pytest.raises(UIOverrideLockedError):
        await llm_settings.update_config(LLMConfigUpdate(provider="anthropic"))


@pytest.mark.usefixtures("db")
async def test_startup_warns_about_fields_that_differ_by_name_only(
    settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    await set_setting(llm_settings.LLM_CONFIG_KEY, dict(STORED))
    with caplog.at_level(logging.WARNING, logger="tokiwa.llm.settings"):
        await llm_settings.apply_stored_config()
    warning = next(r.getMessage() for r in caplog.records if "override the environment" in r.getMessage())
    assert "provider" in warning and "openai_base_url" in warning and "anthropic_api_key" in warning
    assert "model_fast" not in warning  # same value as the static setting
    assert SECRET not in caplog.text and "127.0.0.1" not in caplog.text


async def test_reset_and_lock_over_http(
    client: httpx.AsyncClient, admin_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    r = await client.put(
        "/api/v1/llm/config",
        headers=admin_headers,
        json={
            "provider": "openai_compat",
            "openai_base_url": "http://localhost:22849/v1",
            "anthropic_api_key": SECRET,
        },
    )
    assert r.status_code == 200, r.text
    assert set(r.json()["overridden"]) == {"provider", "openai_base_url", "anthropic_api_key"}
    assert r.json()["ui_override_allowed"] is True

    r = await client.delete("/api/v1/llm/config", headers=admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["overridden"] == [] and r.json()["active_provider"] == "mock"
    assert await get_setting(llm_settings.LLM_CONFIG_KEY) == {}
    async with session_scope() as session:
        audit = (
            (await session.execute(select(AuditRow).where(AuditRow.action == "llm.config.reset")))
            .scalars()
            .one()
        )
    assert audit.actor == "admin"
    assert audit.details["cleared"] == ["anthropic_api_key", "openai_base_url", "provider"]
    assert SECRET not in str(audit.details)

    # Pinned by env: the UI can no longer change LLM settings, but stale rows can still be cleared.
    await set_setting(llm_settings.LLM_CONFIG_KEY, {"provider": "anthropic", "anthropic_api_key": SECRET})
    _pin(monkeypatch)
    r = await client.put("/api/v1/llm/config", headers=admin_headers, json={"provider": "anthropic"})
    assert r.status_code == 409
    assert "allow_ui_override" in r.json()["detail"]
    r = await client.get("/api/v1/llm/config", headers=admin_headers)
    assert r.json()["ui_override_allowed"] is False
    assert set(r.json()["ignored_overrides"]) == {"provider", "anthropic_api_key"}
    r = await client.delete("/api/v1/llm/config", headers=admin_headers)
    assert r.status_code == 200 and r.json()["ignored_overrides"] == []


async def test_reset_requires_admin(client: httpx.AsyncClient, admin_headers: dict[str, str]) -> None:
    from tokiwa.auth.security import create_access_token, hash_password
    from tokiwa.db.models.core import UserRow
    from tokiwa.util import new_id

    uid = new_id()
    async with session_scope() as session:
        session.add(
            UserRow(id=uid, username="analyst1", password_hash=hash_password("x" * 12), role="analyst")
        )
    token, _ = create_access_token(uid, "analyst1", "analyst")
    r = await client.delete("/api/v1/llm/config", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert (await client.delete("/api/v1/llm/config")).status_code == 401


@pytest.mark.usefixtures("db")
async def test_update_still_works_when_allowed(settings: Settings) -> None:
    gateway, _ = await llm_settings.update_config(LLMConfigUpdate(anthropic_api_key=SecretStr(SECRET)))
    assert gateway.settings.llm.allow_ui_override is True
    assert (await llm_settings.config_view(gateway)).overridden == ["anthropic_api_key"]
