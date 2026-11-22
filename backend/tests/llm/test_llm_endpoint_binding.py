"""#98: a stored API key is only ever sent to the endpoint it was entered for, and runtime endpoints are restricted."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from tokiwa.config import Settings, anthropic_api_key
from tokiwa.llm import gateway as gw
from tokiwa.llm import settings as llm_settings
from tokiwa.llm.endpoints import validate_runtime_base_url
from tokiwa.llm.openai_compat import OpenAICompatProvider
from tokiwa.llm.settings import KEY_BINDINGS, LLMConfigUpdate, apply_overlay
from tokiwa.settings_store import get_setting, set_setting

ENV_KEY = "sk-ant-api03-ENVKEY-not-for-attackers-000000"
UI_KEY = "sk-ant-api03-UIKEY-entered-for-this-host-0000"


@pytest.mark.parametrize(
    "url",
    [
        "https://api.anthropic.com",
        "https://llm.internal.example:8443/v1",
        "https://10.0.0.5/v1",  # private address over https: allowed (LAN inference server)
        "http://localhost:11434/v1",
        "http://127.0.0.1:8000",
        "http://[::1]:8000/v1",
    ],
)
def test_allowed_runtime_endpoints(url: str) -> None:
    assert validate_runtime_base_url(url + "/") == url


@pytest.mark.parametrize(
    "url",
    [
        "http://attacker.example",  # plain http to a non-loopback host (key in clear text)
        "http://ollama:11434/v1",  # compose service name: must come from env / YAML
        "http://10.0.0.5:11434/v1",
        "https://169.254.169.254/latest/meta-data",
        "https://169.254.10.1",
        "https://[fe80::1]/",
        "https://[::ffff:169.254.169.254]/",
        "https://2852039166/",  # 169.254.169.254 as one decimal number
        "https://0xa9.0xfe.0xa9.0xfe/",
        "https://0251.0376.0251.0376/",
        "https://169.254.43518/",
        "https://[fd00:ec2::254]/",
        "https://100.100.100.200/",
        "https://metadata.google.internal/computeMetadata/v1",
        "https://METADATA.GOOGLE.INTERNAL./",
        "https://0.0.0.0:8080",
        "https://224.0.0.1/",
        "file:///etc/passwd",
        "ftp://example.com",
        "https:///nohost",
        "https://example.com:notaport/",
    ],
)
def test_refused_runtime_endpoints(url: str) -> None:
    with pytest.raises(ValueError):
        validate_runtime_base_url(url)
    with pytest.raises(ValueError):
        LLMConfigUpdate.model_validate({"anthropic_base_url": url})


def test_stored_rows_are_revalidated(settings: Settings) -> None:
    """A row written before #98 (or straight into the DB) with a forbidden URL is ignored, not applied."""
    eff = apply_overlay(
        settings, {"openai_base_url": "http://169.254.169.254/v1", "model_fast": "claude-haiku-5-5"}
    )
    assert eff.llm.openai_base_url == settings.llm.openai_base_url
    assert eff.llm.model_fast == "claude-haiku-5-5"


def test_runtime_endpoint_blanks_static_and_env_keys(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", ENV_KEY)
    static = settings.model_copy(
        update={"llm": settings.llm.model_copy(update={"openai_api_key": SecretStr("static-openai-key")})}
    )
    assert anthropic_api_key(static) == ENV_KEY
    eff = apply_overlay(
        static,
        {"anthropic_base_url": "https://evil.example", "openai_base_url": "https://evil.example/v1"},
    )
    assert anthropic_api_key(eff) is None  # no fallback to ANTHROPIC_API_KEY either
    assert eff.llm.openai_api_key is not None and eff.llm.openai_api_key.get_secret_value() == ""
    assert "Authorization" not in OpenAICompatProvider(eff)._headers()


def test_legacy_rows_with_unbound_keys_fail_closed(settings: Settings) -> None:
    # Pre-#98 row: runtime URL + key, no binding -> the key is ignored until entered again.
    eff = apply_overlay(
        settings, {"anthropic_base_url": "https://proxy.example", "anthropic_api_key": UI_KEY}
    )
    assert anthropic_api_key(eff) is None
    # Pre-#98 row with only a key (static endpoint) keeps working.
    eff = apply_overlay(settings, {"anthropic_api_key": UI_KEY})
    assert anthropic_api_key(eff) == UI_KEY
    # A key bound to another URL is never used with this one.
    eff = apply_overlay(
        settings,
        {
            "anthropic_base_url": "https://evil.example",
            "anthropic_api_key": UI_KEY,
            KEY_BINDINGS: {"anthropic_api_key": "https://proxy.example"},
        },
    )
    assert anthropic_api_key(eff) is None


@pytest.mark.usefixtures("db")
async def test_changing_the_endpoint_drops_the_stored_key(settings: Settings) -> None:
    gateway, changes = await llm_settings.update_config(
        LLMConfigUpdate(anthropic_api_key=SecretStr(UI_KEY), provider="anthropic")
    )
    assert anthropic_api_key(gateway.settings) == UI_KEY
    stored = await get_setting(llm_settings.LLM_CONFIG_KEY)
    assert stored[KEY_BINDINGS] == {"anthropic_api_key": ""}

    gateway, changes = await llm_settings.update_config(
        LLMConfigUpdate(anthropic_base_url="https://attacker.example")
    )
    assert changes["anthropic_api_key"].startswith("cleared")
    assert anthropic_api_key(gateway.settings) is None
    assert not gateway.provider.available()
    stored = await get_setting(llm_settings.LLM_CONFIG_KEY)
    assert "anthropic_api_key" not in stored and KEY_BINDINGS not in stored
    view = await llm_settings.config_view(gateway)
    assert view.api_key_rebind_required == ["anthropic"]
    assert view.anthropic_api_key_set is False

    # Re-entering the key for the new endpoint binds it to that endpoint.
    gateway, _ = await llm_settings.update_config(LLMConfigUpdate(anthropic_api_key=SecretStr(UI_KEY)))
    assert anthropic_api_key(gateway.settings) == UI_KEY
    assert (await get_setting(llm_settings.LLM_CONFIG_KEY))[KEY_BINDINGS] == {
        "anthropic_api_key": "https://attacker.example"
    }
    assert (await llm_settings.config_view(gateway)).api_key_rebind_required == []

    # Endpoint + key in one update: the new key is kept and bound.
    gateway, changes = await llm_settings.update_config(
        LLMConfigUpdate(anthropic_base_url="https://proxy.example", anthropic_api_key=SecretStr(UI_KEY))
    )
    assert changes["anthropic_api_key"] == "set"
    assert anthropic_api_key(gateway.settings) == UI_KEY

    # Reverting the endpoint (null) also drops the key that was entered for the runtime endpoint.
    gateway, changes = await llm_settings.update_config(
        LLMConfigUpdate.model_validate({"anthropic_base_url": None})
    )
    assert changes["anthropic_api_key"].startswith("cleared")
    assert anthropic_api_key(gateway.settings) is None


@pytest.mark.usefixtures("db")
async def test_unchanged_endpoint_keeps_the_key(settings: Settings) -> None:
    await llm_settings.update_config(
        LLMConfigUpdate(openai_base_url="https://llm.example/v1", openai_api_key=SecretStr("k-123"))
    )
    gateway, changes = await llm_settings.update_config(
        LLMConfigUpdate(openai_base_url="https://llm.example/v1/", model_fast="local-model")
    )
    assert "openai_api_key" not in changes
    key = gateway.settings.llm.openai_api_key
    assert key is not None and key.get_secret_value() == "k-123"


async def test_connection_test_never_sends_the_env_key_to_a_new_endpoint(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The audit scenario: keep the key, point base_url at an attacker host, press "connection test"."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", ENV_KEY)
    built: list[dict[str, Any]] = []

    class NoNetworkClient:
        def __init__(self, **kwargs: Any) -> None:
            built.append(kwargs)
            raise AssertionError("an Anthropic client must not be built for an unbound endpoint")

    monkeypatch.setattr("tokiwa.llm.anthropic_provider.AsyncAnthropic", NoNetworkClient)
    r = await client.put(
        "/api/v1/llm/config",
        headers=admin_headers,
        json={"provider": "anthropic", "anthropic_base_url": "https://attacker.example"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["api_key_rebind_required"] == ["anthropic"]
    assert r.json()["available"] is False
    r = await client.post("/api/v1/llm/test", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["ok"] is False and "not configured" in (r.json()["error"] or "")
    assert built == []
    assert ENV_KEY not in r.text

    # http:// to a non-loopback host and metadata addresses are refused at the API.
    for url in ("http://attacker.example", "https://169.254.169.254"):
        r = await client.put("/api/v1/llm/config", headers=admin_headers, json={"openai_base_url": url})
        assert r.status_code == 422, url


@pytest.mark.usefixtures("db")
async def test_startup_ignores_a_tampered_row(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", ENV_KEY)
    await set_setting(
        llm_settings.LLM_CONFIG_KEY,
        {
            "provider": "anthropic",
            "anthropic_base_url": "http://attacker.example",
            "anthropic_api_key": UI_KEY,
        },
    )
    await llm_settings.apply_stored_config()
    eff = gw.get_gateway().settings
    assert eff.llm.anthropic_base_url is None  # forbidden URL ignored -> static endpoint
    assert anthropic_api_key(eff) == UI_KEY  # legacy unbound key + static endpoint: still usable
