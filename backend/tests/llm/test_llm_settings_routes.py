"""Runtime config overlay (llm/settings.py) and the /api/v1/llm routes."""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select

from tokiwa.auth.security import create_access_token, hash_password
from tokiwa.config import Settings
from tokiwa.db.models.core import AuditRow, UserRow
from tokiwa.db.models.llm import LLMCallRow
from tokiwa.db.session import session_scope
from tokiwa.llm import gateway as gw
from tokiwa.llm import settings as llm_settings
from tokiwa.llm.settings import LLMConfigUpdate, apply_overlay, mask_url
from tokiwa.settings_store import get_setting, set_setting
from tokiwa.util import new_id, utcnow

SECRET = "sk-ant-api03-SUPERSECRETVALUE-0123456789"

# --------------------------------------------------------------------------- pure overlay


def test_apply_overlay_merges_and_ignores_garbage(settings: Settings) -> None:
    eff = apply_overlay(
        settings,
        {
            "model_fast": "claude-haiku-5-5",
            "model_deep": "claude-sonnet-5-5",
            "daily_budget_usd": 12.5,
            "effort_deep": "nonsense",  # invalid -> ignored
            "database": {"url": "x"},  # not an LLM field -> ignored
            "anthropic_api_key": SECRET,
            "openai_base_url": None,  # null -> not overridden
        },
    )
    assert eff.llm.model_deep == "claude-sonnet-5-5"
    assert eff.llm.daily_budget_usd == 12.5
    assert eff.llm.effort_deep == settings.llm.effort_deep
    assert isinstance(eff.llm.anthropic_api_key, SecretStr)
    assert eff.llm.anthropic_api_key.get_secret_value() == SECRET
    assert eff.database == settings.database
    assert settings.llm.daily_budget_usd != 12.5  # base untouched
    assert apply_overlay(settings, {}) is settings


def test_mask_url() -> None:
    assert mask_url("http://user:pw@llm.lab:8000/v1") == "http://[REDACTED]@llm.lab:8000/v1"
    assert mask_url("http://llm.lab:8000") == "http://llm.lab:8000"
    assert mask_url(None) is None


def test_update_model_rejects_unknown_and_bad_values() -> None:
    with pytest.raises(ValueError):
        LLMConfigUpdate.model_validate({"temperature": 0.2})
    with pytest.raises(ValueError):
        LLMConfigUpdate.model_validate({"openai_base_url": "file:///etc/passwd"})
    with pytest.raises(ValueError):
        LLMConfigUpdate.model_validate({"daily_budget_usd": -1})


@pytest.mark.usefixtures("db")
async def test_update_persists_and_rebuilds_gateway(settings: Settings) -> None:
    gateway, changes = await llm_settings.update_config(
        LLMConfigUpdate(
            model_fast="claude-haiku-5-5", daily_budget_usd=3.0, anthropic_api_key=SecretStr(SECRET)
        )
    )
    assert gw.get_gateway() is gateway
    assert gateway.llm.daily_budget_usd == 3.0
    assert changes["anthropic_api_key"] == "set"
    assert SECRET not in repr(changes)
    stored = await get_setting(llm_settings.LLM_CONFIG_KEY)
    assert stored["daily_budget_usd"] == 3.0
    # null reverts / clears
    gateway, changes = await llm_settings.update_config(
        LLMConfigUpdate.model_validate({"daily_budget_usd": None, "anthropic_api_key": ""})
    )
    assert gateway.llm.daily_budget_usd == settings.llm.daily_budget_usd
    assert gateway.llm.anthropic_api_key is None
    assert changes == {"daily_budget_usd": "reverted", "anthropic_api_key": "cleared"}


@pytest.mark.usefixtures("db")
async def test_startup_hook_only_rebuilds_with_overlay(settings: Settings) -> None:
    sentinel = gw.LLMGateway(settings=settings)
    gw.set_gateway(sentinel)
    await llm_settings.apply_stored_config()
    assert gw.get_gateway() is sentinel  # no overlay -> explicitly installed gateway kept

    await set_setting(llm_settings.LLM_CONFIG_KEY, {"model_deep": "claude-sonnet-5-5"})
    await llm_settings.apply_stored_config()
    assert gw.get_gateway() is not sentinel
    assert gw.get_gateway().llm.model_deep == "claude-sonnet-5-5"


# --------------------------------------------------------------------------- routes


async def _headers_for(role: str, username: str) -> dict[str, str]:
    uid = new_id()
    async with session_scope() as session:
        session.add(UserRow(id=uid, username=username, password_hash=hash_password("x" * 12), role=role))
    token, _ = create_access_token(uid, username, role)
    return {"Authorization": f"Bearer {token}"}


async def test_config_get_put_never_returns_keys(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.get("/api/v1/llm/config", headers=admin_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["provider"] == "mock" and body["active_provider"] == "mock"
    assert body["available"] is True
    assert body["anthropic_api_key_set"] is False

    r = await client.put(
        "/api/v1/llm/config",
        headers=admin_headers,
        json={
            "anthropic_api_key": SECRET,
            "openai_api_key": "local-secret-xyz",
            "model_deep": "claude-sonnet-5-5",
            "effort_deep": "high",
            "output_language": "en",
        },
    )
    assert r.status_code == 200, r.text
    assert SECRET not in r.text and "local-secret-xyz" not in r.text
    body = r.json()
    assert body["anthropic_api_key_set"] is True
    assert body["openai_api_key_set"] is True
    assert body["model_deep"] == "claude-sonnet-5-5"
    assert body["effort_deep"] == "high"
    assert body["output_language"] == "en"
    assert set(body["overridden"]) >= {"anthropic_api_key", "model_deep", "effort_deep", "output_language"}
    assert gw.get_gateway().llm.model_deep == "claude-sonnet-5-5"

    r = await client.get("/api/v1/llm/config", headers=admin_headers)
    assert SECRET not in r.text and "local-secret-xyz" not in r.text

    async with session_scope() as session:
        audits = list(
            (await session.execute(select(AuditRow).where(AuditRow.action == "llm.config.update"))).scalars()
        )
    assert len(audits) == 1
    assert audits[0].actor == "admin"
    assert audits[0].details["changes"]["anthropic_api_key"] == "set"
    assert SECRET not in str(audits[0].details)

    # unknown fields are rejected (e.g. sampling params)
    r = await client.put("/api/v1/llm/config", headers=admin_headers, json={"temperature": 0.1})
    assert r.status_code == 422


async def test_switching_to_anthropic_provider_has_no_network_side_effects(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    r = await client.put(
        "/api/v1/llm/config",
        headers=admin_headers,
        json={"provider": "anthropic", "anthropic_api_key": SECRET},
    )
    assert r.status_code == 200, r.text
    assert r.json()["active_provider"] == "anthropic"
    assert r.json()["available"] is True
    assert SECRET not in r.text


async def test_put_config_requires_admin(client: httpx.AsyncClient, admin_headers: dict[str, str]) -> None:
    viewer = await _headers_for("viewer", "viewer1")
    assert (await client.get("/api/v1/llm/config", headers=viewer)).status_code == 200
    r = await client.put("/api/v1/llm/config", headers=viewer, json={"daily_budget_usd": 100})
    assert r.status_code == 403
    assert (await client.post("/api/v1/llm/test", headers=viewer)).status_code == 403
    assert (await client.get("/api/v1/llm/config")).status_code == 401


async def _insert_call(**kw: object) -> str:
    values: dict[str, object] = {
        "id": new_id(),
        "created_at": utcnow(),
        "provider": "anthropic",
        "model": "claude-haiku-5-5",
        "tier": "fast",
        "purpose": "triage",
        "prompt_version": "triage@1",
        "status": "ok",
        "input_tokens": 100,
        "output_tokens": 10,
        "cost_usd": 0.01,
        "related": {"alert_id": "a1"},
        "request_redacted": "[system]\nsys\n\n[user]\nredacted input",
        "response_text": "{}",
    }
    values.update(kw)
    async with session_scope() as session:
        session.add(LLMCallRow(**values))
    return str(values["id"])


async def test_usage_aggregates_by_day_and_purpose(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    now = utcnow()
    await _insert_call(cost_usd=0.5, purpose="triage")
    await _insert_call(cost_usd=0.25, purpose="advisory", input_tokens=1000, output_tokens=200)
    await _insert_call(cost_usd=1.0, purpose="triage", created_at=now - timedelta(days=1))
    await _insert_call(cost_usd=9.0, purpose="triage", created_at=now - timedelta(days=30))  # out of range

    r = await client.get("/api/v1/llm/usage?days=3", headers=admin_headers)
    assert r.status_code == 200, r.text
    days = r.json()["days"]
    assert [d["date"] for d in days] == [
        (now - timedelta(days=2)).date().isoformat(),
        (now - timedelta(days=1)).date().isoformat(),
        now.date().isoformat(),
    ]
    assert days[0]["calls"] == 0 and days[0]["cost_usd"] == 0
    assert days[1]["by_purpose"] == {"triage": 1.0}
    today = days[2]
    assert today["calls"] == 2
    assert today["cost_usd"] == pytest.approx(0.75)
    assert today["input_tokens"] == 1100 and today["output_tokens"] == 210
    assert today["by_purpose"] == {"advisory": 0.25, "triage": 0.5}
    assert today["by_purpose_calls"] == {"advisory": 1, "triage": 1}


async def test_calls_list_filter_and_detail(client: httpx.AsyncClient, admin_headers: dict[str, str]) -> None:
    await _insert_call(purpose="triage", status="ok")
    refused_id = await _insert_call(purpose="triage", status="refused", error="refusal: category=cyber")
    await _insert_call(purpose="copilot", status="ok")

    r = await client.get("/api/v1/llm/calls", headers=admin_headers)
    page = r.json()
    assert page["total"] == 3 and page["limit"] == 50 and page["offset"] == 0
    assert "request_redacted" not in page["items"][0]  # detail-only field

    r = await client.get("/api/v1/llm/calls?purpose=triage&status=refused", headers=admin_headers)
    page = r.json()
    assert page["total"] == 1 and page["items"][0]["id"] == refused_id

    r = await client.get("/api/v1/llm/calls?limit=1&offset=1", headers=admin_headers)
    assert len(r.json()["items"]) == 1 and r.json()["total"] == 3

    r = await client.get(f"/api/v1/llm/calls/{refused_id}", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["request_redacted"].endswith("redacted input")
    assert (await client.get("/api/v1/llm/calls/nope", headers=admin_headers)).status_code == 404

    analyst = await _headers_for("analyst", "analyst1")
    assert (await client.get("/api/v1/llm/calls", headers=analyst)).status_code == 200
    assert (await client.get(f"/api/v1/llm/calls/{refused_id}", headers=analyst)).status_code == 403


async def test_llm_test_endpoint_with_mock(client: httpx.AsyncClient, admin_headers: dict[str, str]) -> None:
    r = await client.post("/api/v1/llm/test", headers=admin_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["provider"] == "mock"
    assert body["model"] == "claude-haiku-5-5"
    assert body["status"] == "ok"
    r = await client.get("/api/v1/llm/calls?purpose=test", headers=admin_headers)
    assert r.json()["total"] == 1
