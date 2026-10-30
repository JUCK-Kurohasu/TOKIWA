"""Model choices for the settings UI: GET /v1/models via the provider, gateway fallback and the route."""

from __future__ import annotations

from typing import Any

import httpx

from tokiwa.config import Settings
from tokiwa.llm.anthropic_provider import AnthropicProvider
from tokiwa.llm.gateway import LLMGateway, set_gateway
from tokiwa.llm.mock import MockProvider
from tokiwa.llm.models import BUILTIN_ANTHROPIC_MODELS


def _model(model_id: str, name: str, **extra: Any) -> dict[str, Any]:
    return {
        "type": "model",
        "id": model_id,
        "display_name": name,
        "created_at": "2026-08-01T00:00:00Z",
        **extra,
    }


def _page(*models: dict[str, Any]) -> dict[str, Any]:
    return {
        "data": list(models),
        "has_more": False,
        "first_id": models[0]["id"] if models else None,
        "last_id": models[-1]["id"] if models else None,
    }


API_MODELS = _page(
    _model("claude-opus-5-5", "Claude Opus 5.5", max_input_tokens=1_000_000),
    _model("claude-haiku-5-5", "Claude Haiku 5.5"),
    _model("claude-old-retired", "Old", lifecycle="retired"),
    _model("claude-no-structured", "No SO", capabilities={"structured_outputs": {"supported": False}}),
    _model("claude-unknown-caps", "Unknown caps", capabilities={}),
)


async def test_provider_lists_active_models_that_can_do_structured_output(
    settings: Settings, fake_anthropic
) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(API_MODELS)
    provider = AnthropicProvider(settings, client=fake_anthropic.client())
    models = await provider.list_models()
    assert [m.id for m in models] == ["claude-opus-5-5", "claude-haiku-5-5", "claude-unknown-caps"]
    assert models[0].display_name == "Claude Opus 5.5" and models[0].max_input_tokens == 1_000_000
    assert fake_anthropic.requests[0]["url"].split("?")[0].endswith("/v1/models")


async def test_base_provider_has_no_listing() -> None:
    assert await MockProvider().list_models() is None


async def test_gateway_uses_api_list_and_caches_it(settings: Settings, fake_anthropic) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(API_MODELS)  # only one reply queued: a second API call would 500
    gw = LLMGateway(provider=AnthropicProvider(settings, client=fake_anthropic.client()), settings=settings)
    first = await gw.list_models()
    second = await gw.list_models()
    assert first.source == second.source == "api" and first.error is None
    assert len(fake_anthropic.requests) == 1


async def test_gateway_falls_back_to_builtin_on_api_error(settings: Settings, fake_anthropic) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(
        {"type": "error", "error": {"type": "authentication_error", "message": "bad key"}}, 401
    )
    gw = LLMGateway(provider=AnthropicProvider(settings, client=fake_anthropic.client()), settings=settings)
    listing = await gw.list_models()
    assert listing.source == "builtin"
    assert [m.id for m in listing.models] == [m.id for m in BUILTIN_ANTHROPIC_MODELS]
    assert listing.error and "AuthenticationError" in listing.error
    assert "sk-ant" not in listing.error  # never echo credentials

    # a failure is not cached: the next call asks the API again
    fake_anthropic.reply(API_MODELS)
    assert (await gw.list_models()).source == "api"


async def test_gateway_without_anthropic_provider_is_builtin(settings: Settings) -> None:
    listing = await LLMGateway(provider=MockProvider(), settings=settings).list_models()
    assert listing.source == "builtin" and listing.error is None
    ids = [m.id for m in listing.models]
    assert {"claude-haiku-5-5", "claude-opus-5-5"} <= set(ids)
    assert all(not i[-8:].isdigit() for i in ids)  # no date-suffixed IDs


async def test_models_route(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    settings: Settings,
    fake_anthropic,  # type: ignore[no-untyped-def]
) -> None:
    assert (await client.get("/api/v1/llm/models")).status_code == 401

    r = await client.get("/api/v1/llm/models", headers=admin_headers)  # test gateway = mock
    assert r.status_code == 200, r.text
    assert r.json()["source"] == "builtin"

    fake_anthropic.reply(API_MODELS)
    set_gateway(
        LLMGateway(provider=AnthropicProvider(settings, client=fake_anthropic.client()), settings=settings)
    )
    try:
        r = await client.get("/api/v1/llm/models", headers=admin_headers)
    finally:
        set_gateway(None)
    body = r.json()
    assert body["source"] == "api"
    assert [m["id"] for m in body["models"]][:2] == ["claude-opus-5-5", "claude-haiku-5-5"]


async def test_empty_api_list_falls_back(settings: Settings, fake_anthropic) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(_page())
    gw = LLMGateway(provider=AnthropicProvider(settings, client=fake_anthropic.client()), settings=settings)
    listing = await gw.list_models()
    assert listing.source == "builtin" and listing.error
