"""Pricing is fail-closed (#35): an unknown model must never be free, or the daily budget stops working."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, ClassVar

import httpx
import pytest
from pydantic import BaseModel
from sqlalchemy import select

from tokiwa.config import LLMSettings, Settings
from tokiwa.db.models.llm import LLMCallRow
from tokiwa.db.session import session_scope
from tokiwa.llm.base import (
    ChatTurn,
    LLMProvider,
    LLMPurpose,
    LLMTier,
    LLMUsage,
    ProviderResponse,
    StructuredRequest,
)
from tokiwa.llm.gateway import LLMGateway, set_gateway
from tokiwa.llm.models import BUILTIN_ANTHROPIC_MODELS
from tokiwa.llm.pricing import (
    DEFAULT_PRICING,
    CostBasis,
    estimate,
    estimate_cost,
    normalize_model,
    price_for,
    unpriced_rates,
)
from tokiwa.schemas.system import LLMCallStatus
from tokiwa.util import new_id, utcnow

MTOK = LLMUsage(input_tokens=1_000_000, output_tokens=100_000)


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("claude-opus-5-5", "claude-opus-5-5"),
        ("Claude-Opus-5-5", "claude-opus-5-5"),
        ("claude-opus-5-5-20261001", "claude-opus-5-5"),  # dated snapshot
        ("claude-opus-4-5@20251101", "claude-opus-4-5"),  # Vertex snapshot separator
        ("anthropic.claude-opus-5-5", "claude-opus-5-5"),  # Bedrock
        ("us.anthropic.claude-haiku-4-5-20251001-v1:0", "claude-haiku-4-5"),  # Bedrock cross-region + version
        ("global.anthropic.claude-sonnet-5-5", "claude-sonnet-5-5"),
        ("anthropic/claude-opus-5-5", "claude-opus-5-5"),  # proxy-style
        ("claude-sonnet-5-5-latest", "claude-sonnet-5-5"),
        ("claude-opus-5-9", "claude-opus-5-9"),  # unknown family member stays as is (no sibling guess)
        ("llama3.1:8b", "llama3.1:8b"),
        ("20261001", "20261001"),  # never strips to an empty id
    ],
)
def test_normalize_model(model: str, expected: str) -> None:
    assert normalize_model(model) == expected


def test_known_and_snapshot_ids_use_the_table() -> None:
    assert price_for("claude-opus-5-5") == (DEFAULT_PRICING["claude-opus-5-5"], CostBasis.TABLE)
    for snapshot in ("claude-opus-5-5-20261001", "anthropic.claude-opus-5-5", "claude-opus-5-5@20261001"):
        rates, basis = price_for(snapshot)
        assert basis == CostBasis.SNAPSHOT
        assert rates == DEFAULT_PRICING["claude-opus-5-5"]
        assert estimate_cost(snapshot, MTOK) == estimate_cost("claude-opus-5-5", MTOK) > 0


@pytest.mark.parametrize(
    "model", ["claude-opus-5-9", "claude-totally-new", "my-proxy/gpt-ish", "llama3.1:8b", "claude-opus-55"]
)
def test_unknown_model_is_charged_at_the_highest_known_rates(model: str) -> None:
    cost, basis = estimate(model, MTOK)
    assert basis == CostBasis.UNPRICED
    top_in = max(p["input"] for p in DEFAULT_PRICING.values())
    top_out = max(p["output"] for p in DEFAULT_PRICING.values())
    assert cost == pytest.approx(top_in + top_out * 0.1)
    # Never cheaper than any model in the table (fail-closed).
    assert all(cost >= estimate_cost(m, MTOK) for m in DEFAULT_PRICING)


def test_unpriced_rates_cover_overrides_and_cache_tokens() -> None:
    overrides = {"premium-proxy": {"input": 99.0, "output": 199.0, "cache_read": 9.0}}
    rates = unpriced_rates(overrides)
    assert rates["input"] == 99.0 and rates["output"] == 199.0 and rates["cache_read"] == 9.0
    usage = LLMUsage(cache_read_tokens=1_000_000, cache_write_tokens=1_000_000)
    cost, basis = estimate("unknown", usage, overrides)
    assert basis == CostBasis.UNPRICED
    assert cost == pytest.approx(rates["cache_read"] + rates["cache_write"])


def test_operator_pricing_entry_makes_a_local_model_free() -> None:
    """The documented escape for free local models (openai_compat): an explicit zero price in llm.pricing."""
    overrides = {"llama3.1:8b": {"input": 0.0, "output": 0.0}}
    assert estimate("llama3.1:8b", MTOK, overrides) == (0.0, CostBasis.TABLE)
    # A dated override wins over the built-in entry with the same canonical id.
    overrides = {"claude-opus-5-5-20261001": {"input": 1.0, "output": 1.0}}
    assert price_for("claude-opus-5-5-20261001", overrides) == (
        {"input": 1.0, "output": 1.0},
        CostBasis.TABLE,
    )


def test_every_builtin_selectable_model_has_a_price() -> None:
    """The UI dropdown (BUILTIN_ANTHROPIC_MODELS) must never offer a model that silently costs $0 / an estimate."""
    missing = [m.id for m in BUILTIN_ANTHROPIC_MODELS if price_for(m.id)[1] != CostBasis.TABLE]
    assert missing == []
    defaults = LLMSettings()
    assert price_for(defaults.model_fast)[1] == CostBasis.TABLE
    assert price_for(defaults.model_deep)[1] == CostBasis.TABLE


def test_table_entries_are_complete() -> None:
    for model, rates in DEFAULT_PRICING.items():
        assert normalize_model(model) == model, model  # table keys are canonical ids
        assert rates["input"] > 0 and rates["output"] > 0, model


# --------------------------------------------------------------------------- gateway / budget / usage


class PaidProvider(LLMProvider):
    """A non-mock provider so pricing applies; answers as ``served`` when set (server-side fallback)."""

    name: ClassVar[str] = "anthropic"

    def __init__(self, served: str | None = None, usage: LLMUsage | None = None) -> None:
        self.calls = 0
        self.served = served
        self.usage = usage or LLMUsage(input_tokens=100_000, output_tokens=10_000)

    def available(self) -> bool:
        return True

    async def complete_structured(self, **kw: Any) -> ProviderResponse:  # type: ignore[override]
        self.calls += 1
        return ProviderResponse(
            model=self.served or kw["model"],
            text='{"ok": true}',
            parsed={"ok": True},
            usage=self.usage,
            stop_reason="end_turn",
        )

    async def chat(self, **kw: Any) -> ChatTurn:  # type: ignore[override]
        self.calls += 1
        return ChatTurn(
            model=self.served or kw["model"],
            text="hi",
            raw_content=[{"type": "text", "text": "hi"}],
            usage=self.usage,
            stop_reason="end_turn",
        )


class Out(BaseModel):
    ok: bool


def _req() -> StructuredRequest:
    return StructuredRequest(
        purpose=LLMPurpose.TRIAGE, tier=LLMTier.FAST, system="sys", user="u", prompt_version="t@1"
    )


def _settings(settings: Settings, **llm: Any) -> Settings:
    return settings.model_copy(update={"llm": settings.llm.model_copy(update=llm)})


async def _rows() -> list[LLMCallRow]:
    async with session_scope() as s:
        return list((await s.execute(select(LLMCallRow).order_by(LLMCallRow.created_at))).scalars())


@pytest.mark.usefixtures("db")
async def test_unpriced_model_trips_the_daily_budget(settings: Settings) -> None:
    provider = PaidProvider()
    gw = LLMGateway(
        provider=provider, settings=_settings(settings, model_fast="claude-sonnet-9-9", daily_budget_usd=2.0)
    )
    assert gw.unpriced_models() == ["claude-sonnet-9-9"]
    statuses = [(await gw.structured(_req(), Out)).status for _ in range(5)]
    # 100k in + 10k out at the highest known rates = $1.50 per call -> the second call is the last one allowed.
    assert statuses[:2] == [LLMCallStatus.OK, LLMCallStatus.OK]
    assert statuses[2:] == [LLMCallStatus.BUDGET_EXCEEDED] * 3
    assert provider.calls == 2
    rows = await _rows()
    billed = [r for r in rows if r.status == "ok"]
    assert all(r.cost_basis == "unpriced" and r.cost_usd > 0 for r in billed)
    # Calls that were never billed are not "unpriced calls".
    assert all(r.cost_basis is None and r.cost_usd == 0 for r in rows if r.status == "budget_exceeded")


@pytest.mark.usefixtures("db")
async def test_served_snapshot_model_is_priced_from_the_table(settings: Settings) -> None:
    provider = PaidProvider(served="claude-opus-5-5-20261001")
    gw = LLMGateway(provider=provider, settings=settings)
    _, status, _, call_id = await gw.chat(
        purpose=LLMPurpose.COPILOT,
        tier=LLMTier.DEEP,
        system="s",
        messages=[{"role": "user", "content": "hi"}],
        tools=[],
        prompt_version="copilot@1",
    )
    assert status == LLMCallStatus.OK
    row = next(r for r in await _rows() if r.id == call_id)
    assert row.model == "claude-opus-5-5-20261001"
    assert row.cost_basis == "snapshot"
    assert row.cost_usd == estimate_cost("claude-opus-5-5", provider.usage)


async def test_usage_and_config_report_unpriced_calls(
    client: httpx.AsyncClient, admin_headers: dict[str, str], settings: Settings
) -> None:
    now = utcnow()
    async with session_scope() as s:
        for basis, model, when in (
            ("unpriced", "claude-new-1", now),
            ("unpriced", "claude-new-1", now),
            ("unpriced", "claude-new-2", now - timedelta(days=1)),
            ("table", "claude-opus-5-5", now),
            (None, "claude-opus-5-5", now),  # budget_exceeded / old row
        ):
            s.add(
                LLMCallRow(
                    id=new_id(),
                    created_at=when,
                    provider="anthropic",
                    model=model,
                    tier="fast",
                    purpose="triage",
                    prompt_version="t@1",
                    status="ok",
                    cost_usd=1.0,
                    cost_basis=basis,
                    related={},
                )
            )
    r = await client.get("/api/v1/llm/usage?days=3", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert [d["unpriced_calls"] for d in body["days"]] == [0, 1, 2]
    assert body["unpriced_models"] == ["claude-new-1", "claude-new-2"]
    calls = (await client.get("/api/v1/llm/calls", headers=admin_headers)).json()["items"]
    assert {c["cost_basis"] for c in calls} == {"unpriced", "table", None}

    # The settings view lists configured models without a price (mock -> nothing is billed -> empty).
    cfg = (await client.get("/api/v1/llm/config", headers=admin_headers)).json()
    assert cfg["unpriced_models"] == []
    set_gateway(LLMGateway(provider=PaidProvider(), settings=_settings(settings, model_deep="claude-x-1")))
    cfg = (await client.get("/api/v1/llm/config", headers=admin_headers)).json()
    assert cfg["unpriced_models"] == ["claude-x-1"]
