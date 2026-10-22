"""Gateway behaviour that the providers rely on: budget, audit, cost accounting."""

from __future__ import annotations

from typing import Any, ClassVar

import pytest
from pydantic import BaseModel
from sqlalchemy import select

from tokiwa.config import Settings
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
    ToolSpec,
)
from tokiwa.llm.gateway import LLMGateway
from tokiwa.llm.pricing import estimate_cost
from tokiwa.schemas.system import LLMCallStatus
from tokiwa.util import new_id, utcnow

pytestmark = pytest.mark.usefixtures("db")


class Out(BaseModel):
    ok: bool


class RecordingProvider(LLMProvider):
    """A non-mock provider (so budget/cost rules apply) that records calls."""

    name: ClassVar[str] = "anthropic"

    def __init__(self, served_model: str | None = None) -> None:
        self.calls = 0
        self.served_model = served_model

    def available(self) -> bool:
        return True

    async def complete_structured(self, **kw: Any) -> ProviderResponse:  # type: ignore[override]
        self.calls += 1
        return ProviderResponse(
            model=self.served_model or kw["model"],
            text='{"ok": true}',
            parsed={"ok": True},
            usage=LLMUsage(input_tokens=1000, output_tokens=100),
            stop_reason="end_turn",
        )

    async def chat(self, **kw: Any) -> ChatTurn:  # type: ignore[override]
        self.calls += 1
        return ChatTurn(
            model=self.served_model or kw["model"],
            text="hi",
            raw_content=[{"type": "text", "text": "hi"}],
            usage=LLMUsage(input_tokens=1000, output_tokens=100),
            stop_reason="end_turn",
        )


def _settings(settings: Settings, **llm: Any) -> Settings:
    return settings.model_copy(update={"llm": settings.llm.model_copy(update=llm)})


async def _spend(amount: float) -> None:
    async with session_scope() as session:
        session.add(
            LLMCallRow(
                id=new_id(),
                created_at=utcnow(),
                provider="anthropic",
                model="claude-opus-5-5",
                tier="deep",
                purpose="triage",
                prompt_version="x@1",
                status="ok",
                cost_usd=amount,
                related={},
            )
        )


async def _rows() -> list[LLMCallRow]:
    async with session_scope() as session:
        return list((await session.execute(select(LLMCallRow).order_by(LLMCallRow.created_at))).scalars())


def _req() -> StructuredRequest:
    return StructuredRequest(
        purpose=LLMPurpose.TRIAGE, tier=LLMTier.DEEP, system="sys", user="u", prompt_version="triage@1"
    )


async def test_budget_exceeded_structured_skips_provider_and_audits(settings: Settings) -> None:
    provider = RecordingProvider()
    gw = LLMGateway(provider=provider, settings=_settings(settings, daily_budget_usd=1.0))
    await _spend(1.5)
    res = await gw.structured(_req(), Out)
    assert res.status == LLMCallStatus.BUDGET_EXCEEDED
    assert res.output is None
    assert provider.calls == 0
    rows = await _rows()
    audit = [r for r in rows if r.id == res.call_id]
    assert audit and audit[0].status == "budget_exceeded"
    assert audit[0].cost_usd == 0.0


async def test_budget_exceeded_chat_skips_provider_and_audits(settings: Settings) -> None:
    provider = RecordingProvider()
    gw = LLMGateway(provider=provider, settings=_settings(settings, daily_budget_usd=1.0))
    await _spend(2.0)
    turn, status, err, call_id = await gw.chat(
        purpose=LLMPurpose.COPILOT,
        tier=LLMTier.FAST,
        system="s",
        messages=[{"role": "user", "content": "hi"}],
        tools=[ToolSpec(name="t", description="d", input_schema={"type": "object", "properties": {}})],
        prompt_version="copilot@1",
    )
    assert turn is None
    assert status == LLMCallStatus.BUDGET_EXCEEDED
    assert err and "budget" in err
    assert provider.calls == 0
    assert any(r.id == call_id and r.status == "budget_exceeded" for r in await _rows())


async def test_under_budget_calls_provider(settings: Settings) -> None:
    provider = RecordingProvider()
    gw = LLMGateway(provider=provider, settings=_settings(settings, daily_budget_usd=10.0))
    await _spend(1.0)
    res = await gw.structured(_req(), Out)
    assert res.ok and provider.calls == 1
    assert res.cost_usd == estimate_cost("claude-opus-5-5", res.usage)


async def test_chat_cost_uses_served_model(settings: Settings) -> None:
    """After a server-side fallback the served model's price applies (and is what the audit shows)."""
    provider = RecordingProvider(served_model="claude-opus-4-8")
    gw = LLMGateway(provider=provider, settings=settings)
    turn, status, _, call_id = await gw.chat(
        purpose=LLMPurpose.COPILOT,
        tier=LLMTier.DEEP,
        system="s",
        messages=[{"role": "user", "content": "hi"}],
        tools=[],
        prompt_version="copilot@1",
    )
    assert status == LLMCallStatus.OK and turn is not None
    row = next(r for r in await _rows() if r.id == call_id)
    assert row.model == "claude-opus-4-8"
    assert row.cost_usd == estimate_cost("claude-opus-4-8", LLMUsage(input_tokens=1000, output_tokens=100))
    assert row.cost_usd > 0


async def test_provider_exception_is_error_status(settings: Settings) -> None:
    class Boom(RecordingProvider):
        async def complete_structured(self, **kw: Any) -> ProviderResponse:  # type: ignore[override]
            raise RuntimeError("Anthropic API key is not configured")

    gw = LLMGateway(provider=Boom(), settings=settings)
    res = await gw.structured(_req(), Out)
    assert res.status == LLMCallStatus.ERROR
    assert "not configured" in (res.error or "")
