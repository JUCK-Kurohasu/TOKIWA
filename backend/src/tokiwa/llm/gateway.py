"""LLM gateway: the only entry point modules use to call an LLM.

Responsibilities (NFR): tier -> model mapping, daily budget, input size cap, schema validation,
cost accounting, audit log (``llm_calls`` table) and ``llm.call`` bus events.

OWNER: llm module. Other modules: call ``get_gateway().structured(...)`` / ``.chat(...)`` only.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import timedelta
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError
from sqlalchemy import func, select

from tokiwa.bus import bus
from tokiwa.config import LLMSettings, Settings, anthropic_api_key, get_settings
from tokiwa.db.models.llm import LLMCallRow
from tokiwa.db.session import session_scope
from tokiwa.llm.base import (
    ChatTurn,
    LLMProvider,
    LLMPurpose,
    LLMTier,
    LLMUsage,
    StructuredRequest,
    StructuredResult,
    ToolSpec,
)
from tokiwa.llm.mock import MockProvider
from tokiwa.llm.models import ModelListCache, ModelListing, builtin_listing
from tokiwa.llm.pricing import estimate_cost
from tokiwa.schemas.system import LLMCall, LLMCallStatus
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# Rough chars-per-token used for the pre-flight input cap (exact counting would cost an API call).
_CHARS_PER_TOKEN = 3.0


class BudgetExceededError(RuntimeError):
    pass


def build_provider(settings: Settings | None = None) -> LLMProvider:
    s = settings or get_settings()
    kind = s.llm.provider
    if kind == "auto":
        kind = "anthropic" if anthropic_api_key(s) else ("openai_compat" if s.llm.openai_base_url else "mock")
    if kind == "anthropic":
        from tokiwa.llm.anthropic_provider import AnthropicProvider

        return AnthropicProvider(s)
    if kind == "openai_compat":
        from tokiwa.llm.openai_compat import OpenAICompatProvider

        return OpenAICompatProvider(s)
    return MockProvider()


class LLMGateway:
    def __init__(self, provider: LLMProvider | None = None, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.provider = provider or build_provider(self.settings)
        self._models_cache = ModelListCache()

    @property
    def llm(self) -> LLMSettings:
        return self.settings.llm

    def model_for(self, tier: LLMTier) -> str:
        return self.llm.model_fast if tier == LLMTier.FAST else self.llm.model_deep

    def effort_for(self, tier: LLMTier) -> str:
        return self.llm.effort_fast if tier == LLMTier.FAST else self.llm.effort_deep

    async def list_models(self) -> ModelListing:
        """Anthropic model choices for the UI: live from the API when this gateway talks to Anthropic, else built-in."""
        if self.provider.name != "anthropic":
            return builtin_listing()
        cached = self._models_cache.get()
        if cached is not None:
            return ModelListing(source="api", models=cached)
        try:
            models = await self.provider.list_models()
        except Exception as exc:
            log.warning("could not list Anthropic models: %s", exc)
            return builtin_listing(f"{type(exc).__name__}: {exc}"[:300])
        if not models:
            return builtin_listing("the API returned no models")
        self._models_cache.put(models)
        return ModelListing(source="api", models=models)

    async def spent_today_usd(self) -> float:
        since = utcnow() - timedelta(hours=24)
        async with session_scope() as session:
            total = (
                await session.execute(
                    select(func.coalesce(func.sum(LLMCallRow.cost_usd), 0.0)).where(
                        LLMCallRow.created_at >= since
                    )
                )
            ).scalar_one()
        return float(total or 0.0)

    async def check_budget(self) -> None:
        if self.provider.name == "mock":
            return
        if self.llm.daily_budget_usd <= 0:
            return
        if await self.spent_today_usd() >= self.llm.daily_budget_usd:
            raise BudgetExceededError(f"daily LLM budget of ${self.llm.daily_budget_usd:.2f} reached")

    def _cap_input(self, text: str) -> str:
        max_chars = int(self.llm.max_input_tokens_per_call * _CHARS_PER_TOKEN)
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + "\n[input truncated by TOKIWA to respect max_input_tokens_per_call]"

    async def structured(self, req: StructuredRequest, schema: type[T]) -> StructuredResult[T]:
        model = self.model_for(req.tier)
        started = time.perf_counter()
        user = self._cap_input(req.user)
        try:
            await self.check_budget()
        except BudgetExceededError as exc:
            return await self._finish(
                req,
                schema,
                model,
                LLMCallStatus.BUDGET_EXCEEDED,
                None,
                LLMUsage(),
                started,
                str(exc),
                None,
                [],
            )
        try:
            resp = await self.provider.complete_structured(
                model=model,
                system=req.system,
                user=user,
                schema=schema,
                max_tokens=req.max_output_tokens or self.llm.max_output_tokens,
                effort=self.effort_for(req.tier),
                cache=self.llm.prompt_cache,
                web_search=req.web_search,
                web_search_max_uses=req.web_search_max_uses,
                allowed_domains=req.allowed_domains,
            )
        except Exception as exc:
            log.warning("LLM call failed (%s/%s): %s", req.purpose, model, exc)
            return await self._finish(
                req,
                schema,
                model,
                LLMCallStatus.ERROR,
                None,
                LLMUsage(),
                started,
                f"{type(exc).__name__}: {exc}",
                None,
                [],
            )
        if resp.refused:
            return await self._finish(
                req,
                schema,
                resp.model,
                LLMCallStatus.REFUSED,
                None,
                resp.usage,
                started,
                f"model refused (stop_reason={resp.stop_reason})"
                + (f": {resp.text[:500]}" if resp.text else ""),
                resp.text,
                resp.citations,
            )
        output: T | None = None
        status = LLMCallStatus.OK
        error: str | None = None
        try:
            if resp.parsed is None:
                raise ValueError("no structured output returned")
            output = schema.model_validate(resp.parsed)
        except (ValidationError, ValueError) as exc:
            status, error = LLMCallStatus.INVALID_OUTPUT, str(exc)[:2000]
        return await self._finish(
            req, schema, resp.model, status, output, resp.usage, started, error, resp.text, resp.citations
        )

    async def _finish(
        self,
        req: StructuredRequest,
        schema: type[T],
        model: str,
        status: LLMCallStatus,
        output: T | None,
        usage: LLMUsage,
        started: float,
        error: str | None,
        raw_text: str | None,
        citations: list[dict[str, Any]],
    ) -> StructuredResult[T]:
        latency = (time.perf_counter() - started) * 1000
        cost = estimate_cost(model, usage, self.llm.pricing) if self.provider.name != "mock" else 0.0
        call_id = await self._audit(
            purpose=req.purpose,
            tier=req.tier,
            model=model,
            prompt_version=req.prompt_version,
            status=status,
            usage=usage,
            cost=cost,
            latency=latency,
            related=req.related,
            error=error,
            request_text=f"[system]\n{req.system}\n\n[user]\n{req.user}",
            response_text=raw_text,
        )
        return StructuredResult[schema](  # type: ignore[valid-type]
            output=output,
            status=status,
            provider=self.provider.name,
            model=model,
            usage=usage,
            cost_usd=cost,
            latency_ms=latency,
            call_id=call_id,
            error=error,
            raw_text=raw_text,
            citations=citations,
        )

    async def chat(
        self,
        *,
        purpose: LLMPurpose,
        tier: LLMTier,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
        prompt_version: str,
        related: dict[str, str] | None = None,
        max_tokens: int | None = None,
    ) -> tuple[ChatTurn | None, LLMCallStatus, str | None, str | None]:
        """Returns (turn, status, error, call_id)."""
        model = self.model_for(tier)
        started = time.perf_counter()
        turn: ChatTurn | None = None
        err: str | None = None
        usage = LLMUsage()
        try:
            await self.check_budget()
            turn = await self.provider.chat(
                model=model,
                system=system,
                messages=messages,
                tools=tools,
                max_tokens=max_tokens or self.llm.max_output_tokens,
                effort=self.effort_for(tier),
                cache=self.llm.prompt_cache,
            )
        except BudgetExceededError as exc:
            status, err = LLMCallStatus.BUDGET_EXCEEDED, str(exc)
        except Exception as exc:
            log.warning("LLM chat failed (%s/%s): %s", purpose, model, exc)
            status, err = LLMCallStatus.ERROR, f"{type(exc).__name__}: {exc}"
        else:
            usage = turn.usage
            status = LLMCallStatus.REFUSED if turn.refused else LLMCallStatus.OK
        latency = (time.perf_counter() - started) * 1000
        served_model = turn.model if turn else model  # may differ from `model` after a server-side fallback
        cost = estimate_cost(served_model, usage, self.llm.pricing) if self.provider.name != "mock" else 0.0
        call_id = await self._audit(
            purpose=purpose,
            tier=tier,
            model=served_model,
            prompt_version=prompt_version,
            status=status,
            usage=usage,
            cost=cost,
            latency=latency,
            related=related or {},
            # The returned `err` stays None for refusals (callers branch on status); the audit row gets the reason.
            error=err or (f"model refused: {turn.text[:500]}" if turn is not None and turn.refused else None),
            request_text=json.dumps(
                {"system": system, "messages": messages[-6:]}, ensure_ascii=False, default=str
            )[:50_000],
            response_text=turn.text if turn else None,
        )
        return turn, status, err, call_id

    async def _audit(
        self,
        *,
        purpose: str,
        tier: str,
        model: str,
        prompt_version: str,
        status: LLMCallStatus,
        usage: LLMUsage,
        cost: float,
        latency: float,
        related: dict[str, str],
        error: str | None,
        request_text: str | None,
        response_text: str | None,
    ) -> str:
        row = LLMCallRow(
            id=new_id(),
            created_at=utcnow(),
            provider=self.provider.name,
            model=model,
            tier=str(tier),
            purpose=str(purpose),
            prompt_version=prompt_version,
            status=status,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_read_tokens=usage.cache_read_tokens,
            cache_write_tokens=usage.cache_write_tokens,
            web_search_requests=usage.web_search_requests,
            cost_usd=cost,
            latency_ms=latency,
            related=related,
            error=error,
            request_redacted=(request_text or "")[:100_000],
            response_text=(response_text or "")[:100_000] or None,
        )
        try:
            async with session_scope() as session:
                session.add(row)
            await bus.publish("llm.call", LLMCall.model_validate(row))
        except Exception:
            log.exception("failed to write LLM audit record")
        return row.id


_gateway: LLMGateway | None = None


def get_gateway() -> LLMGateway:
    global _gateway
    if _gateway is None:
        _gateway = LLMGateway()
    return _gateway


def set_gateway(gw: LLMGateway | None) -> None:
    """Tests / settings changes: replace (or reset with None) the process-wide gateway."""
    global _gateway
    _gateway = gw
