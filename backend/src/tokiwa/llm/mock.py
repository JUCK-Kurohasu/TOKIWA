"""Deterministic offline provider for tests, demos and "no API key" mode.

Modules can register a responder per output schema so the mock produces meaningful results (e.g. the triage
module registers its rule-based triage, which doubles as the no-LLM fallback)::

    from tokiwa.llm.mock import register_mock_responder

    @register_mock_responder(TriageResult)
    def _triage(system: str, user: str) -> dict: ...
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, ClassVar

from pydantic import BaseModel, ValidationError

from tokiwa.llm.base import ChatTurn, LLMProvider, LLMUsage, ProviderResponse, ToolSpec

Responder = Callable[[str, str], dict[str, Any]]

_RESPONDERS: dict[str, Responder] = {}


def register_mock_responder(schema: type[BaseModel]) -> Callable[[Responder], Responder]:
    def deco(fn: Responder) -> Responder:
        _RESPONDERS[schema.__name__] = fn
        return fn

    return deco


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class MockProvider(LLMProvider):
    name: ClassVar[str] = "mock"

    def __init__(self, responders: dict[str, Responder] | None = None) -> None:
        self._local = responders or {}
        self.calls: list[dict[str, Any]] = []

    def available(self) -> bool:
        return True

    async def complete_structured(
        self,
        *,
        model: str,
        system: str,
        user: str,
        schema: type[BaseModel],
        max_tokens: int,
        effort: str | None,
        cache: bool,
        web_search: bool = False,
        web_search_max_uses: int = 5,
        allowed_domains: list[str] | None = None,
    ) -> ProviderResponse:
        self.calls.append({"model": model, "schema": schema.__name__, "system": system, "user": user})
        responder = self._local.get(schema.__name__) or _RESPONDERS.get(schema.__name__)
        usage = LLMUsage(input_tokens=_estimate_tokens(system + user), output_tokens=200)
        if responder is None:
            try:
                parsed = schema.model_validate({}).model_dump(mode="json")
            except ValidationError:
                return ProviderResponse(
                    model=model,
                    text=None,
                    parsed=None,
                    usage=usage,
                    stop_reason="error",
                )
        else:
            parsed = responder(system, user)
        return ProviderResponse(
            model=model,
            text=json.dumps(parsed, ensure_ascii=False),
            parsed=parsed,
            usage=usage,
            stop_reason="end_turn",
        )

    async def chat(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
        max_tokens: int,
        effort: str | None,
        cache: bool,
    ) -> ChatTurn:
        last = messages[-1] if messages else {"content": ""}
        content = last.get("content")
        if isinstance(content, list):
            content = " ".join(str(b.get("text", "")) for b in content if isinstance(b, dict))
        text = f"[mock] LLM is not configured (set ANTHROPIC_API_KEY). I received: {str(content)[:200]}"
        return ChatTurn(
            model=model,
            text=text,
            raw_content=[{"type": "text", "text": text}],
            usage=LLMUsage(input_tokens=_estimate_tokens(system), output_tokens=_estimate_tokens(text)),
            stop_reason="end_turn",
        )
