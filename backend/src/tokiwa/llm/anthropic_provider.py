"""Anthropic (Claude) provider. OWNER: llm module (to be implemented - see docs/tasks/llm.md)."""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel

from tokiwa.config import Settings, anthropic_api_key
from tokiwa.llm.base import ChatTurn, LLMProvider, ProviderResponse, ToolSpec


class AnthropicProvider(LLMProvider):
    name: ClassVar[str] = "anthropic"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def available(self) -> bool:
        return anthropic_api_key(self.settings) is not None

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
        raise NotImplementedError

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
        raise NotImplementedError
