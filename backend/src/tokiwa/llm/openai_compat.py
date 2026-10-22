"""OpenAI-compatible provider (local Ollama / vLLM etc.). OWNER: llm module (to be implemented)."""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel

from tokiwa.config import Settings
from tokiwa.llm.base import ChatTurn, LLMProvider, ProviderResponse, ToolSpec


class OpenAICompatProvider(LLMProvider):
    name: ClassVar[str] = "openai_compat"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def available(self) -> bool:
        return bool(self.settings.llm.openai_base_url)

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
