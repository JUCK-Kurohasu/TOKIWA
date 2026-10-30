"""Provider-neutral LLM interfaces.

Modules never talk to an SDK directly: they call :class:`tokiwa.llm.gateway.LLMGateway`, which applies the
budget, picks the model for the tier, writes the audit record and delegates to an :class:`LLMProvider`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar, Generic, TypeVar

from pydantic import BaseModel, Field

from tokiwa.schemas.system import LLMCallStatus

T = TypeVar("T", bound=BaseModel)


class LLMTier(StrEnum):
    FAST = "fast"  # cheap first pass (claude-haiku-5-5 by default)
    DEEP = "deep"  # escalation / deep analysis (claude-opus-5-5 by default)


class LLMPurpose(StrEnum):
    TRIAGE = "triage"
    INCIDENT = "incident"
    COPILOT = "copilot"
    ADVISORY = "advisory"
    RESEARCH = "research"
    RULE = "rule"
    CLASSIFY = "classify"
    EVAL = "eval"
    TEST = "test"


class LLMUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    web_search_requests: int = 0


@dataclass
class StructuredRequest:
    purpose: LLMPurpose
    tier: LLMTier
    system: str
    user: str  # already contains redacted, envelope-wrapped untrusted data (see tokiwa.llm.prompting)
    prompt_version: str
    max_output_tokens: int | None = None
    related: dict[str, str] = field(default_factory=dict)  # e.g. {"alert_id": "..."} for the audit log
    web_search: bool = False  # allow server-side web search (intel research only)
    web_search_max_uses: int = 5
    allowed_domains: list[str] | None = None


@dataclass
class ProviderResponse:
    """What a provider returns for one structured call."""

    model: str
    text: str | None = None
    parsed: dict[str, Any] | None = None  # JSON object matching the schema (not yet validated)
    usage: LLMUsage = field(default_factory=LLMUsage)
    stop_reason: str | None = None
    refused: bool = False
    citations: list[dict[str, Any]] = field(default_factory=list)
    request_id: str | None = None


class StructuredResult(BaseModel, Generic[T]):
    output: T | None = None
    status: LLMCallStatus
    provider: str
    model: str
    usage: LLMUsage = Field(default_factory=LLMUsage)
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    call_id: str | None = None
    error: str | None = None
    raw_text: str | None = None
    citations: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == LLMCallStatus.OK and self.output is not None


class ToolSpec(BaseModel):
    """A client-side tool exposed to the model (copilot). Read-only tools only (security policy)."""

    name: str
    description: str
    input_schema: dict[str, Any]


class ToolCall(BaseModel):
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class ChatTurn:
    """One assistant turn. ``raw_content`` holds provider-native blocks to append back verbatim."""

    model: str
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw_content: list[dict[str, Any]] = field(default_factory=list)
    usage: LLMUsage = field(default_factory=LLMUsage)
    stop_reason: str | None = None
    refused: bool = False


class ModelOption(BaseModel):
    """A model a provider can serve, as offered in the settings UI."""

    id: str
    display_name: str | None = None
    max_input_tokens: int | None = None


class LLMProvider(ABC):
    name: ClassVar[str]

    async def list_models(self) -> list[ModelOption] | None:
        """Models selectable for this provider, or ``None`` when it cannot enumerate them (the default)."""
        return None

    @abstractmethod
    def available(self) -> bool:
        """True when credentials/config are present."""

    @abstractmethod
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
        """Single structured-output call. ``parsed`` must be a dict matching ``schema`` (validated upstream)."""

    @abstractmethod
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
        """One assistant turn with optional tool calls. ``messages`` use Anthropic-style role/content blocks."""
