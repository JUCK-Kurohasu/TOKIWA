"""API schemas for the SOC Copilot (docs/api-contract.md「コパイロット」).

Kept inside the copilot package (owned by this module) instead of ``tokiwa.schemas`` so parallel work does not
touch shared files. TS counterparts belong in ``frontend/src/api/types.ts`` (owned by frontend-intel).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from tokiwa.schemas.common import ORMModel

# Context keys a conversation can be anchored to. The copilot summarizes the referenced objects into the
# system prompt (snapshot taken once, so the prompt stays byte-stable across turns for caching / replay).
CONTEXT_KEYS = ("incident_id", "alert_id", "session_id", "source_ip", "vuln_id", "asset_id")

# Keys starting with "_" inside the stored context are internal (e.g. the frozen summary) and never returned.
INTERNAL_CONTEXT_PREFIX = "_"


class ConversationContext(BaseModel):
    """What the conversation is about (e.g. opened from an incident page). Unknown keys are ignored."""

    model_config = ConfigDict(extra="ignore")

    incident_id: str | None = Field(default=None, max_length=128)
    alert_id: str | None = Field(default=None, max_length=128)
    session_id: str | None = Field(default=None, max_length=128)
    source_ip: str | None = Field(default=None, max_length=64)
    vuln_id: str | None = Field(default=None, max_length=128)
    asset_id: str | None = Field(default=None, max_length=128)


class ConversationCreate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    context: ConversationContext | None = None


class Conversation(ORMModel):
    id: str
    title: str
    owner: str  # user id
    context: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    @field_validator("context", mode="before")
    @classmethod
    def _hide_internal(cls, v: Any) -> Any:
        if isinstance(v, dict):
            return {k: val for k, val in v.items() if not str(k).startswith(INTERNAL_CONTEXT_PREFIX)}
        return v or {}


class CopilotToolCall(BaseModel):
    id: str
    name: str
    input: dict[str, Any] = Field(default_factory=dict)


class CopilotToolResult(BaseModel):
    tool_use_id: str
    name: str | None = None
    ok: bool
    summary: str


# user = analyst input, assistant = model turn, tool = tool results (replayed to the model as a user turn),
# notice = shown in the UI only (LLM not configured, errors, limits) - never sent to the model.
MessageRole = Literal["user", "assistant", "tool", "notice"]


class CopilotMessage(BaseModel):
    id: str
    role: MessageRole
    content: str
    created_at: datetime
    tool_calls: list[CopilotToolCall] | None = None
    tool_results: list[CopilotToolResult] | None = None
    llm_call_id: str | None = None


class ConversationDetail(BaseModel):
    conversation: Conversation
    messages: list[CopilotMessage]


class MessageCreate(BaseModel):
    content: str = Field(min_length=1, max_length=8000)

    @field_validator("content")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("content must not be blank")
        return v
