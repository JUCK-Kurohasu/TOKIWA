"""LLM call audit log (NFR: 監査性) and copilot conversations."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from tokiwa.db.base import Base, IdMixin, TimestampMixin
from tokiwa.util import utcnow


class LLMCallRow(IdMixin, Base):
    __tablename__ = "llm_calls"
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(64))
    tier: Mapped[str] = mapped_column(String(16))
    purpose: Mapped[str] = mapped_column(String(32), index=True)
    prompt_version: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), index=True)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_read_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_write_tokens: Mapped[int] = mapped_column(Integer, default=0)
    web_search_requests: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    related: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    request_redacted: Mapped[str | None] = mapped_column(Text, default=None)
    response_text: Mapped[str | None] = mapped_column(Text, default=None)


class CopilotConversationRow(IdMixin, TimestampMixin, Base):
    __tablename__ = "copilot_conversations"
    title: Mapped[str] = mapped_column(String(255), default="New conversation")
    owner: Mapped[str] = mapped_column(String(64), index=True)
    context: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # e.g. {"incident_id": "..."}


class CopilotMessageRow(IdMixin, Base):
    __tablename__ = "copilot_messages"
    conversation_id: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    role: Mapped[str] = mapped_column(String(16))  # user / assistant / tool
    content: Mapped[str] = mapped_column(Text, default="")
    # Raw provider content blocks (tool_use / tool_result) for faithful replay
    blocks: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    llm_call_id: Mapped[str | None] = mapped_column(String(64), default=None)
