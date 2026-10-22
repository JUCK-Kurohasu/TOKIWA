"""Alerts, incidents, detection rules."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from tokiwa.db.base import Base, IdMixin, TimestampMixin
from tokiwa.util import utcnow


class AlertRow(IdMixin, TimestampMixin, Base):
    __tablename__ = "alerts"
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    count: Mapped[int] = mapped_column(Integer, default=1)
    fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    detector: Mapped[str] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.7)
    category: Mapped[str] = mapped_column(String(32), index=True)
    mitre: Mapped[list[str]] = mapped_column(JSON, default=list)
    ai_score: Mapped[float | None] = mapped_column(Float, default=None)
    source_ip: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    entities: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    evidence_event_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    incident_id: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    triage: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)


class IncidentRow(IdMixin, TimestampMixin, Base):
    __tablename__ = "incidents"
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    title: Mapped[str] = mapped_column(String(512))
    summary: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    category: Mapped[str] = mapped_column(String(32))
    actor_type: Mapped[str] = mapped_column(String(32), default="unknown")
    ai_score: Mapped[float | None] = mapped_column(Float, default=None)
    source_ips: Mapped[list[str]] = mapped_column(JSON, default=list)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    kill_chain: Mapped[list[str]] = mapped_column(JSON, default=list)
    mitre: Mapped[list[str]] = mapped_column(JSON, default=list)
    triage: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    assignee: Mapped[str | None] = mapped_column(String(64), default=None)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)


class RuleRow(IdMixin, TimestampMixin, Base):
    __tablename__ = "rules"
    kind: Mapped[str] = mapped_column(String(16), default="sigma")
    title: Mapped[str] = mapped_column(String(512))
    content: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)
    source: Mapped[str] = mapped_column(String(16), default="user")
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
