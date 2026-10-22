"""Response actions, deception assets, notification channels."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from tokiwa.db.base import Base, IdMixin, TimestampMixin
from tokiwa.util import utcnow


class ResponseActionRow(IdMixin, TimestampMixin, Base):
    __tablename__ = "response_actions"
    action_type: Mapped[str] = mapped_column(String(32), index=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    reason: Mapped[str] = mapped_column(Text, default="")
    proposed_by: Mapped[str] = mapped_column(String(16), default="user")
    incident_id: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    alert_id: Mapped[str | None] = mapped_column(String(64), default=None)
    status: Mapped[str] = mapped_column(String(16), default="proposed", index=True)
    reversible: Mapped[bool] = mapped_column(Boolean, default=True)
    ttl_minutes: Mapped[int | None] = mapped_column(Integer, default=None)
    approved_by: Mapped[str | None] = mapped_column(String(64), default=None)
    approved_at: Mapped[datetime | None] = mapped_column(default=None)
    executed_at: Mapped[datetime | None] = mapped_column(default=None)
    expires_at: Mapped[datetime | None] = mapped_column(default=None, index=True)
    reverted_at: Mapped[datetime | None] = mapped_column(default=None)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class DeceptionAssetRow(IdMixin, Base):
    __tablename__ = "deception_assets"
    kind: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(255))
    path: Mapped[str | None] = mapped_column(Text, default=None)
    token: Mapped[str | None] = mapped_column(String(255), default=None, index=True)
    content_template: Mapped[str | None] = mapped_column(Text, default=None)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    trip_count: Mapped[int] = mapped_column(Integer, default=0)
    last_tripped: Mapped[datetime | None] = mapped_column(default=None)


class NotificationChannelRow(IdMixin, Base):
    __tablename__ = "notification_channels"
    kind: Mapped[str] = mapped_column(String(16))
    name: Mapped[str] = mapped_column(String(128))
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    min_severity: Mapped[str] = mapped_column(String(16), default="high")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
