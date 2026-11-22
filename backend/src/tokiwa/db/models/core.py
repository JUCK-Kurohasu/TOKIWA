"""Users, API tokens, runtime settings, audit log."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from tokiwa.db.base import Base, IdMixin
from tokiwa.util import utcnow


class UserRow(IdMixin, Base):
    __tablename__ = "users"
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(16), default="analyst")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_login: Mapped[datetime | None] = mapped_column(default=None)


class ApiTokenRow(IdMixin, Base):
    __tablename__ = "api_tokens"
    name: Mapped[str] = mapped_column(String(64))
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(16))
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_used: Mapped[datetime | None] = mapped_column(default=None)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    # Ingest binding (audit #40). NULL = unrestricted (tokens created before these columns existed keep working).
    # allowed_sensor_ids: the server forces Event.sensor_id into this list (the client value goes to labels).
    # allowed_datasets: fnmatch patterns ("nginx.access", "host.*"); a batch with any other dataset is refused.
    allowed_sensor_ids: Mapped[list[str] | None] = mapped_column(JSON(none_as_null=True), default=None)
    allowed_datasets: Mapped[list[str] | None] = mapped_column(JSON(none_as_null=True), default=None)
    # Lifecycle (audit #163). NULL expires_at = never expires (the default, as before).
    expires_at: Mapped[datetime | None] = mapped_column(default=None)
    created_by: Mapped[str | None] = mapped_column(String(128), default=None)  # username or "cli"
    rotated_from: Mapped[str | None] = mapped_column(String(64), default=None)  # id of the token it replaced


class SettingRow(Base):
    """Runtime-editable settings (key -> JSON value). Keys are namespaced: "llm.config", "detection.overrides"."""

    __tablename__ = "settings_kv"
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class AuditRow(IdMixin, Base):
    __tablename__ = "audit_log"
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(128), index=True)
    target: Mapped[str | None] = mapped_column(String(256), default=None)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    note: Mapped[str | None] = mapped_column(Text, default=None)
