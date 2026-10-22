"""Events, actor sessions, host ports and port baselines."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from tokiwa.db.base import Base, IdMixin
from tokiwa.util import utcnow


class EventRow(Base):
    """Normalized events. Hot query fields are columns; the full Event document lives in ``data``."""

    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(index=True)
    ingested_at: Mapped[datetime] = mapped_column(default=utcnow)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    dataset: Mapped[str] = mapped_column(String(64), index=True)
    sensor_id: Mapped[str | None] = mapped_column(String(128), default=None)
    host_name: Mapped[str | None] = mapped_column(String(255), default=None, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, default=None)
    dest_ip: Mapped[str | None] = mapped_column(String(64), default=None)
    dest_port: Mapped[int | None] = mapped_column(Integer, default=None, index=True)
    http_method: Mapped[str | None] = mapped_column(String(16), default=None)
    http_host: Mapped[str | None] = mapped_column(String(255), default=None)
    http_path: Mapped[str | None] = mapped_column(Text, default=None)
    http_status: Mapped[int | None] = mapped_column(Integer, default=None)
    user_agent: Mapped[str | None] = mapped_column(Text, default=None)
    session_id: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    asset_id: Mapped[str | None] = mapped_column(String(64), default=None)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)

    __table_args__ = (Index("ix_events_source_ts", "source_ip", "timestamp"),)


class ActorSessionRow(IdMixin, Base):
    __tablename__ = "actor_sessions"
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    client_fingerprint: Mapped[str] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(Text, default=None)
    first_seen: Mapped[datetime] = mapped_column(index=True)
    last_seen: Mapped[datetime] = mapped_column(index=True)
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    unique_paths: Mapped[int] = mapped_column(Integer, default=0)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ai_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    classification: Mapped[str] = mapped_column(String(32), default="unknown")
    incident_id: Mapped[str | None] = mapped_column(String(64), default=None)


class HostPortRow(IdMixin, Base):
    """Current listening sockets per host (latest snapshot state)."""

    __tablename__ = "host_ports"
    host: Mapped[str] = mapped_column(String(255), index=True)
    protocol: Mapped[str] = mapped_column(String(8))
    bind_ip: Mapped[str] = mapped_column(String(64))
    port: Mapped[int] = mapped_column(Integer)
    pid: Mapped[int | None] = mapped_column(Integer, default=None)
    process_name: Mapped[str | None] = mapped_column(String(255), default=None)
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)
    open: Mapped[bool] = mapped_column(Boolean, default=True)


class PortBaselineRow(IdMixin, Base):
    """Allowed listeners (FR-02). host='*' applies to every host. process=None means any process."""

    __tablename__ = "port_baselines"
    host: Mapped[str] = mapped_column(String(255), default="*", index=True)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    port: Mapped[int] = mapped_column(Integer)
    process_name: Mapped[str | None] = mapped_column(String(255), default=None)
    allow_public: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
