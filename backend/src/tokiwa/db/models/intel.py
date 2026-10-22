"""Assets, vulnerabilities, matches, advisories, news items, research reports."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from tokiwa.db.base import Base, IdMixin, TimestampMixin
from tokiwa.util import utcnow


class AssetRow(IdMixin, TimestampMixin, Base):
    __tablename__ = "assets"
    name: Mapped[str] = mapped_column(String(255), index=True)
    kind: Mapped[str] = mapped_column(String(32), default="host")
    hostname: Mapped[str | None] = mapped_column(String(255), default=None, index=True)
    ips: Mapped[list[str]] = mapped_column(JSON, default=list)
    software: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    criticality: Mapped[str] = mapped_column(String(16), default="medium")
    owner: Mapped[str | None] = mapped_column(String(128), default=None)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    notes: Mapped[str | None] = mapped_column(Text, default=None)


class VulnRow(Base):
    __tablename__ = "vulns"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # CVE-YYYY-NNNN / GHSA-... / JVNDB-...
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)
    sources: Mapped[list[str]] = mapped_column(JSON, default=list)
    title: Mapped[str | None] = mapped_column(Text, default=None)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    published: Mapped[datetime | None] = mapped_column(default=None, index=True)
    modified: Mapped[datetime | None] = mapped_column(default=None, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, default=None)
    cvss_vector: Mapped[str | None] = mapped_column(String(256), default=None)
    severity: Mapped[str | None] = mapped_column(String(16), default=None)
    epss: Mapped[float | None] = mapped_column(Float, default=None, index=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, default=None)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_date_added: Mapped[datetime | None] = mapped_column(default=None)
    kev_due_date: Mapped[datetime | None] = mapped_column(default=None)
    kev_ransomware: Mapped[bool | None] = mapped_column(Boolean, default=None)
    cwe: Mapped[list[str]] = mapped_column(JSON, default=list)
    affected: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class VulnMatchRow(IdMixin, Base):
    __tablename__ = "vuln_matches"
    vuln_id: Mapped[str] = mapped_column(String(64), index=True)
    asset_id: Mapped[str] = mapped_column(String(64), index=True)
    software: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    reason: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class AdvisoryRow(IdMixin, Base):
    __tablename__ = "advisories"
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    vuln_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    title: Mapped[str] = mapped_column(String(512))
    priority: Mapped[str] = mapped_column(String(4), index=True)
    status: Mapped[str] = mapped_column(String(16), default="new")
    analysis: Mapped[dict[str, Any]] = mapped_column(JSON)
    llm_call_id: Mapped[str | None] = mapped_column(String(64), default=None)


class IntelItemRow(IdMixin, Base):
    __tablename__ = "intel_items"
    source: Mapped[str] = mapped_column(String(64), index=True)
    url: Mapped[str | None] = mapped_column(Text, default=None)
    url_hash: Mapped[str | None] = mapped_column(String(64), default=None, unique=True)
    title: Mapped[str] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text, default=None)
    published: Mapped[datetime | None] = mapped_column(default=None, index=True)
    fetched_at: Mapped[datetime] = mapped_column(default=utcnow)
    vuln_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    relevance: Mapped[float | None] = mapped_column(Float, default=None)


class ResearchReportRow(IdMixin, Base):
    __tablename__ = "research_reports"
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    topic: Mapped[str] = mapped_column(Text)
    output: Mapped[dict[str, Any]] = mapped_column(JSON)
    citations: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    llm_call_id: Mapped[str | None] = mapped_column(String(64), default=None)
