"""Aggregated read models for the dashboard and event statistics (routes/dashboard.py, routes/events.py)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from tokiwa.schemas.alerts import Incident


class AlertCounts(BaseModel):
    total: int = 0
    # Every Severity value is present (0 when none) so the UI can render a fixed legend.
    by_severity: dict[str, int] = Field(default_factory=dict)


class TopSource(BaseModel):
    ip: str
    count: int  # sum of alert hit counts in the window
    ai_score: float | None = None  # max AI-agent likelihood seen on those alerts


class TopRule(BaseModel):
    rule_id: str
    title: str
    count: int  # sum of alert hit counts in the window


class DashboardSummary(BaseModel):
    alerts_24h: AlertCounts
    open_incidents: int = 0
    ai_sessions_24h: int = 0
    events_24h: int = 0
    llm_cost_today_usd: float = 0.0
    llm_budget_usd: float = 0.0
    pending_actions: int = 0
    kev_matches: int = 0
    top_sources: list[TopSource] = Field(default_factory=list)
    top_rules: list[TopRule] = Field(default_factory=list)
    recent_incidents: list[Incident] = Field(default_factory=list)


class DashboardBucket(BaseModel):
    ts: datetime  # bucket start (UTC)
    events: int = 0
    alerts: int = 0
    ai_alerts: int = 0


class DashboardTimeline(BaseModel):
    bucket_minutes: int
    buckets: list[DashboardBucket]


class EventTimelineBucket(BaseModel):
    ts: datetime  # bucket start (UTC)
    total: int = 0
    by_kind: dict[str, int] = Field(default_factory=dict)


class EventTimeline(BaseModel):
    bucket_minutes: int
    buckets: list[EventTimelineBucket]
