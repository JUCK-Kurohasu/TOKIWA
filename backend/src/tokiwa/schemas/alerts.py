"""Alerts (FR-06), incidents and actor sessions."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from tokiwa.schemas.common import ActorType, ORMModel, Severity
from tokiwa.schemas.events import Event
from tokiwa.schemas.triage import TriageRecord


class AlertStatus(StrEnum):
    NEW = "new"
    TRIAGING = "triaging"
    TRIAGED = "triaged"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertCategory(StrEnum):
    """Top-level categories. Detectors may use finer-grained ``tags``."""

    RECON = "recon"
    SCAN = "scan"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    CREDENTIAL_ATTACK = "credential_attack"
    AI_AGENT = "ai_agent"  # behaviour attributed to an autonomous LLM agent
    PROMPT_INJECTION = "prompt_injection"  # attacks against protected LLM applications
    DECEPTION = "deception"  # decoy / honeytoken / AI-canary interaction (high fidelity)
    PORT_DEVIATION = "port_deviation"
    POLICY = "policy"
    VULN_EXPOSURE = "vuln_exposure"  # an asset is affected by a known-exploited / high-EPSS vuln
    IDS = "ids"
    ANOMALY = "anomaly"
    OTHER = "other"


class AlertDraft(BaseModel):
    """What a detector returns. The detection engine turns drafts into persisted :class:`Alert` rows."""

    rule_id: str
    title: str
    description: str = ""
    severity: Severity
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    category: AlertCategory
    mitre: list[str] = Field(default_factory=list)
    # 0..1 likelihood the actor is an autonomous AI agent (None = not assessed by this detector)
    ai_score: float | None = Field(default=None, ge=0.0, le=1.0)
    source_ip: str | None = None
    # Entities for correlation, e.g. {"host": "web-1", "port": "8080", "cve": "CVE-2025-..."}
    entities: dict[str, str] = Field(default_factory=dict)
    evidence_event_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    # Dedup key. Same fingerprint within the dedup window increments ``count`` instead of a new alert.
    # Default (when None): rule_id + source_ip.
    fingerprint: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class Alert(ORMModel):
    id: str
    created_at: datetime
    updated_at: datetime
    first_seen: datetime
    last_seen: datetime
    count: int
    fingerprint: str
    rule_id: str
    detector: str  # registry id of the detector (or "sigma:<rule id>")
    title: str
    description: str
    severity: Severity
    confidence: float
    category: AlertCategory
    mitre: list[str]
    ai_score: float | None
    source_ip: str | None
    entities: dict[str, str]
    evidence_event_ids: list[str]
    tags: list[str]
    details: dict[str, Any]
    status: AlertStatus
    incident_id: str | None
    triage: TriageRecord | None


class AlertDetail(Alert):
    evidence: list[Event] = Field(default_factory=list)


class AlertUpdate(BaseModel):
    status: AlertStatus | None = None
    tags: list[str] | None = None


class IncidentStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Incident(ORMModel):
    id: str
    created_at: datetime
    updated_at: datetime
    first_seen: datetime
    last_seen: datetime
    title: str
    summary: str
    severity: Severity
    status: IncidentStatus
    category: AlertCategory
    actor_type: ActorType
    ai_score: float | None
    source_ips: list[str]
    alert_count: int
    # Ordered ATT&CK tactics observed (kill-chain progression)
    kill_chain: list[str]
    mitre: list[str]
    triage: TriageRecord | None
    assignee: str | None
    tags: list[str]


class IncidentDetail(Incident):
    alerts: list[Alert] = Field(default_factory=list)
    # Response actions linked to the incident (tokiwa.schemas.response.ResponseAction as dicts to avoid cycles)
    actions: list[dict[str, Any]] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    status: IncidentStatus | None = None
    assignee: str | None = None
    tags: list[str] | None = None


class ActorSession(ORMModel):
    """A sequence of activity from one actor (source IP + client fingerprint) bounded by an idle timeout.

    ``features`` holds the behavioural features used for AI-agent attribution (inter-request timing,
    burstiness, payload mutation rate, endpoint discovery breadth ...). See docs/detection/ai-attacks.md.
    """

    id: str
    source_ip: str
    client_fingerprint: str
    user_agent: str | None
    first_seen: datetime
    last_seen: datetime
    request_count: int
    error_count: int
    unique_paths: int
    features: dict[str, Any]
    ai_score: float
    classification: ActorType
    incident_id: str | None
