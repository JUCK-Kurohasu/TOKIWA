"""Fixed output schemas for LLM triage (FR-07). The LLM must return exactly these shapes.

Anything outside these schemas is discarded. ``recommended_actions`` are *proposals* restricted to the
:class:`ActionType` allow-list and always go through the human approval workflow in :mod:`tokiwa.respond`.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from tokiwa.schemas.common import ActorType, Severity


class AttackStage(StrEnum):
    """MITRE ATT&CK enterprise tactics (subset relevant to network/web telemetry)."""

    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    NONE = "none"


class ActionType(StrEnum):
    """Allow-listed, reversible response actions (FR-12). Executors live in tokiwa.respond.executors."""

    BLOCK_IP = "block_ip"  # Gate deny-list (TTL)
    RATE_LIMIT = "rate_limit"  # Gate per-source rate limit (TTL)
    TARPIT = "tarpit"  # Gate adds latency to responses for the source (TTL)
    DECEIVE = "deceive"  # Gate routes the source into the Mirage decoy environment (TTL)
    DEPLOY_CANARY = "deploy_canary"  # plant an additional honeytoken / AI canary
    NOTIFY = "notify"  # page a human via notification channels
    WEBHOOK = "webhook"  # hand off to an external SOAR/firewall via webhook
    NFTABLES_BLOCK = "nftables_block"  # host firewall drop rule from a fixed template (disabled by default)


class RecommendedAction(BaseModel):
    action_type: ActionType
    target: str = Field(
        description="Target of the action, e.g. an IP address or CIDR. Must appear in evidence."
    )
    reason: str
    ttl_minutes: int | None = Field(default=None, ge=1, le=10080)


class TriageResult(BaseModel):
    """LLM output for a single alert or incident."""

    severity: Severity
    category: str = Field(description="Short machine-friendly category, e.g. sqli, recon, ai_agent_recon")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence that this is a true positive")
    actor_type: ActorType
    ai_agent_likelihood: float = Field(
        ge=0.0, le=1.0, description="Likelihood the activity is driven by an autonomous LLM agent"
    )
    ai_agent_indicators: list[str] = Field(default_factory=list, max_length=10)
    attack_stage: AttackStage
    mitre_techniques: list[str] = Field(default_factory=list, max_length=10, description="e.g. T1190")
    summary: str = Field(description="1-3 sentence summary for an analyst")
    rationale: str = Field(description="Why this verdict, referencing evidence ids")
    evidence_ids: list[str] = Field(description="IDs of events supporting the verdict. Must exist.")
    next_steps: list[str] = Field(default_factory=list, max_length=8)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list, max_length=5)


class TriageRecord(BaseModel):
    """Stored alongside an alert/incident: the verdict plus provenance (audit, NFR)."""

    result: TriageResult
    tier: str  # fast | deep | rules
    model: str | None = None
    prompt_version: str
    llm_call_id: str | None = None
    escalated: bool = False
    rejected_evidence_ids: list[str] = Field(default_factory=list)
