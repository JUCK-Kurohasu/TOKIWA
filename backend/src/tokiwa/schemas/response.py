"""Response actions (XDR, FR-12), deception assets, notification channels, gate policy."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from tokiwa.schemas.common import ORMModel, Severity
from tokiwa.schemas.triage import ActionType


class ActionStatus(StrEnum):
    PROPOSED = "proposed"  # waiting for human approval
    APPROVED = "approved"  # approved, executor pending
    ACTIVE = "active"  # executed and in effect (until expires_at)
    EXPIRED = "expired"
    REVERTED = "reverted"
    REJECTED = "rejected"
    FAILED = "failed"


class ActionProposer(StrEnum):
    RULE = "rule"
    LLM = "llm"
    USER = "user"
    POLICY = "policy"


class ActionProposal(BaseModel):
    action_type: ActionType
    target: str
    params: dict[str, Any] = Field(default_factory=dict)
    reason: str
    ttl_minutes: int | None = None
    incident_id: str | None = None
    alert_id: str | None = None
    proposed_by: ActionProposer = ActionProposer.USER


class ResponseAction(ORMModel):
    id: str
    created_at: datetime
    updated_at: datetime
    action_type: ActionType
    target: str
    params: dict[str, Any]
    reason: str
    proposed_by: ActionProposer
    incident_id: str | None
    alert_id: str | None
    status: ActionStatus
    reversible: bool
    ttl_minutes: int | None
    approved_by: str | None
    approved_at: datetime | None
    executed_at: datetime | None
    expires_at: datetime | None
    reverted_at: datetime | None
    result: dict[str, Any]
    # Audit #130: who proposed it through the API (None for rule / llm / policy), and later proposals made after
    # approval (kept apart from ``reason``, which stays what the approver saw).
    proposed_by_user: str | None = None
    notes: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("notes", mode="before")
    @classmethod
    def _notes(cls, v: Any) -> Any:
        return [] if v is None else v


class DecoyRoute(BaseModel):
    """A decoy served directly by the Gate (never forwarded upstream). Body is pre-rendered by the server."""

    asset_id: str
    kind: str  # DeceptionKind value
    path: str  # exact path, or prefix when ending with "*"
    status_code: int = 200
    content_type: str = "text/plain; charset=utf-8"
    body: str = ""
    headers: dict[str, str] = Field(default_factory=dict)


class GatePolicy(BaseModel):
    """What TOKIWA Gate pulls from the server (GET /api/v1/gate/policy, token scope "gate")."""

    version: str  # content hash; the gate only swaps policy when it changes
    generated_at: datetime
    blocked: list[str] = Field(default_factory=list)  # IPs / CIDRs -> 403
    rate_limited: dict[str, int] = Field(default_factory=dict)  # ip/cidr -> max requests per minute
    tarpit: dict[str, int] = Field(default_factory=dict)  # ip/cidr -> added latency in ms
    deceive: list[str] = Field(default_factory=list)  # ip/cidr -> every request served from Mirage decoys
    decoys: list[DecoyRoute] = Field(default_factory=list)
    # HTML snippet (e.g. hidden AI-canary instruction) the gate inserts into upstream HTML responses.
    # None = disabled.
    html_injection: str | None = None
    # Audit #64: {"blocked" | "rate_limited" | "tarpit" | "deceive": {entry: expires_at}}. Entries without an
    # expiry are absent. The Gate lifts an entry at (its receive time + expires_at - generated_at) even while it
    # cannot reach the server (fail-static keeps the last policy, but never past these expiries).
    entry_expires_at: dict[str, dict[str, datetime]] = Field(default_factory=dict)
    # Where: "head" (the snippet's leading HTML comment, after <head>), "body_start" (after <body>), "body_end"
    # (before the last </body>). None = ["body_end"] (servers before audit #41). Plain strings so a gate ignores
    # positions it does not know instead of rejecting the whole policy.
    html_injection_positions: list[str] | None = None


class DeceptionKind(StrEnum):
    HONEYTOKEN = "honeytoken"  # fake credential / API key planted in a decoy
    DECOY_PATH = "decoy_path"  # a path that no legitimate user should request
    AI_CANARY = "ai_canary"  # hidden instruction only an LLM agent would follow ("reverse prompt injection")
    LABYRINTH = "labyrinth"  # generated maze of plausible pages to waste agent tokens


class DeceptionAssetIn(BaseModel):
    kind: DeceptionKind
    name: str
    path: str | None = None  # where it is served (decoy_path / ai_canary page)
    token: str | None = None  # canary value; generated when omitted
    content_template: str | None = None
    description: str | None = None
    enabled: bool = True


class DeceptionAsset(DeceptionAssetIn, ORMModel):
    id: str
    created_at: datetime
    trip_count: int
    last_tripped: datetime | None


class ChannelKind(StrEnum):
    WEBHOOK = "webhook"
    SLACK = "slack"
    DISCORD = "discord"
    EMAIL = "email"


class NotificationChannelIn(BaseModel):
    kind: ChannelKind
    name: str
    config: dict[str, Any] = Field(default_factory=dict)  # url / smtp settings; secrets masked on read
    min_severity: Severity = Severity.HIGH
    enabled: bool = True


class NotificationChannel(NotificationChannelIn, ORMModel):
    id: str
    created_at: datetime
