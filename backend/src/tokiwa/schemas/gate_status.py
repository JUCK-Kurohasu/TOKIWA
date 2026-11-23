"""GET /api/v1/gate/status: is the Gate policy actually being enforced? (audit #145)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class GateInstance(BaseModel):
    """One Gate (API token + source address) that has pulled the policy at least once."""

    model_config = ConfigDict(from_attributes=True)

    token_name: str
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    last_version: str
    last_status: int
    fetch_count: int
    current: bool = False  # last_version == the policy version right now
    stale: bool = False  # no poll for longer than stale_after_seconds


class GateActionReflection(BaseModel):
    """For one active Gate action: how many Gates pulled a policy that contains it."""

    action_id: str
    active_since: datetime
    gates_applied: int = 0  # Gates whose last poll happened after the action became active
    gates_applied_fresh: int = 0  # ... of which still polling (not stale)
    last_applied_at: datetime | None = None  # most recent such poll


class GateStatus(BaseModel):
    generated_at: datetime
    current_version: str
    stale_after_seconds: int
    gates: list[GateInstance] = Field(default_factory=list)
    actions: list[GateActionReflection] = Field(default_factory=list)
