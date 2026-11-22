"""Response suppressions (audit #63): "do not propose / auto-approve this again" after a human decision."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from tokiwa.schemas.common import ORMModel
from tokiwa.schemas.triage import ActionType

# Upper bound for a timed suppression (1 year). Longer means "permanent".
MAX_SUPPRESS_HOURS = 24 * 365


class SuppressionMode(StrEnum):
    # Automated proposals (rule / llm / policy) are dropped (audit only); user proposals are created but never
    # auto-approved.
    SUPPRESS = "suppress"
    # Proposals are created as usual but never auto-approved (written on every human reject / revert for
    # ``response.auto_approve_cooldown_minutes``).
    MANUAL_ONLY = "manual_only"


class SuppressOptions(BaseModel):
    """Optional part of a reject / revert request: stop re-proposals of the same type + target."""

    suppress_hours: int | None = Field(default=None, ge=1, le=MAX_SUPPRESS_HOURS)
    suppress_permanent: bool = False

    @property
    def requested(self) -> bool:
        return self.suppress_permanent or self.suppress_hours is not None


class ResponseSuppressionIn(SuppressOptions):
    """``POST /response/suppressions``: suppress a (type, target) proactively (e.g. a shared NAT address)."""

    action_type: ActionType
    target: str = Field(min_length=1, max_length=255)
    reason: str = Field(default="", max_length=2000)


class ResponseSuppression(ORMModel):
    id: str
    created_at: datetime
    updated_at: datetime
    action_type: ActionType
    target: str
    mode: SuppressionMode
    reason: str
    created_by: str
    source_action_id: str | None = None
    expires_at: datetime | None = None
    lifted_at: datetime | None = None
    lifted_by: str | None = None
    hits: int = 0
    last_hit_at: datetime | None = None
    # Computed when served: not lifted and not past expires_at.
    active: bool = False
