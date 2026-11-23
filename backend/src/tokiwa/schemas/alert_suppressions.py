"""Alert suppressions (audit #166 / #173): false-positive feedback and allowlists for authorised testing."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from tokiwa.schemas.common import ORMModel

# Upper bound for a timed suppression (1 year), as for response suppressions.
MAX_ALERT_SUPPRESS_HOURS = 24 * 365


class AlertSuppressionKind(StrEnum):
    # Written when an alert is marked false_positive: the same finding (rule, matched signatures within the marked
    # set, route, source) is counted on that alert instead of raising a new one.
    FALSE_POSITIVE = "false_positive"
    # Declared ahead of time for an authorised scan / load test: a source CIDR (optionally one rule / route) for a
    # limited time.
    ALLOWLIST = "allowlist"


class AlertSuppressionMode(StrEnum):
    SUPPRESS = "suppress"  # no alert at all (counted on the suppression)
    DOWNGRADE = "downgrade"  # recorded at info severity, never triaged / notified / correlated


class AlertSuppressionIn(BaseModel):
    """``POST /alert-suppressions``. Allowlists need ``source_cidr`` and ``hours``."""

    kind: AlertSuppressionKind = AlertSuppressionKind.ALLOWLIST
    mode: AlertSuppressionMode = AlertSuppressionMode.DOWNGRADE
    source_cidr: str | None = Field(default=None, max_length=64)
    rule_id: str | None = Field(default=None, max_length=128)
    path: str | None = Field(
        default=None, max_length=512, description="request path; stored as its route key"
    )
    hours: float | None = Field(default=None, gt=0, le=MAX_ALERT_SUPPRESS_HOURS)
    reason: str = Field(default="", max_length=2000)


class AlertSuppression(ORMModel):
    id: str
    created_at: datetime
    updated_at: datetime
    kind: AlertSuppressionKind
    mode: AlertSuppressionMode
    rule_id: str | None = None
    path_key: str | None = None
    source_cidr: str | None = None
    match: dict[str, Any] = Field(default_factory=dict)
    max_severity: str | None = None
    reason: str = ""
    created_by: str = ""
    source_alert_id: str | None = None
    expires_at: datetime | None = None
    lifted_at: datetime | None = None
    lifted_by: str | None = None
    hits: int = 0
    last_hit_at: datetime | None = None
    # Computed when served: not lifted and not past expires_at.
    active: bool = False
