"""Alert suppressions: false-positive feedback and allowlists for authorised testing (audit #166 / #173).

A ``false_positive`` row is written when an analyst marks an alert as a false positive: later drafts of the same
finding (same rule, matched signatures / selections within the marked set, same route and, by default, the same
source) are counted on the marked alert instead of becoming new alerts. An ``allowlist`` row declares a source
CIDR (optionally one rule / route) as authorised for a limited time, e.g. a vulnerability scan or a load test.
The detection engine consults the active rows in ``persist`` (``tokiwa.detect.suppress``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from tokiwa.db.base import Base, IdMixin, TimestampMixin


class AlertSuppressionRow(IdMixin, TimestampMixin, Base):
    __tablename__ = "alert_suppressions"

    kind: Mapped[str] = mapped_column(String(16), index=True)  # "false_positive" | "allowlist"
    # "suppress": no alert (counted here and, for false positives, on the marked alert).
    # "downgrade": the alert is recorded at info severity, tagged, and never published (no triage / notification
    # / incident / response proposal).
    mode: Mapped[str] = mapped_column(String(16), default="suppress")
    # None = any value.
    rule_id: Mapped[str | None] = mapped_column(String(128), default=None, index=True)
    path_key: Mapped[str | None] = mapped_column(String(255), default=None)
    source_cidr: Mapped[str | None] = mapped_column(String(64), default=None)
    # Normalised match of the marked alert: {"signatures": [...], "location": ..., "param": ...} for web.*,
    # {"selections": [...]} for Sigma, {} otherwise. A later draft matches when its set is a subset.
    match: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # False positives: drafts *above* this severity are not suppressed (escalation re-opens).
    max_severity: Mapped[str | None] = mapped_column(String(16), default=None)
    reason: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    source_alert_id: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(default=None, index=True)  # None = until lifted
    lifted_at: Mapped[datetime | None] = mapped_column(default=None)
    lifted_by: Mapped[str | None] = mapped_column(String(64), default=None)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    last_hit_at: Mapped[datetime | None] = mapped_column(default=None)
