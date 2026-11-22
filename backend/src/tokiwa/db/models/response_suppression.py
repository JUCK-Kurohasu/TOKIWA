"""Response suppressions: what a human said "do not do this again" about (audit #63).

A row is written when an analyst rejects a proposal or reverts an active action, and can be created or lifted
through the API. ``create_proposal`` consults it so that a rejected / reverted (type, target) is not proposed
again by the rule engine or the LLM, and is never auto-approved while the row is in force.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from tokiwa.db.base import Base, IdMixin, TimestampMixin


class ResponseSuppressionRow(IdMixin, TimestampMixin, Base):
    __tablename__ = "response_suppressions"

    action_type: Mapped[str] = mapped_column(String(32), index=True)
    # Normalized like ResponseActionRow.target (IP / CIDR, path or identifier).
    target: Mapped[str] = mapped_column(String(255), index=True)
    # "suppress": automated proposals (rule / llm) are dropped, user proposals are never auto-approved.
    # "manual_only": proposals are still created but never auto-approved.
    mode: Mapped[str] = mapped_column(String(16), default="suppress")
    reason: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    # The rejected / reverted action that produced this row (None when created directly).
    source_action_id: Mapped[str | None] = mapped_column(String(64), default=None)
    # None = permanent (until lifted).
    expires_at: Mapped[datetime | None] = mapped_column(default=None, index=True)
    lifted_at: Mapped[datetime | None] = mapped_column(default=None)
    lifted_by: Mapped[str | None] = mapped_column(String(64), default=None)
    # How many proposals this row stopped / downgraded (for the UI and tuning).
    hits: Mapped[int] = mapped_column(Integer, default=0)
    last_hit_at: Mapped[datetime | None] = mapped_column(default=None)
