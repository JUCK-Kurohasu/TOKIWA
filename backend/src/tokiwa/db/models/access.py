"""Read-access log (audit #167): who looked at raw telemetry, with which filter, how many items.

Separate from ``audit_log`` (security decisions) because reads are far more frequent: one row covers all
identical reads (same actor, route, target and filter) within a window, see ``tokiwa.access_log``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from tokiwa.db.base import Base, IdMixin
from tokiwa.util import utcnow


class AccessLogRow(IdMixin, Base):
    __tablename__ = "access_log"
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)  # first read in the window
    last_at: Mapped[datetime] = mapped_column(default=utcnow)  # last read in the window
    actor: Mapped[str] = mapped_column(String(128), index=True)
    actor_id: Mapped[str | None] = mapped_column(String(64), default=None)
    role: Mapped[str | None] = mapped_column(String(16), default=None)
    route: Mapped[str] = mapped_column(
        String(128), index=True
    )  # "events.list", "copilot.tool.search_events" ...
    target: Mapped[str | None] = mapped_column(String(256), default=None)  # id for detail reads
    filters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    hits: Mapped[int] = mapped_column(Integer, default=1)  # identical reads merged into this row
    items: Mapped[int] = mapped_column(Integer, default=0)  # items returned, summed over hits
