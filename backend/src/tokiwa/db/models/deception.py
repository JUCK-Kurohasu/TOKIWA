"""Deception trip log (one row per event x asset). OWNER: deception module.

The assets themselves live in ``db/models/response.py`` (``DeceptionAssetRow``). Trips are kept separately so the
trip history survives event retention and can be filtered per asset cheaply.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from tokiwa.db.base import Base, IdMixin
from tokiwa.util import utcnow


class DeceptionTripRow(IdMixin, Base):
    __tablename__ = "deception_trips"
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    timestamp: Mapped[datetime] = mapped_column(index=True)  # event time
    asset_id: Mapped[str] = mapped_column(String(64), index=True)
    asset_kind: Mapped[str] = mapped_column(String(32))
    event_id: Mapped[str] = mapped_column(String(64), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    trip_type: Mapped[str] = mapped_column(String(32))
    ai_followed: Mapped[bool] = mapped_column(Boolean, default=False)
    # {token, fields, slots, path, method, user_agent, depth}
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
