"""Read-access log entries (audit #167). See ``tokiwa.access_log``."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from tokiwa.schemas.common import ORMModel


class AccessLogEntry(ORMModel):
    id: str
    created_at: datetime
    last_at: datetime
    actor: str
    actor_id: str | None = None
    role: str | None = None
    route: str
    target: str | None = None
    filters: dict[str, Any] = Field(default_factory=dict)
    hits: int = 1
    items: int = 0
