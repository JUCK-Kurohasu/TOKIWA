"""Which TOKIWA Gates pulled the policy, and when (audit #145).

One row per Gate instance, keyed by (API token, source address). Upserted on every ``GET /api/v1/gate/policy``
(200 and 304), so the table stays small however often Gates poll. Read by ``GET /api/v1/gate/status`` to tell
"approved but no Gate has it yet" from "enforced by n Gates".
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from tokiwa.db.base import Base
from tokiwa.util import utcnow


class GatePollRow(Base):
    __tablename__ = "gate_polls"

    # sha256(token_id | source_ip)[:32]: deterministic so concurrent first polls collide on the primary key.
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    token_id: Mapped[str] = mapped_column(String(64), index=True)
    token_name: Mapped[str] = mapped_column(String(128))
    # request.client.host. Behind a reverse proxy this is the proxy's address (X-Forwarded-For is not trusted).
    source_ip: Mapped[str] = mapped_column(String(64))
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    # ``generated_at`` of the policy served by the last poll (taken before the policy query).
    last_seen: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    last_version: Mapped[str] = mapped_column(String(64))
    last_status: Mapped[int] = mapped_column(Integer, default=200)  # 200 or 304
    fetch_count: Mapped[int] = mapped_column(Integer, default=0)
