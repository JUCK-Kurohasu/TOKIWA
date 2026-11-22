"""Authentication state that is not a user row (owned by the auth module).

``UserRow`` / ``ApiTokenRow`` live in ``core.py``; tables added for account protection live here.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from tokiwa.db.base import Base

AUTH_STATE_ID = "auth"


class AuthStateRow(Base):
    """Singleton row (``id == "auth"``) that records that the first-run setup has happened.

    Why a separate row instead of "no users yet": the unauthenticated ``POST /auth/setup`` must never reopen once
    an installation has been set up, even if the user table later becomes empty (#170). The primary key also
    serializes two concurrent setup requests on every database: the second INSERT conflicts (#95).
    """

    __tablename__ = "auth_state"
    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    setup_completed_at: Mapped[datetime | None] = mapped_column(default=None)
    setup_completed_by: Mapped[str | None] = mapped_column(String(64), default=None)
