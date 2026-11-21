"""Auth request models added after v0.1 (``User`` / ``UserCreate`` / ``LoginRequest`` live in schemas/system.py)."""

from __future__ import annotations

from pydantic import Field

from tokiwa.schemas.system import UserCreate


class SetupRequest(UserCreate):
    """``POST /auth/setup``. ``role`` is ignored: the first user is always an admin."""

    # One-time code from the server log / data_dir/setup-code (required unless auth.setup_code_required=false).
    setup_code: str | None = Field(default=None, max_length=64)
