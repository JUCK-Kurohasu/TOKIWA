"""User administration request models (routes/users.py). ``User`` / ``UserCreate`` live in schemas/system.py."""

from __future__ import annotations

from pydantic import BaseModel, Field

from tokiwa.schemas.system import Role


class UserUpdate(BaseModel):
    """Partial update by an admin. The last remaining admin cannot be demoted."""

    role: Role | None = None
    password: str | None = Field(default=None, min_length=10, max_length=256)
