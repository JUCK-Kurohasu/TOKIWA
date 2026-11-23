"""Live stream (SSE) tickets (audit #100). See ``tokiwa.api.routes.stream``."""

from __future__ import annotations

from pydantic import BaseModel


class StreamTicket(BaseModel):
    """Single-use credential for ``GET /api/v1/stream?ticket=...`` (EventSource cannot send headers)."""

    ticket: str
    expires_in: int  # seconds
