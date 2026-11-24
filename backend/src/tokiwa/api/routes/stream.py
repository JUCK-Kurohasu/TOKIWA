"""Live Server-Sent Events stream relaying selected bus topics to the UI.

Each message is ``data: {"topic": "...", "data": {...}}``. Relayed topics: ``alert.*``, ``incident.*``,
``action.*``, ``deception.tripped``, ``intel.advisory``, ``llm.call`` and ``event.ingested`` (reduced to
``{"count": n}`` so raw telemetry never leaves through the stream). A keep-alive comment is sent every 15 s.

Authentication (EventSource cannot set headers): the UI first calls ``POST /api/v1/stream/ticket`` with its JWT in
the Authorization header and opens ``GET /api/v1/stream?ticket=<ticket>``. A ticket is valid for
:data:`TICKET_TTL_SECONDS` and for one connection only, and the JWT behind it is checked again (expiry, revocation)
when it is redeemed (audit #100: a 12-hour JWT in the query string ended up in reverse-proxy access logs, which TOKIWA
cannot redact). ``Authorization: Bearer`` also works for non-browser clients. The old ``?access_token=<JWT>`` is
still accepted for compatibility but deprecated (WARNING, at most every 10 minutes).

Tickets live in process memory, like the bus the stream relays: TOKIWA serves the stream from a single process.

The DB session used for the check is closed before streaming starts: a long-lived SSE connection must not pin a
pooled connection. :class:`RedactAccessToken` masks ``access_token=`` and ``ticket=`` in uvicorn's access log
(AGENTS.md §2: no secrets in logs).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import secrets
import time
from collections.abc import AsyncIterator, Callable, Sized
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from pydantic import BaseModel
from pydantic_core import to_jsonable_python
from sse_starlette import EventSourceResponse, ServerSentEvent
from starlette.background import BackgroundTask

from tokiwa.api.deps import CurrentUser, _bearer, user_from_token
from tokiwa.bus import bus
from tokiwa.db.session import session_scope
from tokiwa.schemas.stream import StreamTicket
from tokiwa.schemas.system import User

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["stream"])

KEEPALIVE_SECONDS: float = 15
RELAY_PREFIXES = ("alert.", "incident.", "action.")
RELAY_TOPICS = frozenset({"deception.tripped", "intel.advisory", "llm.call", "event.ingested"})
# LLMCallDetail-only fields: prompts/responses are admin-only (GET /llm/calls/{id}), never broadcast.
_LLM_PRIVATE_FIELDS = ("request_redacted", "response_text")


_ACCESS_TOKEN_QS = re.compile(r"(?i)((?<![\w-])(?:access_token|ticket)=)[^&\s\"]+")


class RedactAccessToken(logging.Filter):
    """Mask ``access_token=`` / ``ticket=`` query values in access-log records (uvicorn logs the full path)."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(
                _ACCESS_TOKEN_QS.sub(r"\1[REDACTED]", a) if isinstance(a, str) else a for a in record.args
            )
        if isinstance(record.msg, str):
            record.msg = _ACCESS_TOKEN_QS.sub(r"\1[REDACTED]", record.msg)
        return True


def install_access_log_redaction(logger_name: str = "uvicorn.access") -> None:
    target = logging.getLogger(logger_name)
    if not any(isinstance(f, RedactAccessToken) for f in target.filters):
        target.addFilter(RedactAccessToken())


# TODO(integration): move to the app factory / logging setup; done here to stay within api-core's files.
install_access_log_redaction()


def is_relayed(topic: str) -> bool:
    return topic in RELAY_TOPICS or topic.startswith(RELAY_PREFIXES)


def to_message(topic: str, payload: Any) -> dict[str, Any]:
    """Convert a bus payload into the JSON-safe ``{"topic", "data"}`` envelope sent to clients."""
    data: Any
    if topic == "event.ingested":
        data = {"count": len(payload) if isinstance(payload, Sized) else 1}
    elif isinstance(payload, BaseModel):
        data = payload.model_dump(mode="json")
    else:
        data = to_jsonable_python(payload, fallback=str)
    if topic == "llm.call" and isinstance(data, dict):
        for key in _LLM_PRIVATE_FIELDS:
            data.pop(key, None)
    return {"topic": topic, "data": data}


# ---------------------------------------------------------------------------------------------------------
# Tickets (audit #100)
# ---------------------------------------------------------------------------------------------------------
TICKET_TTL_SECONDS: int = 60
MAX_TICKETS_PER_USER = 16
MAX_TICKETS = 10_000
LEGACY_WARN_INTERVAL_SECONDS = 600.0


@dataclass(slots=True)
class _Ticket:
    jwt: str
    user_id: str
    expires_at: float


class TicketStore:
    """Single-use, short-lived stream tickets. Only a SHA-256 of each ticket is kept as the key.

    A ticket maps to the JWT it was issued for, so redeeming it re-runs the normal JWT checks (a logout or password
    change in between still ends access). Per-user and global caps keep an authenticated client from growing the
    store without bound: the oldest tickets are dropped first.
    """

    def __init__(
        self, ttl_seconds: float = TICKET_TTL_SECONDS, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self._tickets: dict[str, _Ticket] = {}

    @staticmethod
    def _key(ticket: str) -> str:
        return hashlib.sha256(ticket.encode("utf-8", "surrogatepass")).hexdigest()

    def __len__(self) -> int:
        return len(self._tickets)

    def _purge(self, now: float) -> None:
        for key in [k for k, t in self._tickets.items() if t.expires_at <= now]:
            del self._tickets[key]

    def issue(self, user_id: str, jwt: str) -> str:
        now = self.clock()
        self._purge(now)
        mine = [k for k, t in self._tickets.items() if t.user_id == user_id]  # insertion order = oldest first
        for key in mine[: max(0, len(mine) - MAX_TICKETS_PER_USER + 1)]:
            del self._tickets[key]
        while len(self._tickets) >= MAX_TICKETS:
            del self._tickets[next(iter(self._tickets))]
        ticket = secrets.token_urlsafe(32)
        self._tickets[self._key(ticket)] = _Ticket(jwt, user_id, now + self.ttl_seconds)
        return ticket

    def redeem(self, ticket: str) -> str | None:
        """The JWT behind ``ticket``, or ``None`` if it is unknown, used or expired. A ticket works once."""
        entry = self._tickets.pop(self._key(ticket), None)
        if entry is None or entry.expires_at <= self.clock():
            return None
        return entry.jwt

    def clear(self) -> None:
        self._tickets.clear()


tickets = TicketStore()
_legacy_warned_at: float | None = None


def _warn_legacy_query_token() -> None:
    global _legacy_warned_at
    now = time.monotonic()
    if _legacy_warned_at is not None and now - _legacy_warned_at < LEGACY_WARN_INTERVAL_SECONDS:
        return
    _legacy_warned_at = now
    log.warning(
        "GET /api/v1/stream?access_token= is deprecated: the JWT ends up in reverse-proxy access logs. "
        "Use POST /api/v1/stream/ticket and ?ticket= (or an Authorization header)"
    )


async def _stream_user(
    authorization: Annotated[str | None, Header()] = None,
    ticket: Annotated[
        str | None, Query(description="Single-use ticket from POST /api/v1/stream/ticket", max_length=256)
    ] = None,
    access_token: Annotated[
        str | None,
        Query(
            description="Deprecated: JWT in the query string (leaks into proxy logs). Use ticket.",
            deprecated=True,
        ),
    ] = None,
) -> User:
    token = _bearer(authorization)
    if token is None and ticket:
        token = tickets.redeem(ticket)
        if token is None:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "invalid or expired ticket",
                headers={"WWW-Authenticate": "Bearer"},
            )
    if token is None and access_token:
        _warn_legacy_query_token()
        token = access_token
    async with session_scope() as session:
        return await user_from_token(session, token)


@router.post("/stream/ticket", response_model=StreamTicket)
async def stream_ticket(
    user: CurrentUser,
    response: Response,
    authorization: Annotated[str | None, Header()] = None,
) -> StreamTicket:
    """Issue a single-use ticket (valid :data:`TICKET_TTL_SECONDS`) for opening the live stream."""
    jwt = _bearer(authorization)
    assert jwt is not None  # CurrentUser accepted it
    response.headers["Cache-Control"] = "no-store"
    return StreamTicket(ticket=tickets.issue(user.id, jwt), expires_in=TICKET_TTL_SECONDS)


async def _relay(queue: asyncio.Queue[tuple[str, Any]]) -> AsyncIterator[ServerSentEvent]:
    try:
        # Initial comment: flushes headers through proxies and tells clients the listener is registered.
        yield ServerSentEvent(comment="connected")
        while True:
            topic, payload = await queue.get()
            if not is_relayed(topic):
                continue
            try:
                message = json.dumps(to_message(topic, payload), ensure_ascii=False, separators=(",", ":"))
            except Exception:
                log.exception("failed to serialize bus payload for topic %s", topic)
                continue
            yield ServerSentEvent(data=message)
    finally:
        bus.unlisten(queue)


@router.get("/stream", response_class=EventSourceResponse)
async def stream(user: Annotated[User, Depends(_stream_user)]) -> EventSourceResponse:
    queue = bus.listen()
    return EventSourceResponse(
        _relay(queue),
        ping=KEEPALIVE_SECONDS,
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        # Runs after the stream ends for any reason (also when the generator never started).
        background=BackgroundTask(bus.unlisten, queue),
    )
