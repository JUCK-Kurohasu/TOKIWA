"""Live Server-Sent Events stream relaying selected bus topics to the UI.

Each message is ``data: {"topic": "...", "data": {...}}``. Relayed topics: ``alert.*``, ``incident.*``,
``action.*``, ``deception.tripped``, ``intel.advisory``, ``llm.call`` and ``event.ingested`` (reduced to
``{"count": n}`` so raw telemetry never leaves through the stream). A keep-alive comment is sent every 15 s.

Authentication uses ``?access_token=<JWT>`` because EventSource cannot set headers. The DB session used for
that check is closed before streaming starts: a long-lived SSE connection must not pin a pooled connection.
Because the JWT travels in the query string, :class:`RedactAccessToken` masks it in uvicorn's access log
(AGENTS.md §2: no secrets in logs).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import AsyncIterator, Sized
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Query
from pydantic import BaseModel
from pydantic_core import to_jsonable_python
from sse_starlette import EventSourceResponse, ServerSentEvent
from starlette.background import BackgroundTask

from tokiwa.api.deps import get_current_user
from tokiwa.bus import bus
from tokiwa.db.session import session_scope
from tokiwa.schemas.system import User

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["stream"])

KEEPALIVE_SECONDS: float = 15
RELAY_PREFIXES = ("alert.", "incident.", "action.")
RELAY_TOPICS = frozenset({"deception.tripped", "intel.advisory", "llm.call", "event.ingested"})
# LLMCallDetail-only fields: prompts/responses are admin-only (GET /llm/calls/{id}), never broadcast.
_LLM_PRIVATE_FIELDS = ("request_redacted", "response_text")


_ACCESS_TOKEN_QS = re.compile(r"(?i)(access_token=)[^&\s\"]+")


class RedactAccessToken(logging.Filter):
    """Mask ``access_token=`` query values in access-log records (uvicorn logs the full request path)."""

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


async def _stream_user(
    authorization: Annotated[str | None, Header()] = None,
    access_token: Annotated[
        str | None, Query(description="JWT (EventSource cannot send an Authorization header)")
    ] = None,
) -> User:
    async with session_scope() as session:
        return await get_current_user(session, authorization, access_token)


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
