"""SOC Copilot API (docs/api-contract.md「コパイロット」).

Conversations are private to their owner; admins can read and delete any conversation (``?all=true`` lists
everyone's). Only the owner can post messages. Posting returns an SSE stream of
``data: {"type": "text"|"tool_call"|"tool_result"|"error"|"done", ...}`` events that always ends with ``done``.

Cost control (audit #164): a message can drive up to ``copilot.max_tool_iterations`` deep-tier LLM calls against
the one shared daily budget, so a viewer account could starve triage. Creating conversations and posting require
``copilot.min_role`` (default analyst), and each user is limited to ``copilot.messages_per_minute`` (429).
"""

from __future__ import annotations

import json
import math
import time
from collections import deque
from collections.abc import AsyncIterator, Callable
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Response, status
from sse_starlette import EventSourceResponse

from tokiwa.api.deps import CurrentUser, DbSession
from tokiwa.config import get_settings
from tokiwa.copilot import service
from tokiwa.copilot.schemas import Conversation, ConversationCreate, ConversationDetail, MessageCreate
from tokiwa.db.models.llm import CopilotConversationRow
from tokiwa.schemas.system import Role, User

router = APIRouter(prefix="/api/v1/copilot", tags=["copilot"])

_ROLE_RANK = {Role.VIEWER: 0, Role.ANALYST: 1, Role.ADMIN: 2}


def _require_copilot_role(user: User) -> None:
    need = Role(get_settings().copilot.min_role)
    if _ROLE_RANK.get(user.role, 0) < _ROLE_RANK[need]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"copilot requires role {need.value} or higher")


class UserRateLimiter:
    """Sliding 60 s window per user id (in-process; one worker = one budget, good enough for a lab-scale SIEM).

    Keyed by user id, not username: ids are never reused, so a deleted and re-created user starts clean.
    """

    WINDOW = 60.0

    def __init__(self, clock: Callable[[], float] = time.monotonic, max_users: int = 10_000) -> None:
        self._clock = clock
        self._max_users = max_users
        self._hits: dict[str, deque[float]] = {}

    def check(self, key: str, limit: int) -> float | None:
        """Record one hit; returns None when allowed, else seconds until the next slot frees up."""
        if limit <= 0:
            return None
        now = self._clock()
        hits = self._hits.setdefault(key, deque())
        while hits and now - hits[0] >= self.WINDOW:
            hits.popleft()
        if len(hits) >= limit:
            return self.WINDOW - (now - hits[0])
        hits.append(now)
        if len(self._hits) > self._max_users:  # bound memory: forget idle users
            for k in [k for k, v in self._hits.items() if not v or now - v[-1] >= self.WINDOW]:
                del self._hits[k]
        return None

    def clear(self) -> None:
        self._hits.clear()


message_limiter = UserRateLimiter()


async def _get_viewable(session: DbSession, conversation_id: str, user: User) -> CopilotConversationRow:
    row = await session.get(CopilotConversationRow, conversation_id)
    if row is None or not service.can_view(row, user):
        # Same answer for "missing" and "not yours": do not leak which conversation ids exist.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "conversation not found")
    return row


@router.get("/conversations", response_model=list[Conversation])
async def list_conversations(
    session: DbSession,
    user: CurrentUser,
    include_all: bool = Query(
        default=False, alias="all", description="admin only: include other users' conversations"
    ),
) -> list[Conversation]:
    rows = await service.list_conversations(session, user, include_all=include_all)
    return [Conversation.model_validate(r) for r in rows]


@router.post("/conversations", response_model=Conversation, status_code=status.HTTP_201_CREATED)
async def create_conversation(
    body: ConversationCreate, session: DbSession, user: CurrentUser
) -> Conversation:
    _require_copilot_role(user)
    row = await service.create_conversation(session, user, body)
    return Conversation.model_validate(row)


@router.get("/conversations/{conversation_id}", response_model=ConversationDetail)
async def get_conversation(conversation_id: str, session: DbSession, user: CurrentUser) -> ConversationDetail:
    row = await _get_viewable(session, conversation_id, user)
    messages = await service.load_messages(session, row.id)
    return ConversationDetail(
        conversation=Conversation.model_validate(row),
        messages=[service.message_out(m) for m in messages],
    )


@router.delete("/conversations/{conversation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_conversation(conversation_id: str, session: DbSession, user: CurrentUser) -> Response:
    row = await _get_viewable(session, conversation_id, user)
    await service.delete_conversation(session, row)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


async def _sse(events: AsyncIterator[dict[str, Any]]) -> AsyncIterator[dict[str, str]]:
    async for event in events:
        yield {"data": json.dumps(event, ensure_ascii=False, default=str)}


@router.post("/conversations/{conversation_id}/messages", response_class=EventSourceResponse)
async def post_message(
    conversation_id: str, body: MessageCreate, session: DbSession, user: CurrentUser
) -> EventSourceResponse:
    cfg = get_settings().copilot
    if not cfg.enabled:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "copilot is disabled")
    _require_copilot_role(user)
    row = await _get_viewable(session, conversation_id, user)
    if not service.can_post(row, user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only the conversation owner can send messages")
    if service.is_busy(row.id):
        raise HTTPException(status.HTTP_409_CONFLICT, "a reply is already in progress for this conversation")
    # Checked last (after 409 etc.) so refused requests do not use up the quota; raised before the stream starts.
    retry_after = message_limiter.check(user.id, cfg.messages_per_minute)
    if retry_after is not None:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"copilot message limit reached ({cfg.messages_per_minute}/min)",
            headers={"Retry-After": str(max(1, math.ceil(retry_after)))},
        )
    return EventSourceResponse(_sse(service.run_turn(row.id, user, body.content)))
