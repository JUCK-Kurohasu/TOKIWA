"""SOC Copilot API (docs/api-contract.md「コパイロット」).

Conversations are private to their owner; admins can read and delete any conversation (``?all=true`` lists
everyone's). Only the owner can post messages. Posting returns an SSE stream of
``data: {"type": "text"|"tool_call"|"tool_result"|"error"|"done", ...}`` events that always ends with ``done``.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Response, status
from sse_starlette import EventSourceResponse

from tokiwa.api.deps import CurrentUser, DbSession
from tokiwa.config import get_settings
from tokiwa.copilot import service
from tokiwa.copilot.schemas import Conversation, ConversationCreate, ConversationDetail, MessageCreate
from tokiwa.db.models.llm import CopilotConversationRow
from tokiwa.schemas.system import User

router = APIRouter(prefix="/api/v1/copilot", tags=["copilot"])


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
    if not get_settings().copilot.enabled:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "copilot is disabled")
    row = await _get_viewable(session, conversation_id, user)
    if not service.can_post(row, user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only the conversation owner can send messages")
    if service.is_busy(row.id):
        raise HTTPException(status.HTTP_409_CONFLICT, "a reply is already in progress for this conversation")
    return EventSourceResponse(_sse(service.run_turn(row.id, user, body.content)))
