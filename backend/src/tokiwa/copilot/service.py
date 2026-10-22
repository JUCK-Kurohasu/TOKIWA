"""Copilot conversation service: persistence, history replay and the multi-turn read-only tool loop.

One analyst message (:func:`run_turn`) works like this::

    persist user message (redacted)
    for i in 1..copilot.max_tool_iterations:
        turn = gateway.chat(system, history + this turn, read-only tools)
        persist assistant turn (provider-native blocks, verbatim, for faithful replay)
        no tool calls -> done
        run the tool calls in parallel (read-only sessions), wrap results with untrusted_block
        persist ONE tool-result message holding every tool_result block (is_error on failures)

Every step is yielded as an event dict for the SSE endpoint (``text`` / ``tool_call`` / ``tool_result`` /
``error`` / ``done``). The LLM output is only ever rendered as text: there is no write/execute path.

Replay rules (current Claude models bind thinking blocks to the exact conversation that produced them):

- History is append-only. Assistant blocks are re-sent verbatim; the system prompt is frozen per conversation.
- When the history window has to be trimmed (``max_history_messages`` / input budget), it starts at an analyst
  message (never mid tool round) and ``thinking`` blocks are stripped from the retained turns.
- An interrupted tool round (client disconnect) is repaired with synthetic ``is_error`` tool results.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
from collections.abc import AsyncIterator, Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.config import Settings, get_settings
from tokiwa.copilot.prompts import (
    COPILOT_PROMPT,
    FINAL_ANSWER_NOTE,
    build_system,
    llm_error_message,
    max_iterations_message,
    not_configured_message,
    refused_message,
)
from tokiwa.copilot.schemas import (
    INTERNAL_CONTEXT_PREFIX,
    ConversationCreate,
    CopilotMessage,
    CopilotToolCall,
    CopilotToolResult,
)
from tokiwa.copilot.tools import (
    ToolExecution,
    alert_brief,
    asset_brief,
    error_execution,
    execute_tool,
    incident_brief,
    read_only_session,
    session_brief,
    tool_specs,
    vuln_brief,
)
from tokiwa.db.models.detection import AlertRow, IncidentRow
from tokiwa.db.models.intel import AssetRow, VulnRow
from tokiwa.db.models.llm import CopilotConversationRow, CopilotMessageRow
from tokiwa.db.models.telemetry import ActorSessionRow, EventRow
from tokiwa.db.session import session_scope
from tokiwa.llm.base import ChatTurn, LLMPurpose, LLMTier, ToolCall
from tokiwa.llm.gateway import get_gateway
from tokiwa.llm.prompting import untrusted_block
from tokiwa.llm.redact import redact_obj, redact_text
from tokiwa.schemas.system import LLMCallStatus, Role, User
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

DEFAULT_TITLE = "New conversation"
SNAPSHOT_KEY = f"{INTERNAL_CONTEXT_PREFIX}snapshot"
# Stored alongside tool-result blocks (UI metadata: tool name + summary). Never sent to the model.
META_BLOCK_TYPE = "tokiwa_meta"
MAX_PARALLEL_TOOL_CALLS = 8
_CHARS_PER_TOKEN = 3.0  # same rough estimate as the gateway's input cap
_THINKING_TYPES = frozenset({"thinking", "redacted_thinking"})
_REPLAY_ROLES = frozenset({"user", "assistant", "tool"})
_INTERRUPTED = "Error: tool execution was interrupted; no result is available."

# Conversations with a reply in progress (single process). Prevents interleaved turns.
_active: set[str] = set()


# --------------------------------------------------------------------------------------------------------------
# Access control & CRUD
# --------------------------------------------------------------------------------------------------------------


def can_view(row: CopilotConversationRow, user: User) -> bool:
    return row.owner == user.id or user.role == Role.ADMIN


def can_post(row: CopilotConversationRow, user: User) -> bool:
    return row.owner == user.id


def is_busy(conversation_id: str) -> bool:
    return conversation_id in _active


async def create_conversation(
    session: AsyncSession, user: User, body: ConversationCreate
) -> CopilotConversationRow:
    context: dict[str, Any] = body.context.model_dump(exclude_none=True) if body.context else {}
    if context:
        context[SNAPSHOT_KEY] = await build_context_snapshot(context)
    now = utcnow()
    row = CopilotConversationRow(
        id=new_id(),
        title=(body.title or "").strip() or DEFAULT_TITLE,
        owner=user.id,
        context=context,
        created_at=now,
        updated_at=now,
    )
    session.add(row)
    await session.flush()
    return row


async def list_conversations(
    session: AsyncSession, user: User, *, include_all: bool = False
) -> list[CopilotConversationRow]:
    stmt = select(CopilotConversationRow).order_by(CopilotConversationRow.updated_at.desc()).limit(200)
    if not (include_all and user.role == Role.ADMIN):
        stmt = stmt.where(CopilotConversationRow.owner == user.id)
    return list((await session.execute(stmt)).scalars().all())


async def load_messages(session: AsyncSession, conversation_id: str) -> list[CopilotMessageRow]:
    stmt = (
        select(CopilotMessageRow)
        .where(CopilotMessageRow.conversation_id == conversation_id)
        .order_by(CopilotMessageRow.created_at, CopilotMessageRow.id)
    )
    return list((await session.execute(stmt)).scalars().all())


async def delete_conversation(session: AsyncSession, row: CopilotConversationRow) -> None:
    await session.execute(delete(CopilotMessageRow).where(CopilotMessageRow.conversation_id == row.id))
    await session.delete(row)


def message_out(row: CopilotMessageRow) -> CopilotMessage:
    blocks = [b for b in (row.blocks or []) if isinstance(b, dict)]
    tool_calls: list[CopilotToolCall] | None = None
    tool_results: list[CopilotToolResult] | None = None
    if row.role == "assistant":
        calls = [
            CopilotToolCall(
                id=str(b.get("id", "")),
                name=str(b.get("name", "")),
                input=redact_obj(b["input"]) if isinstance(b.get("input"), dict) else {},
            )
            for b in blocks
            if b.get("type") == "tool_use"
        ]
        tool_calls = calls or None
    elif row.role == "tool":
        meta = next((b for b in blocks if b.get("type") == META_BLOCK_TYPE), None)
        if meta is not None:
            tool_results = [CopilotToolResult.model_validate(r) for r in meta.get("tool_results", [])]
        else:
            tool_results = [
                CopilotToolResult(
                    tool_use_id=str(b.get("tool_use_id", "")), ok=not b.get("is_error", False), summary=""
                )
                for b in blocks
                if b.get("type") == "tool_result"
            ]
    return CopilotMessage(
        id=row.id,
        role=row.role,
        content=row.content,
        created_at=row.created_at,
        tool_calls=tool_calls,
        tool_results=tool_results,
        llm_call_id=row.llm_call_id,
    )


# --------------------------------------------------------------------------------------------------------------
# Conversation context snapshot (frozen into the system prompt)
# --------------------------------------------------------------------------------------------------------------


async def build_context_snapshot(context: dict[str, Any]) -> str:
    """Summarize the objects the conversation is anchored to. Taken once and stored, so the system prompt is
    byte-stable for the life of the conversation (prompt caching, valid thinking-block replay)."""
    data: dict[str, Any] = {"taken_at": utcnow().isoformat()}
    try:
        async with read_only_session() as s:
            if iid := context.get("incident_id"):
                inc = await s.get(IncidentRow, iid)
                data["incident"] = incident_brief(inc, detail=True) if inc else {"id": iid, "found": False}
            if aid := context.get("alert_id"):
                alert = await s.get(AlertRow, aid)
                data["alert"] = alert_brief(alert, detail=True) if alert else {"id": aid, "found": False}
            if sid := context.get("session_id"):
                sess = await s.get(ActorSessionRow, sid)
                data["session"] = session_brief(sess) if sess else {"id": sid, "found": False}
            if ip := context.get("source_ip"):
                since = utcnow() - timedelta(hours=24)
                events = (
                    await s.execute(
                        select(func.count())
                        .select_from(EventRow)
                        .where(EventRow.source_ip == ip, EventRow.timestamp >= since)
                    )
                ).scalar_one()
                alerts = (
                    await s.execute(
                        select(func.count())
                        .select_from(AlertRow)
                        .where(AlertRow.source_ip == ip, AlertRow.last_seen >= since)
                    )
                ).scalar_one()
                data["source"] = {"ip": ip, "events_24h": int(events), "alerts_24h": int(alerts)}
            if vid := context.get("vuln_id"):
                vuln = await s.get(VulnRow, vid)
                data["vuln"] = vuln_brief(vuln, detail=False) if vuln else {"id": vid, "found": False}
            if asid := context.get("asset_id"):
                asset = await s.get(AssetRow, asid)
                data["asset"] = asset_brief(asset) if asset else {"id": asid, "found": False}
    except Exception:
        log.exception("failed to build copilot context snapshot")
        data["references"] = {k: v for k, v in context.items() if not k.startswith(INTERNAL_CONTEXT_PREFIX)}
    return untrusted_block("conversation_context", data, max_chars=6000)


# --------------------------------------------------------------------------------------------------------------
# History -> provider messages
# --------------------------------------------------------------------------------------------------------------


def _row_message(row: CopilotMessageRow) -> dict[str, Any]:
    blocks = [
        copy.deepcopy(b)
        for b in (row.blocks or [])
        if isinstance(b, dict) and b.get("type") != META_BLOCK_TYPE
    ]
    if row.role == "assistant":
        if not blocks:
            blocks = [{"type": "text", "text": row.content or "(empty response)"}]
        return {"role": "assistant", "content": blocks}
    if row.role == "user" and not blocks:
        blocks = [{"type": "text", "text": row.content}]
    return {"role": "user", "content": blocks}


def _strip_thinking(msg: dict[str, Any]) -> dict[str, Any]:
    if msg["role"] != "assistant":
        return msg
    kept = [b for b in msg["content"] if b.get("type") not in _THINKING_TYPES]
    return {"role": "assistant", "content": kept or [{"type": "text", "text": "(no text)"}]}


def _repair_tool_pairs(msgs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every tool_use must be answered by a tool_result in the next message (else the API rejects it)."""
    out: list[dict[str, Any]] = []
    for i, msg in enumerate(msgs):
        out.append(msg)
        if msg["role"] != "assistant":
            continue
        ids = [b.get("id") for b in msg["content"] if b.get("type") == "tool_use"]
        if not ids:
            continue
        nxt = msgs[i + 1] if i + 1 < len(msgs) else None
        answered = (
            {b.get("tool_use_id") for b in nxt["content"] if b.get("type") == "tool_result"}
            if nxt is not None and nxt["role"] == "user"
            else set()
        )
        missing = [x for x in ids if x not in answered]
        if missing:
            out.append(
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": x, "content": _INTERRUPTED, "is_error": True}
                        for x in missing
                    ],
                }
            )
    return out


def _merge_same_role(msgs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for msg in msgs:
        if out and out[-1]["role"] == msg["role"]:
            out[-1] = {"role": msg["role"], "content": out[-1]["content"] + msg["content"]}
        else:
            out.append(msg)
    return out


def _blocks_chars(row: CopilotMessageRow) -> int:
    return len(json.dumps(row.blocks or row.content, ensure_ascii=False, default=str))


def history_messages(
    rows: Sequence[CopilotMessageRow], *, max_messages: int, max_chars: int
) -> list[dict[str, Any]]:
    """Provider messages for the stored history (the last row is normally the new analyst message)."""
    replay = [r for r in rows if r.role in _REPLAY_ROLES]
    user_idx = [i for i, r in enumerate(replay) if r.role == "user"]
    if not user_idx:
        return []
    start = max(0, len(replay) - max(1, max_messages))
    later = [i for i in user_idx if i >= start]
    start = later[0] if later else user_idx[-1]  # never start mid tool round
    sizes = [_blocks_chars(r) for r in replay]
    while start != user_idx[-1] and sum(sizes[start:]) > max_chars:
        start = next(i for i in user_idx if i > start)
    msgs = [_row_message(r) for r in replay[start:]]
    if start > 0:
        # Retained thinking blocks were produced with the dropped turns present; replaying them would be
        # rejected by the history-editing check of current models. Text and tool_use blocks stay.
        msgs = [_strip_thinking(m) for m in msgs]
    return _merge_same_role(_repair_tool_pairs(msgs))


# --------------------------------------------------------------------------------------------------------------
# The tool loop
# --------------------------------------------------------------------------------------------------------------


class _Clock:
    """Strictly increasing timestamps so message order survives equal clock readings."""

    def __init__(self, last: datetime | None) -> None:
        self.last = last

    def next(self) -> datetime:
        now = utcnow()
        if self.last is not None and now <= self.last:
            now = self.last + timedelta(microseconds=1)
        self.last = now
        return now


async def _add_message(
    conversation_id: str,
    role: str,
    content: str,
    blocks: list[dict[str, Any]],
    *,
    created_at: datetime,
    llm_call_id: str | None = None,
    title: str | None = None,
) -> CopilotMessageRow:
    row = CopilotMessageRow(
        id=new_id(),
        conversation_id=conversation_id,
        created_at=created_at,
        role=role,
        content=content,
        blocks=blocks,
        llm_call_id=llm_call_id,
    )
    # Short write transactions only: never hold a write lock across an LLM call (SQLite).
    async with session_scope() as s:
        s.add(row)
        conv = await s.get(CopilotConversationRow, conversation_id)
        if conv is not None:
            conv.updated_at = utcnow()
            if title:
                conv.title = title
    return row


def _redact_user_text(text: str, settings: Settings) -> str:
    # Same masking as telemetry, without the per-field length cap (the request schema bounds the length).
    cfg = settings.llm.redaction.model_copy(update={"max_field_chars": 0})
    return redact_text(text, cfg) or ""


def _title_from(text: str) -> str:
    first = text.strip().splitlines()[0] if text.strip() else DEFAULT_TITLE
    return first if len(first) <= 60 else first[:57] + "..."


def _assistant_blocks(turn: ChatTurn) -> list[dict[str, Any]]:
    blocks = [copy.deepcopy(b) for b in turn.raw_content if isinstance(b, dict)]
    if not blocks and turn.text:
        blocks.append({"type": "text", "text": turn.text})
    have = {b.get("id") for b in blocks if b.get("type") == "tool_use"}
    for call in turn.tool_calls:
        if call.id not in have:
            blocks.append({"type": "tool_use", "id": call.id, "name": call.name, "input": call.input})
    if not any(b.get("type") in ("text", "tool_use") for b in blocks):
        blocks.append({"type": "text", "text": turn.text or "(no answer)"})
    return blocks


async def _execute_calls(calls: Sequence[ToolCall]) -> list[ToolExecution]:
    run, extra = calls[:MAX_PARALLEL_TOOL_CALLS], calls[MAX_PARALLEL_TOOL_CALLS:]
    results = list(await asyncio.gather(*(execute_tool(c.name, c.id, c.input) for c in run)))
    results += [
        error_execution(
            c.id,
            c.name,
            f"too many parallel tool calls (max {MAX_PARALLEL_TOOL_CALLS}); call it again",
            c.input,
        )
        for c in extra
    ]
    return results


def _done(
    conversation_id: str,
    stop_reason: str,
    *,
    message_id: str | None = None,
    iterations: int = 0,
    call_ids: Sequence[str] = (),
) -> dict[str, Any]:
    return {
        "type": "done",
        "conversation_id": conversation_id,
        "stop_reason": stop_reason,
        "message_id": message_id,
        "iterations": iterations,
        "llm_call_ids": list(call_ids),
    }


async def run_turn(conversation_id: str, user: User, content: str) -> AsyncIterator[dict[str, Any]]:
    """Process one analyst message; yields SSE event dicts and always ends with a ``done`` event."""
    if conversation_id in _active:
        yield {
            "type": "error",
            "code": "busy",
            "error": "a reply is already in progress for this conversation",
        }
        yield _done(conversation_id, "busy")
        return
    _active.add(conversation_id)
    try:
        async for event in _run_turn(conversation_id, user, content):
            yield event
    except Exception:
        log.exception("copilot turn failed (conversation %s)", conversation_id)
        yield {"type": "error", "code": "internal", "error": "internal error while generating the reply"}
        yield _done(conversation_id, "error")
    finally:
        _active.discard(conversation_id)


async def _run_turn(conversation_id: str, user: User, content: str) -> AsyncIterator[dict[str, Any]]:
    settings = get_settings()
    lang = settings.llm.output_language
    cfg = settings.copilot

    async with session_scope() as s:
        conv = await s.get(CopilotConversationRow, conversation_id)
        if conv is None or not can_post(conv, user):
            yield {"type": "error", "code": "not_found", "error": "conversation not found"}
            yield _done(conversation_id, "error")
            return
        rows = await load_messages(s, conversation_id)
        context = dict(conv.context or {})
        rename = conv.title == DEFAULT_TITLE
    clock = _Clock(rows[-1].created_at if rows else None)

    snapshot = context.get(SNAPSHOT_KEY)
    public_context = {k: v for k, v in context.items() if not k.startswith(INTERNAL_CONTEXT_PREFIX)}
    if public_context and not isinstance(snapshot, str):
        snapshot = await build_context_snapshot(public_context)
        async with session_scope() as s:
            conv = await s.get(CopilotConversationRow, conversation_id)
            if conv is not None:
                conv.context = {**context, SNAPSHOT_KEY: snapshot}

    text = _redact_user_text(content, settings)
    user_row = await _add_message(
        conversation_id,
        "user",
        text,
        [{"type": "text", "text": text}],
        created_at=clock.next(),
        title=_title_from(text) if rename else None,
    )

    gateway = get_gateway()
    if gateway.provider.name == "mock":
        # No LLM configured: answer with setup guidance instead of an error (not replayed to a future LLM).
        msg = not_configured_message(lang)
        notice = await _add_message(conversation_id, "notice", msg, [], created_at=clock.next())
        yield {"type": "text", "text": msg, "final": True, "message_id": notice.id}
        yield _done(conversation_id, "llm_not_configured", message_id=notice.id)
        return

    messages = history_messages(
        [*rows, user_row],
        max_messages=cfg.max_history_messages,
        max_chars=int(settings.llm.max_input_tokens_per_call * _CHARS_PER_TOKEN),
    )
    system = build_system(lang, snapshot if isinstance(snapshot, str) else None)
    specs = tool_specs()
    tier = LLMTier(cfg.tier)
    max_iterations = max(1, cfg.max_tool_iterations)
    call_ids: list[str] = []

    for iteration in range(1, max_iterations + 1):
        turn, status, error, call_id = await gateway.chat(
            purpose=LLMPurpose.COPILOT,
            tier=tier,
            system=system,
            messages=messages,
            tools=specs,
            prompt_version=COPILOT_PROMPT.ref,
            related={"conversation_id": conversation_id},
        )
        if call_id:
            call_ids.append(call_id)
        if turn is None or status in (LLMCallStatus.ERROR, LLMCallStatus.BUDGET_EXCEEDED):
            msg = llm_error_message(lang, str(status), error)
            notice = await _add_message(
                conversation_id, "notice", msg, [], created_at=clock.next(), llm_call_id=call_id
            )
            yield {"type": "error", "code": str(status), "error": msg, "message_id": notice.id}
            yield _done(
                conversation_id, "error", message_id=notice.id, iterations=iteration, call_ids=call_ids
            )
            return
        if turn.refused or status == LLMCallStatus.REFUSED:
            msg = refused_message(lang)
            notice = await _add_message(
                conversation_id, "notice", msg, [], created_at=clock.next(), llm_call_id=call_id
            )
            yield {"type": "error", "code": "refused", "error": msg, "message_id": notice.id}
            yield _done(
                conversation_id, "refused", message_id=notice.id, iterations=iteration, call_ids=call_ids
            )
            return

        blocks = _assistant_blocks(turn)
        calls = list(turn.tool_calls)
        assistant = await _add_message(
            conversation_id,
            "assistant",
            turn.text or "",
            blocks,
            created_at=clock.next(),
            llm_call_id=call_id,
        )
        messages.append({"role": "assistant", "content": copy.deepcopy(blocks)})
        if turn.text:
            yield {"type": "text", "text": turn.text, "final": not calls, "message_id": assistant.id}
        if not calls:
            yield _done(
                conversation_id, "end_turn", message_id=assistant.id, iterations=iteration, call_ids=call_ids
            )
            return

        for call in calls:
            yield {"type": "tool_call", "id": call.id, "name": call.name, "input": redact_obj(call.input)}
        last = iteration == max_iterations
        if last:
            executions = [
                error_execution(c.id, c.name, "not executed: tool-call budget exhausted", c.input)
                for c in calls
            ]
        else:
            executions = await _execute_calls(calls)
        for ex in executions:
            yield {
                "type": "tool_result",
                "id": ex.tool_use_id,
                "name": ex.name,
                "ok": ex.ok,
                "summary": ex.summary,
            }
        result_blocks = [ex.block() for ex in executions]
        if iteration == max_iterations - 1:
            result_blocks.append({"type": "text", "text": FINAL_ANSWER_NOTE})
        meta = {
            "type": META_BLOCK_TYPE,
            "tool_results": [
                {"tool_use_id": ex.tool_use_id, "name": ex.name, "ok": ex.ok, "summary": ex.summary}
                for ex in executions
            ],
        }
        await _add_message(
            conversation_id,
            "tool",
            "\n".join(f"{ex.name}: {ex.summary}" for ex in executions),
            [*result_blocks, meta],
            created_at=clock.next(),
        )
        messages.append({"role": "user", "content": copy.deepcopy(result_blocks)})
        if last:
            msg = max_iterations_message(lang, max_iterations)
            notice = await _add_message(conversation_id, "notice", msg, [], created_at=clock.next())
            yield {"type": "error", "code": "max_tool_iterations", "error": msg, "message_id": notice.id}
            yield _done(
                conversation_id,
                "max_tool_iterations",
                message_id=notice.id,
                iterations=iteration,
                call_ids=call_ids,
            )
            return
