"""Copilot tool loop, persistence and history replay, driven by a scripted fake provider."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select

from tokiwa.config import reset_settings_cache
from tokiwa.copilot import service
from tokiwa.copilot.prompts import FINAL_ANSWER_NOTE
from tokiwa.copilot.schemas import ConversationContext, ConversationCreate
from tokiwa.db.models.detection import IncidentRow
from tokiwa.db.models.llm import CopilotMessageRow, LLMCallRow
from tokiwa.db.session import session_scope
from tokiwa.llm.base import ChatTurn
from tokiwa.llm.mock import MockProvider
from tokiwa.llm.prompting import UNTRUSTED_DATA_POLICY
from tokiwa.schemas.system import User
from tokiwa.util import utcnow

from .conftest import ATTACKER_IP, ScriptedProvider, Step, text_turn, tool_turn

Install = Callable[[list[Step]], ScriptedProvider]


async def _new_conversation(user: User, context: dict[str, Any] | None = None) -> str:
    body = ConversationCreate(context=ConversationContext(**context) if context else None)
    async with session_scope() as s:
        row = await service.create_conversation(s, user, body)
        return row.id


async def _turn(conv_id: str, user: User, content: str) -> list[dict[str, Any]]:
    return [e async for e in service.run_turn(conv_id, user, content)]


async def _rows(conv_id: str) -> list[CopilotMessageRow]:
    async with session_scope() as s:
        return await service.load_messages(s, conv_id)


async def test_tool_loop_tool_use_then_text(seeded: dict[str, Any], scripted: Install, analyst: User) -> None:
    provider = scripted(
        [
            tool_turn(("toolu_1", "search_events", {"source_ip": ATTACKER_IP})),
            text_turn("203.0.113.10 probed /api/v1/users and attempted SQL injection."),
        ]
    )
    conv_id = await _new_conversation(analyst)
    events = await _turn(conv_id, analyst, "What did 203.0.113.10 do?")

    assert [e["type"] for e in events] == ["text", "tool_call", "tool_result", "text", "done"]
    assert events[0]["final"] is False and events[3]["final"] is True
    assert events[1] == {
        "type": "tool_call",
        "id": "toolu_1",
        "name": "search_events",
        "input": {"source_ip": ATTACKER_IP},
    }
    assert events[2]["ok"] is True and events[2]["summary"] == "3 of 3 events"
    done = events[-1]
    assert done["stop_reason"] == "end_turn" and done["iterations"] == 2 and len(done["llm_call_ids"]) == 2

    # Request shape: read-only tool specs, frozen system prompt with the untrusted-data policy.
    first, second = provider.requests
    assert len(first["tools"]) == 11
    assert UNTRUSTED_DATA_POLICY in first["system"] and first["system"] == second["system"]
    assert first["messages"] == [
        {"role": "user", "content": [{"type": "text", "text": "What did 203.0.113.10 do?"}]}
    ]
    assistant, results = second["messages"][1], second["messages"][2]
    assert assistant["role"] == "assistant" and assistant["content"][-1]["type"] == "tool_use"
    assert results["role"] == "user"
    (block,) = results["content"]
    assert block["type"] == "tool_result" and block["tool_use_id"] == "toolu_1" and "is_error" not in block
    assert block["content"].startswith('<untrusted_data name="tool_result:search_events">')

    # Persistence: provider-native blocks + UI metadata.
    rows = await _rows(conv_id)
    assert [r.role for r in rows] == ["user", "assistant", "tool", "assistant"]
    assert rows[1].blocks == assistant["content"]
    assert rows[1].llm_call_id == done["llm_call_ids"][0]
    out = service.message_out(rows[2])
    assert out.tool_results and out.tool_results[0].name == "search_events" and out.tool_results[0].ok
    assert service.message_out(rows[1]).tool_calls[0].name == "search_events"  # type: ignore[index]

    # Audit: every LLM call goes through the gateway (purpose copilot, linked to the conversation).
    async with session_scope() as s:
        calls = (await s.execute(select(LLMCallRow))).scalars().all()
    assert len(calls) == 2
    assert all(c.purpose == "copilot" and c.related == {"conversation_id": conv_id} for c in calls)
    assert all(c.prompt_version == "copilot.chat@2026-10-22.1" for c in calls)


async def test_parallel_tool_calls_return_in_one_message(
    seeded: dict[str, Any], scripted: Install, analyst: User
) -> None:
    provider = scripted(
        [
            tool_turn(
                ("toolu_a", "get_incident", {"incident_id": "inc-1"}),
                ("toolu_b", "get_alert", {"alert_id": "missing"}),
                ("toolu_c", "list_vuln_matches", {"kev_only": True, "bogus": 1}),
            ),
            text_turn("Summary."),
        ]
    )
    conv_id = await _new_conversation(analyst)
    events = await _turn(conv_id, analyst, "Summarize inc-1")
    results = [e for e in events if e["type"] == "tool_result"]
    assert [(r["id"], r["ok"]) for r in results] == [
        ("toolu_a", True),
        ("toolu_b", False),
        ("toolu_c", False),
    ]

    last = provider.requests[1]["messages"][-1]
    assert last["role"] == "user"
    assert [b["tool_use_id"] for b in last["content"]] == ["toolu_a", "toolu_b", "toolu_c"]
    assert [b.get("is_error", False) for b in last["content"]] == [False, True, True]
    assert "not found" in last["content"][1]["content"]
    assert "Extra inputs" in last["content"][2]["content"]


async def test_history_is_replayed_append_only(
    seeded: dict[str, Any], scripted: Install, analyst: User
) -> None:
    provider = scripted(
        [
            tool_turn(("toolu_1", "top_sources", {"hours": 24}), thinking=True),
            text_turn("The top source is 203.0.113.10.", thinking=True),
            text_turn("It is linked to incident inc-1."),
        ]
    )
    conv_id = await _new_conversation(analyst)
    await _turn(conv_id, analyst, "Who are the top sources?")
    await _turn(conv_id, analyst, "Is it part of an incident?")

    turn1_last, turn2 = provider.requests[1], provider.requests[2]
    # The second question's request is exactly the previous request + the final answer + the new question.
    assert turn2["messages"][: len(turn1_last["messages"])] == turn1_last["messages"]
    assert turn2["messages"][-2] == {
        "role": "assistant",
        "content": [
            {"type": "thinking", "thinking": "", "signature": "sig-text"},
            {"type": "text", "text": "The top source is 203.0.113.10."},
        ],
    }
    assert turn2["messages"][-1]["content"] == [{"type": "text", "text": "Is it part of an incident?"}]
    assert turn2["system"] == turn1_last["system"]


async def test_max_tool_iterations(
    seeded: dict[str, Any], scripted: Install, analyst: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TOKIWA_COPILOT__MAX_TOOL_ITERATIONS", "2")
    reset_settings_cache()
    provider = scripted(
        [
            tool_turn(("toolu_1", "list_alerts", {})),
            tool_turn(("toolu_2", "list_incidents", {})),
        ]
    )
    conv_id = await _new_conversation(analyst)
    events = await _turn(conv_id, analyst, "Investigate everything")

    assert len(provider.requests) == 2  # never more chat() calls than max_tool_iterations
    # Before the final allowed call the model is told to answer with what it has.
    note = provider.requests[1]["messages"][-1]["content"][-1]
    assert note == {"type": "text", "text": FINAL_ANSWER_NOTE}
    results = [e for e in events if e["type"] == "tool_result"]
    assert [(r["id"], r["ok"]) for r in results] == [("toolu_1", True), ("toolu_2", False)]
    assert events[-2]["type"] == "error" and events[-2]["code"] == "max_tool_iterations"
    assert events[-1]["stop_reason"] == "max_tool_iterations"

    rows = await _rows(conv_id)
    assert [r.role for r in rows] == ["user", "assistant", "tool", "assistant", "tool", "notice"]
    assert rows[4].blocks[0]["is_error"] is True and "budget exhausted" in rows[4].blocks[0]["content"]


async def test_mock_provider_returns_setup_guidance(db: None, mock_llm: MockProvider, analyst: User) -> None:
    conv_id = await _new_conversation(analyst)
    events = await _turn(conv_id, analyst, "hello")
    assert [e["type"] for e in events] == ["text", "done"]
    assert "ANTHROPIC_API_KEY" in events[0]["text"]
    assert events[-1]["stop_reason"] == "llm_not_configured"
    rows = await _rows(conv_id)
    assert [r.role for r in rows] == ["user", "notice"]
    # The guidance is shown, but never replayed to a real LLM later.
    assert service.history_messages(rows, max_messages=40, max_chars=100_000) == [
        {"role": "user", "content": [{"type": "text", "text": "hello"}]}
    ]


async def test_llm_error_and_refusal_are_reported(db: None, scripted: Install, analyst: User) -> None:
    refused = ChatTurn(model="claude-test", text="", refused=True, stop_reason="refusal")
    scripted([RuntimeError("upstream unavailable"), refused])
    conv_id = await _new_conversation(analyst)

    events = await _turn(conv_id, analyst, "first")
    assert events[0]["type"] == "error" and events[0]["code"] == "error"
    assert "upstream unavailable" in events[0]["error"]
    assert events[-1] == {**events[-1], "type": "done", "stop_reason": "error"}

    events = await _turn(conv_id, analyst, "second")
    assert events[0]["type"] == "error" and events[0]["code"] == "refused"
    assert events[-1]["stop_reason"] == "refused"
    assert [r.role for r in await _rows(conv_id)] == ["user", "notice", "user", "notice"]


async def test_context_snapshot_is_frozen_in_system_prompt(
    seeded: dict[str, Any], scripted: Install, analyst: User
) -> None:
    provider = scripted([text_turn("one"), text_turn("two")])
    conv_id = await _new_conversation(analyst, {"incident_id": "inc-1", "source_ip": ATTACKER_IP})
    await _turn(conv_id, analyst, "Summarize this incident")
    async with session_scope() as s:
        inc = await s.get(IncidentRow, "inc-1")
        assert inc is not None
        inc.title = "renamed later"
    await _turn(conv_id, analyst, "And now?")

    first, second = provider.requests
    assert '<untrusted_data name="conversation_context">' in first["system"]
    assert "AI agent reconnaissance" in first["system"]
    assert '"events_24h": 3' in first["system"]
    assert first["system"] == second["system"]  # snapshot, not re-rendered per turn


async def test_user_message_is_redacted_and_titles_conversation(
    db: None, scripted: Install, analyst: User
) -> None:
    provider = scripted([text_turn("ok")])
    conv_id = await _new_conversation(analyst)
    await _turn(conv_id, analyst, "Is password=hunter2hunter2 in any request?")
    sent = provider.requests[0]["messages"][0]["content"][0]["text"]
    assert "hunter2hunter2" not in sent and "[REDACTED:secret]" in sent
    rows = await _rows(conv_id)
    assert "hunter2hunter2" not in rows[0].content
    async with session_scope() as s:
        convs = await service.list_conversations(s, analyst)
    assert convs[0].title.startswith("Is password=[REDACTED")


async def test_busy_conversation_is_rejected(db: None, scripted: Install, analyst: User) -> None:
    provider = scripted([])
    conv_id = await _new_conversation(analyst)
    service._active.add(conv_id)
    try:
        events = await _turn(conv_id, analyst, "hi")
    finally:
        service._active.discard(conv_id)
    assert events[0]["code"] == "busy" and events[-1]["stop_reason"] == "busy"
    assert provider.requests == []


# ------------------------------------------------------------------------------------------------ history building


def _row(role: str, blocks: list[dict[str, Any]], content: str = "", minute: int = 0) -> CopilotMessageRow:
    return CopilotMessageRow(
        id=f"m{minute}",
        conversation_id="c",
        created_at=utcnow() + timedelta(minutes=minute),
        role=role,
        content=content,
        blocks=blocks,
    )


def _user(text: str, minute: int) -> CopilotMessageRow:
    return _row("user", [{"type": "text", "text": text}], text, minute)


THINK = {"type": "thinking", "thinking": "", "signature": "s"}


def test_history_trimming_starts_at_user_and_strips_thinking() -> None:
    rows = [
        _user("q1", 0),
        _row(
            "assistant",
            [THINK, {"type": "tool_use", "id": "t1", "name": "list_alerts", "input": {}}],
            minute=1,
        ),
        _row(
            "tool",
            [{"type": "tool_result", "tool_use_id": "t1", "content": "x"}, {"type": "tokiwa_meta"}],
            minute=2,
        ),
        _row("assistant", [THINK, {"type": "text", "text": "a1"}], "a1", 3),
        _user("q2", 4),
        _row("assistant", [THINK, {"type": "text", "text": "a2"}], "a2", 5),
        _row("notice", [], "shown only in the UI", 6),
        _user("q3", 7),
    ]
    full = service.history_messages(rows, max_messages=40, max_chars=100_000)
    assert full[1]["content"][0] == THINK  # untrimmed: replayed verbatim
    assert all(b.get("type") != "tokiwa_meta" for m in full for b in m["content"])
    assert len(full) == 7

    trimmed = service.history_messages(rows, max_messages=4, max_chars=100_000)
    assert trimmed[0] == {"role": "user", "content": [{"type": "text", "text": "q2"}]}
    assert trimmed[1] == {"role": "assistant", "content": [{"type": "text", "text": "a2"}]}
    assert trimmed[-1]["content"] == [{"type": "text", "text": "q3"}]

    # Input budget: drop whole exchanges from the front, always keep the latest question.
    tiny = service.history_messages(rows, max_messages=40, max_chars=10)
    assert tiny == [{"role": "user", "content": [{"type": "text", "text": "q3"}]}]


def test_interrupted_tool_round_is_repaired() -> None:
    rows = [
        _user("q1", 0),
        _row("assistant", [{"type": "tool_use", "id": "t9", "name": "list_alerts", "input": {}}], minute=1),
        _user("q2", 2),
    ]
    msgs = service.history_messages(rows, max_messages=40, max_chars=100_000)
    assert [m["role"] for m in msgs] == ["user", "assistant", "user"]
    repaired = msgs[2]["content"]
    assert repaired[0]["type"] == "tool_result" and repaired[0]["tool_use_id"] == "t9"
    assert repaired[0]["is_error"] is True
    assert repaired[1] == {"type": "text", "text": "q2"}
