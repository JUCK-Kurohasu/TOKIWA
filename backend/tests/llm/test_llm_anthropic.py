"""AnthropicProvider against a fake Messages API (no real API calls)."""

from __future__ import annotations

import json
from typing import Literal

import pytest
from pydantic import BaseModel, Field

from tokiwa.config import Settings
from tokiwa.llm import anthropic_provider as ap
from tokiwa.llm.anthropic_provider import AnthropicProvider
from tokiwa.llm.base import LLMPurpose, LLMTier, StructuredRequest, ToolSpec
from tokiwa.llm.gateway import LLMGateway
from tokiwa.schemas.system import LLMCallStatus


class Verdict(BaseModel):
    verdict: Literal["benign", "malicious"]
    confidence: float = Field(ge=0, le=1)
    reasons: list[str] = Field(default_factory=list)


VERDICT_JSON = '{"verdict": "malicious", "confidence": 0.9, "reasons": ["sqli payload"]}'


def _provider(settings: Settings, fake) -> AnthropicProvider:  # type: ignore[no-untyped-def]
    return AnthropicProvider(settings, client=fake.client())


async def _structured(provider: AnthropicProvider, model: str = "claude-opus-5-5", **kw):  # type: ignore[no-untyped-def]
    args = {
        "model": model,
        "system": "SYSTEM PROMPT v1",
        "user": "analyze <untrusted_data>...</untrusted_data>",
        "schema": Verdict,
        "max_tokens": 2048,
        "effort": "medium",
        "cache": True,
    }
    args.update(kw)
    return await provider.complete_structured(**args)


# --------------------------------------------------------------------------- client construction


def test_client_construction_uses_settings(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-env-0000000000000000")
    provider = AnthropicProvider(settings)
    assert provider.available()
    client = provider.client
    assert client.max_retries == 2
    assert client.timeout == settings.llm.request_timeout_seconds
    assert str(client.base_url).startswith("https://api.anthropic.com")

    custom = settings.model_copy(
        update={"llm": settings.llm.model_copy(update={"anthropic_base_url": "http://claude-proxy.lab:8080"})}
    )
    assert str(AnthropicProvider(custom).client.base_url).startswith("http://claude-proxy.lab:8080")


def test_unavailable_without_key(settings: Settings) -> None:
    provider = AnthropicProvider(settings)
    assert not provider.available()
    with pytest.raises(RuntimeError, match="API key"):
        _ = provider.client


# --------------------------------------------------------------------------- structured output


async def test_parse_success_request_shape(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(
        msg(
            [
                {"type": "thinking", "thinking": "", "signature": "sig"},
                {"type": "text", "text": VERDICT_JSON},
            ],
            usage={
                "input_tokens": 1200,
                "output_tokens": 80,
                "cache_read_input_tokens": 3000,
                "cache_creation_input_tokens": 500,
            },
        )
    )
    resp = await _structured(_provider(settings, fake_anthropic))

    assert resp.parsed == {"verdict": "malicious", "confidence": 0.9, "reasons": ["sqli payload"]}
    assert not resp.refused
    assert resp.stop_reason == "end_turn"
    assert resp.request_id == "req_1"
    assert resp.usage.input_tokens == 1200
    assert resp.usage.output_tokens == 80
    assert resp.usage.cache_read_tokens == 3000
    assert resp.usage.cache_write_tokens == 500

    req = fake_anthropic.requests[0]
    body = req["body"]
    assert body["model"] == "claude-opus-5-5"
    assert body["max_tokens"] == 2048
    # prompt caching on the static system block
    assert body["system"] == [
        {"type": "text", "text": "SYSTEM PROMPT v1", "cache_control": {"type": "ephemeral"}}
    ]
    assert body["messages"] == [{"role": "user", "content": "analyze <untrusted_data>...</untrusted_data>"}]
    # effort explicit + structured output schema from the Pydantic model
    assert body["output_config"]["effort"] == "medium"
    assert body["output_config"]["format"]["type"] == "json_schema"
    assert "verdict" in body["output_config"]["format"]["schema"]["properties"]
    # server-side fallback for the deep model
    assert body["fallbacks"] == "default"
    assert req["headers"]["anthropic-beta"] == ap.FALLBACK_BETA
    # never sent: sampling params, thinking config, forced tool choice
    for forbidden in ("temperature", "top_p", "top_k", "thinking", "tool_choice"):
        assert forbidden not in body


async def test_no_cache_control_when_disabled(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(msg([{"type": "text", "text": VERDICT_JSON}]))
    await _structured(_provider(settings, fake_anthropic), cache=False)
    assert fake_anthropic.bodies[0]["system"] == [{"type": "text", "text": "SYSTEM PROMPT v1"}]


async def test_fast_model_has_no_fallback(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(msg([{"type": "text", "text": VERDICT_JSON}], model="claude-haiku-5-5"))
    resp = await _structured(_provider(settings, fake_anthropic), model="claude-haiku-5-5", effort="low")
    assert resp.parsed is not None
    req = fake_anthropic.requests[0]
    assert "fallbacks" not in req["body"]
    assert "anthropic-beta" not in req["headers"]
    assert req["body"]["output_config"]["effort"] == "low"


async def test_fallbacks_disabled_by_setting(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    no_fb = settings.model_copy(update={"llm": settings.llm.model_copy(update={"enable_fallbacks": False})})
    fake_anthropic.reply(msg([{"type": "text", "text": VERDICT_JSON}]))
    await _structured(_provider(no_fb, fake_anthropic))
    assert "fallbacks" not in fake_anthropic.bodies[0]


async def test_effort_not_sent_to_models_without_effort(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(msg([{"type": "text", "text": VERDICT_JSON}], model="claude-haiku-4-5"))
    await _structured(_provider(settings, fake_anthropic), model="claude-haiku-4-5")
    assert "effort" not in fake_anthropic.bodies[0].get("output_config", {})


async def test_refusal_before_output(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(
        msg(
            [],
            stop_reason="refusal",
            stop_details={"type": "refusal", "category": "cyber", "explanation": "exploit development"},
        )
    )
    resp = await _structured(_provider(settings, fake_anthropic))
    assert resp.refused
    assert resp.parsed is None
    assert resp.stop_reason == "refusal"
    assert resp.text is not None and "category=cyber" in resp.text
    assert resp.usage.input_tokens == 100


async def test_refusal_with_prose_does_not_raise(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    """A model-side refusal can carry non-JSON text; parse() would raise - we must still report a refusal."""
    fake_anthropic.reply(
        msg([{"type": "text", "text": "I can't help with that."}], stop_reason="refusal", stop_details=None)
    )
    resp = await _structured(_provider(settings, fake_anthropic))
    assert resp.refused
    assert resp.text == "refusal: category=none"


async def test_invalid_json_keeps_usage_and_text(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(
        msg(
            [{"type": "text", "text": '{"verdict": "malicious", "confidence": 0.'}],
            stop_reason="max_tokens",
            usage={"input_tokens": 50, "output_tokens": 2048},
        )
    )
    resp = await _structured(_provider(settings, fake_anthropic))
    assert resp.parsed is None
    assert not resp.refused
    assert resp.stop_reason == "max_tokens"
    assert resp.text == '{"verdict": "malicious", "confidence": 0.'
    assert resp.usage.output_tokens == 2048


async def test_schema_violation_is_not_parsed(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(msg([{"type": "text", "text": '{"verdict": "malicious", "confidence": 7}'}]))
    resp = await _structured(_provider(settings, fake_anthropic))
    assert resp.parsed is None


async def test_server_side_fallback_usage_and_model(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    """fallbacks="default": top-level usage covers only the serving attempt; iterations are summed."""
    fake_anthropic.reply(
        msg(
            [
                {
                    "type": "fallback",
                    "from": {"model": "claude-opus-5-5"},
                    "to": {"model": "claude-opus-4-8"},
                },
                {"type": "text", "text": VERDICT_JSON},
            ],
            model="claude-opus-4-8",
            usage={
                "input_tokens": 900,
                "output_tokens": 60,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
                "iterations": [
                    {
                        "type": "message",
                        "model": "claude-opus-5-5",
                        "input_tokens": 1000,
                        "output_tokens": 0,
                        "cache_read_input_tokens": 0,
                        "cache_creation_input_tokens": 0,
                    },
                    {
                        "type": "fallback_message",
                        "model": "claude-opus-4-8",
                        "input_tokens": 900,
                        "output_tokens": 60,
                        "cache_read_input_tokens": 10,
                        "cache_creation_input_tokens": 5,
                    },
                ],
            },
        )
    )
    resp = await _structured(_provider(settings, fake_anthropic))
    assert resp.parsed is not None
    assert resp.model == "claude-opus-4-8"
    assert resp.usage.input_tokens == 1900
    assert resp.usage.output_tokens == 60
    assert resp.usage.cache_read_tokens == 10
    assert resp.usage.cache_write_tokens == 5


# --------------------------------------------------------------------------- web search


def _search_turn(msg, *, stop_reason: str, text: str | None, citations: bool, search_requests: int):  # type: ignore[no-untyped-def]
    content = [
        {
            "type": "server_tool_use",
            "id": f"srvtoolu_{stop_reason}",
            "name": "web_search",
            "input": {"query": "actively exploited zero-day"},
        },
        {
            "type": "web_search_tool_result",
            "tool_use_id": f"srvtoolu_{stop_reason}",
            "content": [
                {
                    "type": "web_search_result",
                    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "title": "KEV Catalog",
                    "encrypted_content": "enc",
                    "page_age": "1 day ago",
                }
            ],
        },
    ]
    if text is not None:
        block = {"type": "text", "text": text}
        if citations:
            block["citations"] = [
                {
                    "type": "web_search_result_location",
                    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "title": "KEV Catalog",
                    "cited_text": "CVE-2026-0001 added to KEV",
                    "encrypted_index": "idx",
                }
            ]
        content.append(block)
    return msg(
        content,
        stop_reason=stop_reason,
        usage={
            "input_tokens": 500,
            "output_tokens": 100,
            "server_tool_use": {"web_search_requests": search_requests, "web_fetch_requests": 0},
        },
    )


async def test_web_search_pause_turn_citations_and_two_phase(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(
        _search_turn(msg, stop_reason="pause_turn", text=None, citations=False, search_requests=2)
    )
    fake_anthropic.reply(
        _search_turn(
            msg, stop_reason="end_turn", text="CVE-2026-0001 is exploited.", citations=True, search_requests=1
        )
    )
    fake_anthropic.reply(
        msg([{"type": "text", "text": VERDICT_JSON}], usage={"input_tokens": 300, "output_tokens": 40})
    )

    resp = await _structured(
        _provider(settings, fake_anthropic),
        web_search=True,
        web_search_max_uses=3,
        allowed_domains=["cisa.gov", "nvd.nist.gov"],
    )

    assert len(fake_anthropic.requests) == 3
    first, second, third = fake_anthropic.bodies
    # phase 1: web search tool declared with limits, no structured output format
    assert first["tools"] == [
        {
            "type": "web_search_20260209",
            "name": "web_search",
            "max_uses": 3,
            "allowed_domains": ["cisa.gov", "nvd.nist.gov"],
        }
    ]
    assert "format" not in first.get("output_config", {})
    assert first["messages"] == [{"role": "user", "content": "analyze <untrusted_data>...</untrusted_data>"}]
    # pause_turn continuation: original user message + paused assistant content, no extra "continue" message
    assert len(second["messages"]) == 2
    assert second["messages"][0] == first["messages"][0]
    assert second["messages"][1]["role"] == "assistant"
    assert second["messages"][1]["content"][0]["type"] == "server_tool_use"
    # phase 2: structured extraction without tools; the web report is wrapped as untrusted data
    assert "tools" not in third
    assert third["output_config"]["format"]["type"] == "json_schema"
    user_text = third["messages"][0]["content"]
    assert '<untrusted_data name="web_research">' in user_text
    assert "CVE-2026-0001 is exploited." in user_text

    assert resp.parsed == {"verdict": "malicious", "confidence": 0.9, "reasons": ["sqli payload"]}
    assert resp.citations == [
        {
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "title": "KEV Catalog",
            "cited_text": "CVE-2026-0001 added to KEV",
        }
    ]
    assert resp.usage.web_search_requests == 3
    assert resp.usage.input_tokens == 500 + 500 + 300
    assert resp.usage.output_tokens == 100 + 100 + 40


async def test_web_search_pause_turn_is_bounded(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    for _ in range(ap.MAX_PAUSE_CONTINUATIONS + 1):
        fake_anthropic.reply(
            _search_turn(msg, stop_reason="pause_turn", text=None, citations=False, search_requests=1)
        )
    fake_anthropic.reply(msg([{"type": "text", "text": VERDICT_JSON}]))
    resp = await _structured(_provider(settings, fake_anthropic), web_search=True)
    assert len(fake_anthropic.requests) == ap.MAX_PAUSE_CONTINUATIONS + 2  # bounded research + extraction
    assert resp.parsed is not None
    assert resp.usage.web_search_requests == ap.MAX_PAUSE_CONTINUATIONS + 1


async def test_web_search_refusal_skips_extraction(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(
        msg([], stop_reason="refusal", stop_details={"type": "refusal", "category": "cyber"})
    )
    resp = await _structured(_provider(settings, fake_anthropic), web_search=True)
    assert resp.refused
    assert len(fake_anthropic.requests) == 1


def test_search_tool_errors_are_detected() -> None:
    sources, errors = ap.search_sources_of(
        [
            {
                "type": "web_search_tool_result",
                "tool_use_id": "x",
                "content": {"error_code": "max_uses_exceeded"},
            }
        ]
    )
    assert sources == []
    assert errors == ["max_uses_exceeded"]


# --------------------------------------------------------------------------- chat / tools

TOOLS = [
    ToolSpec(
        name="search_events",
        description="Search stored telemetry events (read-only).",
        input_schema={
            "type": "object",
            "properties": {
                "source_ip": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            },
            "required": ["source_ip"],
        },
    )
]


async def test_chat_tool_use_turn(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(
        msg(
            [
                {"type": "thinking", "thinking": "", "signature": "sig-1"},
                {"type": "text", "text": "Looking up events."},
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "search_events",
                    "input": {"source_ip": "203.0.113.10", "limit": 20},
                },
            ],
            stop_reason="tool_use",
        )
    )
    provider = _provider(settings, fake_anthropic)
    turn = await provider.chat(
        model="claude-opus-5-5",
        system="copilot system",
        messages=[{"role": "user", "content": "What did 203.0.113.10 do?"}],
        tools=TOOLS,
        max_tokens=4096,
        effort="medium",
        cache=True,
    )
    assert turn.stop_reason == "tool_use"
    assert turn.text == "Looking up events."
    assert [(c.id, c.name, c.input) for c in turn.tool_calls] == [
        ("toolu_1", "search_events", {"source_ip": "203.0.113.10", "limit": 20})
    ]
    # raw content is replayable verbatim (thinking signature preserved)
    assert [b["type"] for b in turn.raw_content] == ["thinking", "text", "tool_use"]
    assert turn.raw_content[0]["signature"] == "sig-1"
    json.dumps(turn.raw_content)  # JSON-serializable for the copilot_messages table

    body = fake_anthropic.bodies[0]
    assert "tool_choice" not in body  # forced tool choice is a 400 on Opus 5.5
    tool = body["tools"][0]
    assert tool["name"] == "search_events"
    assert tool["strict"] is True
    assert tool["input_schema"]["additionalProperties"] is False
    assert tool["input_schema"]["required"] == ["source_ip"]
    assert "minimum" not in tool["input_schema"]["properties"]["limit"]  # moved into description
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}


async def test_chat_retries_without_strict_on_400(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(
        {
            "type": "error",
            "error": {"type": "invalid_request_error", "message": "strict tools: too many optional"},
        },
        status=400,
    )
    fake_anthropic.reply(msg([{"type": "text", "text": "ok"}]))
    provider = _provider(settings, fake_anthropic)
    turn = await provider.chat(
        model="claude-opus-5-5",
        system="s",
        messages=[{"role": "user", "content": "hi"}],
        tools=TOOLS,
        max_tokens=1024,
        effort="low",
        cache=False,
    )
    assert turn.text == "ok"
    assert fake_anthropic.bodies[0]["tools"][0]["strict"] is True
    assert "strict" not in fake_anthropic.bodies[1]["tools"][0]
    assert fake_anthropic.bodies[1]["tools"][0]["input_schema"] == TOOLS[0].input_schema


async def test_chat_refusal(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    fake_anthropic.reply(
        msg(
            [{"type": "text", "text": "partial"}],
            stop_reason="refusal",
            stop_details={"type": "refusal", "category": "cyber"},
        )
    )
    turn = await _provider(settings, fake_anthropic).chat(
        model="claude-opus-5-5",
        system="s",
        messages=[{"role": "user", "content": "write an exploit"}],
        tools=[],
        max_tokens=1024,
        effort="low",
        cache=False,
    )
    assert turn.refused
    assert turn.tool_calls == []
    assert "partial" not in json.dumps(turn.raw_content)  # partial output is discarded


def test_sanitize_after_mid_output_fallback() -> None:
    blocks = [
        {"type": "thinking", "thinking": "", "signature": "a"},
        {"type": "text", "text": "partial "},
        {"type": "tool_use", "id": "t1", "name": "x", "input": {}},
        {"type": "server_tool_use", "id": "s1", "name": "web_search", "input": {}},
        {"type": "fallback", "from": {"model": "claude-opus-5-5"}, "to": {"model": "claude-opus-4-8"}},
        {"type": "thinking", "thinking": "", "signature": "b"},
        {"type": "text", "text": "rest"},
    ]
    out = ap.sanitize_for_replay(blocks)
    assert out == [
        {"type": "text", "text": "partial "},
        {"type": "thinking", "thinking": "", "signature": "b"},
        {"type": "text", "text": "rest"},
    ]
    assert ap.sanitize_for_replay(blocks[:3]) == blocks[:3]  # untouched without a fallback block


# --------------------------------------------------------------------------- through the gateway


@pytest.mark.usefixtures("db")
async def test_gateway_refusal_and_invalid_output_audited(settings: Settings, fake_anthropic, msg) -> None:  # type: ignore[no-untyped-def]
    from tokiwa.db.models.llm import LLMCallRow
    from tokiwa.db.session import session_scope

    fake_anthropic.reply(
        msg([], stop_reason="refusal", stop_details={"type": "refusal", "category": "cyber"})
    )
    fake_anthropic.reply(msg([{"type": "text", "text": "not json"}]))
    fake_anthropic.reply(msg([{"type": "text", "text": VERDICT_JSON}], model="claude-haiku-5-5"))
    gw = LLMGateway(provider=_provider(settings, fake_anthropic), settings=settings)

    def req(tier: LLMTier) -> StructuredRequest:
        return StructuredRequest(
            purpose=LLMPurpose.TRIAGE,
            tier=tier,
            system="sys",
            user="u",
            prompt_version="t@1",
            related={"alert_id": "a1"},
        )

    refused = await gw.structured(req(LLMTier.DEEP), Verdict)
    invalid = await gw.structured(req(LLMTier.DEEP), Verdict)
    ok = await gw.structured(req(LLMTier.FAST), Verdict)

    assert refused.status == LLMCallStatus.REFUSED and refused.output is None
    assert "category=cyber" in (refused.error or "")
    assert invalid.status == LLMCallStatus.INVALID_OUTPUT and invalid.raw_text == "not json"
    assert ok.ok and ok.output is not None and ok.output.verdict == "malicious"
    assert ok.cost_usd > 0
    async with session_scope() as session:
        rows = {r.id: r for r in (await session.execute(LLMCallRow.__table__.select())).all()}
    assert {refused.call_id, invalid.call_id, ok.call_id} <= set(rows)
    assert rows[refused.call_id].status == "refused"
    assert rows[invalid.call_id].input_tokens == 100  # billed tokens recorded even for invalid output
