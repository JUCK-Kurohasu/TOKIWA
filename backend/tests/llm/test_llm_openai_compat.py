"""OpenAI-compatible provider (local LLM servers) with respx-mocked HTTP."""

from __future__ import annotations

import json
from typing import Any, Literal

import httpx
import pytest
import respx
from pydantic import BaseModel, Field, SecretStr

from tokiwa.config import Settings
from tokiwa.llm.base import ToolSpec
from tokiwa.llm.openai_compat import (
    OpenAICompatProvider,
    ProviderCapabilityError,
    chat_completions_url,
    extract_json_object,
    to_openai_messages,
)

BASE = "http://ollama.lab:11434"
URL = f"{BASE}/v1/chat/completions"


class Verdict(BaseModel):
    verdict: Literal["benign", "malicious"]
    confidence: float = Field(ge=0, le=1)


def _settings(settings: Settings, **llm: Any) -> Settings:
    values = {"openai_base_url": BASE, "openai_api_key": SecretStr("local-key-123"), **llm}
    return settings.model_copy(update={"llm": settings.llm.model_copy(update=values)})


def completion(
    content: str | None, *, finish: str = "stop", tool_calls: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "id": "chatcmpl-1",
        "model": "llama3.1:8b",
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
        "usage": {
            "prompt_tokens": 120,
            "completion_tokens": 30,
            "prompt_tokens_details": {"cached_tokens": 20},
        },
    }


async def _structured(provider: OpenAICompatProvider, **kw: Any):  # type: ignore[no-untyped-def]
    args = {
        "model": "llama3.1:8b",
        "system": "sys",
        "user": "analyze",
        "schema": Verdict,
        "max_tokens": 512,
        "effort": "low",
        "cache": True,
    }
    args.update(kw)
    return await provider.complete_structured(**args)


def test_url_normalization() -> None:
    assert chat_completions_url("http://h:11434") == "http://h:11434/v1/chat/completions"
    assert chat_completions_url("http://h:8000/v1/") == "http://h:8000/v1/chat/completions"
    assert chat_completions_url("http://h/v1/chat/completions") == "http://h/v1/chat/completions"


def test_extract_json_object() -> None:
    assert extract_json_object('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json_object('Sure! {"a": {"b": 2}} done') == {"a": {"b": 2}}
    with pytest.raises(ValueError):
        extract_json_object("no json here")


@respx.mock
async def test_json_schema_mode(settings: Settings) -> None:
    route = respx.post(URL).mock(
        return_value=httpx.Response(200, json=completion('{"verdict": "benign", "confidence": 0.2}'))
    )
    provider = OpenAICompatProvider(_settings(settings))
    resp = await _structured(provider)
    assert resp.parsed == {"verdict": "benign", "confidence": 0.2}
    assert resp.stop_reason == "end_turn"
    assert resp.usage.input_tokens == 100 and resp.usage.cache_read_tokens == 20
    assert resp.usage.output_tokens == 30
    body = json.loads(route.calls[0].request.content)
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["name"] == "Verdict"
    assert route.calls[0].request.headers["authorization"] == "Bearer local-key-123"
    assert provider.json_schema_supported is True


@respx.mock
async def test_falls_back_to_prompt_mode_when_response_format_rejected(settings: Settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if "response_format" in body:
            return httpx.Response(400, json={"error": {"message": "response_format not supported"}})
        return httpx.Response(
            200, json=completion('```json\n{"verdict": "malicious", "confidence": 0.8}\n```')
        )

    route = respx.post(URL).mock(side_effect=handler)
    provider = OpenAICompatProvider(_settings(settings))
    resp = await _structured(provider)
    assert resp.parsed == {"verdict": "malicious", "confidence": 0.8}
    assert provider.json_schema_supported is False
    prompt_body = json.loads(route.calls[1].request.content)
    assert "response_format" not in prompt_body
    assert "JSON Schema" in prompt_body["messages"][0]["content"]

    # learned: the next call goes straight to prompt mode
    await _structured(provider)
    assert len(route.calls) == 3
    assert "response_format" not in json.loads(route.calls[2].request.content)


@respx.mock
async def test_invalid_json_retried_once(settings: Settings) -> None:
    route = respx.post(URL).mock(
        side_effect=[
            httpx.Response(200, json=completion("The verdict is malicious.")),
            httpx.Response(200, json=completion('{"verdict": "malicious", "confidence": 0.7}')),
        ]
    )
    resp = await _structured(OpenAICompatProvider(_settings(settings)))
    assert resp.parsed == {"verdict": "malicious", "confidence": 0.7}
    retry_messages = json.loads(route.calls[1].request.content)["messages"]
    assert retry_messages[-2] == {"role": "assistant", "content": "The verdict is malicious."}
    assert "not a valid JSON object" in retry_messages[-1]["content"]
    assert resp.usage.output_tokens == 60  # both attempts counted


@respx.mock
async def test_invalid_json_twice_returns_unparsed(settings: Settings) -> None:
    respx.post(URL).mock(
        side_effect=[
            httpx.Response(200, json=completion('{"verdict": "unknown", "confidence": 3}')),
            httpx.Response(200, json=completion("still not it")),
        ]
    )
    resp = await _structured(OpenAICompatProvider(_settings(settings)))
    assert resp.parsed is None
    assert resp.text == "still not it"


@respx.mock
async def test_content_filter_is_refusal(settings: Settings) -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, json=completion("", finish="content_filter")))
    resp = await _structured(OpenAICompatProvider(_settings(settings)))
    assert resp.refused and resp.stop_reason == "refusal"


async def test_web_search_not_supported(settings: Settings) -> None:
    with pytest.raises(ProviderCapabilityError):
        await _structured(OpenAICompatProvider(_settings(settings)), web_search=True)


def test_message_conversion_roundtrip() -> None:
    history = [
        {"role": "user", "content": "What did 203.0.113.10 do?"},
        {
            "role": "assistant",
            "content": [
                {"type": "thinking", "thinking": "", "signature": "x"},
                {"type": "text", "text": "Checking."},
                {
                    "type": "tool_use",
                    "id": "call_1",
                    "name": "search_events",
                    "input": {"source_ip": "203.0.113.10"},
                },
            ],
        },
        {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": "call_1", "content": "3 events"},
                {"type": "text", "text": "and summarize"},
            ],
        },
    ]
    out = to_openai_messages("sys", history)
    assert out[0] == {"role": "system", "content": "sys"}
    assert out[1] == {"role": "user", "content": "What did 203.0.113.10 do?"}
    assert out[2]["role"] == "assistant" and out[2]["content"] == "Checking."
    assert out[2]["tool_calls"][0]["function"] == {
        "name": "search_events",
        "arguments": json.dumps({"source_ip": "203.0.113.10"}),
    }
    assert out[3] == {"role": "tool", "tool_call_id": "call_1", "content": "3 events"}
    assert out[4] == {"role": "user", "content": "and summarize"}


@respx.mock
async def test_chat_tool_calls(settings: Settings) -> None:
    route = respx.post(URL).mock(
        return_value=httpx.Response(
            200,
            json=completion(
                None,
                finish="tool_calls",
                tool_calls=[
                    {
                        "id": "call_9",
                        "type": "function",
                        "function": {"name": "search_events", "arguments": '{"source_ip": "198.51.100.7"}'},
                    }
                ],
            ),
        )
    )
    tools = [
        ToolSpec(
            name="search_events",
            description="read-only search",
            input_schema={"type": "object", "properties": {"source_ip": {"type": "string"}}},
        )
    ]
    turn = await OpenAICompatProvider(_settings(settings)).chat(
        model="llama3.1:8b",
        system="sys",
        messages=[{"role": "user", "content": "hi"}],
        tools=tools,
        max_tokens=512,
        effort=None,
        cache=False,
    )
    assert turn.stop_reason == "tool_use"
    assert [(c.id, c.name, c.input) for c in turn.tool_calls] == [
        ("call_9", "search_events", {"source_ip": "198.51.100.7"})
    ]
    assert turn.raw_content == [
        {"type": "tool_use", "id": "call_9", "name": "search_events", "input": {"source_ip": "198.51.100.7"}}
    ]
    body = json.loads(route.calls[0].request.content)
    assert body["tools"][0]["function"]["name"] == "search_events"
    assert "tool_choice" not in body
