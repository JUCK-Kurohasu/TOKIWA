"""Fixtures for the llm module tests.

The Anthropic SDK 2.x is built on ``httpx2``; ``respx`` patches ``httpx`` and would silently not see SDK traffic.
So the fake server here is an ``httpx2.MockTransport`` injected through ``DefaultAsyncHttpxClient`` - the real SDK
request building and response parsing still run, only the network is replaced.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx2
import pytest
from anthropic import AsyncAnthropic, DefaultAsyncHttpxClient

Responder = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]


def anthropic_message(
    content: list[dict[str, Any]],
    *,
    model: str = "claude-opus-5-5",
    stop_reason: str | None = "end_turn",
    usage: dict[str, Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": usage
        or {
            "input_tokens": 100,
            "output_tokens": 20,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
        },
        **extra,
    }


class FakeAnthropicServer:
    """Queue of canned responses; records every request (headers + JSON body)."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self._queue: list[tuple[int, dict[str, Any]] | Responder] = []

    def reply(self, payload: dict[str, Any], status: int = 200) -> FakeAnthropicServer:
        self._queue.append((status, payload))
        return self

    def reply_with(self, fn: Responder) -> FakeAnthropicServer:
        self._queue.append(fn)
        return self

    def _handler(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content) if request.content else {}  # GET requests have no body
        self.requests.append({"url": str(request.url), "headers": dict(request.headers), "body": body})
        if not self._queue:
            return httpx2.Response(
                500, json={"type": "error", "error": {"type": "api_error", "message": "no reply"}}
            )
        item = self._queue.pop(0)
        status, payload = item(body) if callable(item) else item
        return httpx2.Response(status, json=payload, headers={"request-id": f"req_{len(self.requests)}"})

    def client(self) -> AsyncAnthropic:
        return AsyncAnthropic(
            api_key="sk-ant-test-0000000000000000",
            max_retries=0,
            http_client=DefaultAsyncHttpxClient(transport=httpx2.MockTransport(self._handler)),
        )

    @property
    def bodies(self) -> list[dict[str, Any]]:
        return [r["body"] for r in self.requests]


@pytest.fixture
def fake_anthropic() -> FakeAnthropicServer:
    return FakeAnthropicServer()


@pytest.fixture
def msg() -> Callable[..., dict[str, Any]]:
    return anthropic_message
