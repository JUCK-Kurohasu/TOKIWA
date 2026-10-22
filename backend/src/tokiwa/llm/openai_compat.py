"""OpenAI-compatible provider (local Ollama / vLLM / llama.cpp server ...). OWNER: llm module.

For deployments where telemetry must not leave the premises. Talks plain HTTP to ``POST {base}/v1/chat/completions``
(``openai_base_url`` may be given with or without the trailing ``/v1``).

Structured output strategy (local servers vary a lot):

1. ``response_format={"type": "json_schema", ...}`` when the server accepts it.
2. If the server rejects ``response_format`` (HTTP 400/404/422/501), remember that and switch to prompt mode:
   "answer with JSON only" + the JSON Schema in the system prompt, then extract the JSON object from the reply.
3. If the reply is not valid JSON / does not validate, retry once with a correction message. A second failure is
   returned as ``parsed=None`` so the gateway records ``invalid_output`` (the caller falls back to rules).

Tool calls are converted between the neutral (Anthropic-style) message format used by the gateway and the OpenAI
``tool_calls`` / ``role: tool`` format. Web search is not available on local models: requesting it raises, which
the gateway records as an error (better than letting a local model invent "recent" findings).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, ClassVar

import httpx
from pydantic import BaseModel, ValidationError

from tokiwa.config import Settings
from tokiwa.llm.base import ChatTurn, LLMProvider, LLMUsage, ProviderResponse, ToolCall, ToolSpec

log = logging.getLogger(__name__)

_RESPONSE_FORMAT_REJECTED = {400, 404, 422, 501}
_FINISH_TO_STOP = {
    "stop": "end_turn",
    "length": "max_tokens",
    "tool_calls": "tool_use",
    "function_call": "tool_use",
    "content_filter": "refusal",
}
_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S | re.I)

JSON_ONLY_INSTRUCTIONS = """\

OUTPUT FORMAT: respond with a single JSON object only - no prose, no markdown fences. The object must validate
against this JSON Schema:
{schema}"""

JSON_RETRY_MESSAGE = (
    "Your previous reply was not a valid JSON object for the required schema ({error}). "
    "Reply again with only the corrected JSON object."
)


class ProviderCapabilityError(RuntimeError):
    """The configured provider cannot serve this kind of request."""


def chat_completions_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    if not base.endswith("/v1"):
        base += "/v1"
    return base + "/chat/completions"


def extract_json_object(text: str | None) -> dict[str, Any]:
    """Best-effort JSON object extraction from model text (fenced block, bare object, or surrounding prose)."""
    if not text:
        raise ValueError("empty response")
    candidates = [m.group(1) for m in _FENCE.finditer(text)]
    candidates.append(text)
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        candidates.append(text[start : end + 1])
    for cand in candidates:
        try:
            value = json.loads(cand.strip())
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(value, dict):
            return value
    raise ValueError("response is not a JSON object")


def _block_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict) and b.get("type") == "text":
                parts.append(str(b.get("text") or ""))
            elif isinstance(b, str):
                parts.append(b)
        return "".join(parts)
    return "" if content is None else json.dumps(content, ensure_ascii=False, default=str)


def to_openai_messages(system: str, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Neutral (Anthropic-style) history -> OpenAI chat messages."""
    out: list[dict[str, Any]] = []
    if system:
        out.append({"role": "system", "content": system})
    for m in messages:
        role = m.get("role")
        content = m.get("content")
        if role == "assistant":
            msg: dict[str, Any] = {"role": "assistant", "content": _block_text(content) or None}
            if isinstance(content, list):
                calls = [
                    {
                        "id": b.get("id"),
                        "type": "function",
                        "function": {
                            "name": b.get("name"),
                            "arguments": json.dumps(b.get("input") or {}, ensure_ascii=False),
                        },
                    }
                    for b in content
                    if isinstance(b, dict) and b.get("type") == "tool_use"
                ]
                if calls:
                    msg["tool_calls"] = calls
            out.append(msg)
        elif role == "user":
            if isinstance(content, list):
                # tool_result blocks become role=tool messages (they must directly follow the assistant tool_calls)
                for b in content:
                    if isinstance(b, dict) and b.get("type") == "tool_result":
                        text = _block_text(b.get("content"))
                        if b.get("is_error"):
                            text = f"ERROR: {text}"
                        out.append({"role": "tool", "tool_call_id": b.get("tool_use_id"), "content": text})
                rest = [b for b in content if not (isinstance(b, dict) and b.get("type") == "tool_result")]
                text = _block_text(rest)
                if text:
                    out.append({"role": "user", "content": text})
            else:
                out.append({"role": "user", "content": _block_text(content)})
        elif role == "system":
            out.append({"role": "system", "content": _block_text(content)})
    return out


def to_openai_tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {"name": t.name, "description": t.description, "parameters": t.input_schema},
        }
        for t in tools
    ]


def usage_from_openai(data: dict[str, Any]) -> LLMUsage:
    u = data.get("usage") or {}
    prompt = int(u.get("prompt_tokens") or 0)
    cached = int((u.get("prompt_tokens_details") or {}).get("cached_tokens") or 0)
    return LLMUsage(
        # Anthropic semantics: input_tokens excludes cache reads.
        input_tokens=max(0, prompt - cached),
        output_tokens=int(u.get("completion_tokens") or 0),
        cache_read_tokens=cached,
    )


def _add(a: LLMUsage, b: LLMUsage) -> LLMUsage:
    return LLMUsage(
        input_tokens=a.input_tokens + b.input_tokens,
        output_tokens=a.output_tokens + b.output_tokens,
        cache_read_tokens=a.cache_read_tokens + b.cache_read_tokens,
        cache_write_tokens=a.cache_write_tokens + b.cache_write_tokens,
        web_search_requests=a.web_search_requests + b.web_search_requests,
    )


class OpenAICompatProvider(LLMProvider):
    name: ClassVar[str] = "openai_compat"

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self._transport = transport  # tests
        # None = unknown, learned on first structured call.
        self.json_schema_supported: bool | None = None

    def available(self) -> bool:
        return bool(self.settings.llm.openai_base_url)

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        key = self.settings.llm.openai_api_key
        if key is not None and key.get_secret_value():
            headers["Authorization"] = f"Bearer {key.get_secret_value()}"
        return headers

    async def _post(self, body: dict[str, Any]) -> httpx.Response:
        base = self.settings.llm.openai_base_url
        if not base:
            raise RuntimeError("openai_base_url is not configured")
        async with httpx.AsyncClient(
            timeout=self.settings.llm.request_timeout_seconds, transport=self._transport
        ) as client:
            return await client.post(chat_completions_url(base), json=body, headers=self._headers())

    async def _completion(self, body: dict[str, Any]) -> dict[str, Any]:
        resp = await self._post(body)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict) or not data.get("choices"):
            raise ValueError("malformed chat completion response")
        return data

    # ------------------------------------------------------------------ structured
    async def complete_structured(
        self,
        *,
        model: str,
        system: str,
        user: str,
        schema: type[BaseModel],
        max_tokens: int,
        effort: str | None,
        cache: bool,
        web_search: bool = False,
        web_search_max_uses: int = 5,
        allowed_domains: list[str] | None = None,
    ) -> ProviderResponse:
        if web_search:
            raise ProviderCapabilityError("web search is not supported by the openai_compat provider")
        json_schema = schema.model_json_schema()
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        usage = LLMUsage()
        data: dict[str, Any] | None = None
        rejected_now = False

        if self.json_schema_supported is not False:
            body = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {"name": schema.__name__, "schema": json_schema, "strict": True},
                },
            }
            resp = await self._post(body)
            if resp.status_code in _RESPONSE_FORMAT_REJECTED:
                log.info(
                    "openai_compat server rejected response_format (%s); trying prompt mode", resp.status_code
                )
                rejected_now = True
            else:
                resp.raise_for_status()
                data = resp.json()
                self.json_schema_supported = True

        if data is None:
            messages = [
                {
                    "role": "system",
                    "content": system
                    + JSON_ONLY_INSTRUCTIONS.format(schema=json.dumps(json_schema, ensure_ascii=False)),
                },
                {"role": "user", "content": user},
            ]
            data = await self._completion({"model": model, "messages": messages, "max_tokens": max_tokens})
            if rejected_now:
                # Only remember "no response_format" once prompt mode actually works (the 4xx may have had another
                # cause, e.g. an unknown model name).
                self.json_schema_supported = False

        usage = _add(usage, usage_from_openai(data))
        parsed, text, finish, error = self._parse_choice(data, schema)
        if finish == "content_filter":
            return ProviderResponse(
                model=str(data.get("model") or model),
                text=text,
                usage=usage,
                stop_reason="refusal",
                refused=True,
            )
        if parsed is None:
            # One corrective retry (also covers servers that accept response_format but do not enforce it).
            retry_messages = [
                *messages,
                {"role": "assistant", "content": text or ""},
                {"role": "user", "content": JSON_RETRY_MESSAGE.format(error=error)},
            ]
            data = await self._completion(
                {"model": model, "messages": retry_messages, "max_tokens": max_tokens}
            )
            usage = _add(usage, usage_from_openai(data))
            parsed, text, finish, error = self._parse_choice(data, schema)
            if finish == "content_filter":
                return ProviderResponse(
                    model=str(data.get("model") or model),
                    text=text,
                    usage=usage,
                    stop_reason="refusal",
                    refused=True,
                )
        return ProviderResponse(
            model=str(data.get("model") or model),
            text=text,
            parsed=parsed,
            usage=usage,
            stop_reason=_FINISH_TO_STOP.get(str(finish), str(finish) if finish else None),
            request_id=data.get("id"),
        )

    @staticmethod
    def _parse_choice(
        data: dict[str, Any], schema: type[BaseModel]
    ) -> tuple[dict[str, Any] | None, str | None, str | None, str | None]:
        choice = data["choices"][0]
        message = choice.get("message") or {}
        text = message.get("content")
        finish = choice.get("finish_reason")
        try:
            obj = extract_json_object(text)
            schema.model_validate(obj)
        except (ValueError, ValidationError) as exc:
            return None, text, finish, str(exc)[:300]
        return obj, text, finish, None

    # ------------------------------------------------------------------ chat
    async def chat(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
        max_tokens: int,
        effort: str | None,
        cache: bool,
    ) -> ChatTurn:
        body: dict[str, Any] = {
            "model": model,
            "messages": to_openai_messages(system, messages),
            "max_tokens": max_tokens,
        }
        if tools:
            body["tools"] = to_openai_tools(tools)  # tool_choice left at the server default ("auto")
        data = await self._completion(body)
        choice = data["choices"][0]
        message = choice.get("message") or {}
        text = message.get("content") or ""
        finish = choice.get("finish_reason")
        tool_calls: list[ToolCall] = []
        raw: list[dict[str, Any]] = []
        if text:
            raw.append({"type": "text", "text": text})
        for i, call in enumerate(message.get("tool_calls") or []):
            fn = call.get("function") or {}
            args = fn.get("arguments")
            try:
                parsed_args = json.loads(args) if isinstance(args, str) else dict(args or {})
            except (json.JSONDecodeError, TypeError, ValueError):
                parsed_args = {"_invalid_arguments": str(args)[:2000]}
            if not isinstance(parsed_args, dict):
                parsed_args = {"_invalid_arguments": str(args)[:2000]}
            call_id = str(call.get("id") or f"call_{i}")
            name = str(fn.get("name") or "")
            tool_calls.append(ToolCall(id=call_id, name=name, input=parsed_args))
            raw.append({"type": "tool_use", "id": call_id, "name": name, "input": parsed_args})
        stop = _FINISH_TO_STOP.get(str(finish), str(finish) if finish else None)
        if tool_calls and stop == "end_turn":
            stop = "tool_use"  # some servers report "stop" alongside tool calls
        return ChatTurn(
            model=str(data.get("model") or model),
            text=text,
            tool_calls=tool_calls,
            raw_content=raw or [{"type": "text", "text": ""}],
            usage=usage_from_openai(data),
            stop_reason=stop,
            refused=finish == "content_filter",
        )
