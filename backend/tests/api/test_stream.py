"""Live SSE stream: auth, relayed topics, payload shaping, keep-alive and listener cleanup on disconnect."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime

import httpx
import pytest
from pydantic import BaseModel

from tokiwa.api.routes import stream as stream_mod
from tokiwa.bus import bus
from tokiwa.schemas.events import Event, EventKind
from tokiwa.schemas.system import LLMCallDetail, LLMCallStatus

from .conftest import OpenSSE


def _token(headers: dict[str, str]) -> str:
    return headers["Authorization"].removeprefix("Bearer ")


class _Sample(BaseModel):
    id: str
    at: datetime


def _llm_call() -> LLMCallDetail:
    return LLMCallDetail(
        id="c1",
        created_at=datetime(2026, 10, 22, tzinfo=UTC),
        provider="mock",
        model="m",
        tier="fast",
        purpose="triage",
        prompt_version="p@1",
        status=LLMCallStatus.OK,
        input_tokens=1,
        output_tokens=2,
        cache_read_tokens=0,
        cache_write_tokens=0,
        web_search_requests=0,
        cost_usd=0.0,
        latency_ms=1.0,
        related={},
        request_redacted="SECRET PROMPT",
        response_text="SECRET RESPONSE",
    )


async def test_stream_requires_auth(client: httpx.AsyncClient, open_sse: OpenSSE) -> None:
    assert (await client.get("/api/v1/stream")).status_code == 401
    assert (await client.get("/api/v1/stream", params={"access_token": "junk"})).status_code == 401
    # API tokens are not user credentials.
    assert (await client.get("/api/v1/stream", params={"access_token": "tkw_abc"})).status_code == 401
    async with open_sse() as conn:
        assert conn.status == 401
        assert json.loads(await conn.body())["detail"] == "not authenticated"
    assert not bus._queues  # nothing registered for rejected requests


async def test_stream_relays_bus_topics(open_sse: OpenSSE, viewer_headers: dict[str, str]) -> None:
    before = len(bus._queues)
    async with open_sse(params={"access_token": _token(viewer_headers)}) as conn:
        assert conn.status == 200
        assert conn.headers["content-type"].startswith("text/event-stream")
        assert (await conn.next_event()) == {"comment": "connected"}
        assert len(bus._queues) == before + 1

        at = datetime(2026, 10, 22, 1, 2, 3, tzinfo=UTC)
        await bus.publish("alert.created", _Sample(id="a1", at=at))
        await bus.publish("intel.vuln_matched", {"id": "not relayed"})
        await bus.publish(
            "event.ingested", [Event(kind=EventKind.HTTP, dataset="gate.http") for _ in range(3)]
        )
        await bus.publish("custom.topic", {"id": "not relayed"})
        await bus.publish("incident.updated", {"id": "i1", "at": at, "nested": _Sample(id="n", at=at)})
        await bus.publish("action.proposed", _Sample(id="act", at=at))
        await bus.publish(
            "deception.tripped", {"asset_id": "d1", "event_id": "e1", "source_ip": "203.0.113.9"}
        )
        await bus.publish("intel.advisory", _Sample(id="adv", at=at))
        await bus.publish("llm.call", _llm_call())

        msgs = [await conn.next_message() for _ in range(7)]
        assert [m["topic"] for m in msgs] == [
            "alert.created",
            "event.ingested",
            "incident.updated",
            "action.proposed",
            "deception.tripped",
            "intel.advisory",
            "llm.call",
        ]
        assert msgs[0]["data"] == {"id": "a1", "at": "2026-10-22T01:02:03Z"}
        assert msgs[1]["data"] == {"count": 3}  # telemetry is reduced to a count
        assert msgs[2]["data"] == {
            "id": "i1",
            "at": "2026-10-22T01:02:03Z",
            "nested": {"id": "n", "at": "2026-10-22T01:02:03Z"},
        }
        assert msgs[4]["data"]["source_ip"] == "203.0.113.9"
        llm = msgs[6]["data"]
        assert llm["id"] == "c1" and llm["status"] == "ok"
        assert "request_redacted" not in llm and "response_text" not in llm
    # Disconnect unregisters the bus listener.
    await asyncio.sleep(0)
    assert len(bus._queues) == before


async def test_stream_any_role_query_or_header(
    open_sse: OpenSSE, role_headers: dict[str, dict[str, str]]
) -> None:
    conns = {
        "viewer": open_sse(params={"access_token": _token(role_headers["viewer"])}),
        "analyst": open_sse(headers=role_headers["analyst"]),  # Authorization: Bearer also works
        "admin": open_sse(params={"access_token": _token(role_headers["admin"])}),
    }
    for role, sse in conns.items():
        async with sse as conn:
            assert conn.status == 200, role
            assert (await conn.next_event())["comment"] == "connected"
            await bus.publish("alert.updated", {"id": role})
            assert (await conn.next_message()) == {"topic": "alert.updated", "data": {"id": role}}
    assert not bus._queues


async def test_stream_keepalive(
    open_sse: OpenSSE, viewer_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(stream_mod, "KEEPALIVE_SECONDS", 0.05)
    async with open_sse(params={"access_token": _token(viewer_headers)}) as conn:
        assert (await conn.next_event())["comment"] == "connected"
        ping = await conn.next_event(timeout=2)
        assert ping["comment"].startswith("ping")
        assert "data" not in ping


def test_to_message_and_topic_filter() -> None:
    assert stream_mod.is_relayed("alert.created")
    assert stream_mod.is_relayed("incident.created")
    assert stream_mod.is_relayed("action.updated")
    assert stream_mod.is_relayed("llm.call")
    assert not stream_mod.is_relayed("intel.vuln_matched")
    assert not stream_mod.is_relayed("alerts")
    assert stream_mod.to_message("event.ingested", []) == {"topic": "event.ingested", "data": {"count": 0}}
    msg = stream_mod.to_message("deception.tripped", {"x": object()})
    assert isinstance(msg["data"]["x"], str)  # unknown objects degrade to str instead of breaking the stream
    json.dumps(msg)


def test_access_log_redacts_access_token(caplog: pytest.LogCaptureFixture) -> None:
    """uvicorn logs the full path incl. query string; the JWT passed via ?access_token= must not appear."""
    stream_mod.install_access_log_redaction()  # idempotent (already installed at import)
    access = logging.getLogger("uvicorn.access")
    assert sum(isinstance(f, stream_mod.RedactAccessToken) for f in access.filters) == 1
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
    path = f"/api/v1/stream?x=1&access_token={jwt}&y=2"
    with caplog.at_level(logging.INFO, logger="uvicorn.access"):
        # Same call shape as uvicorn.protocols.http.h11_impl
        access.info('%s - "%s %s HTTP/%s" %d', "127.0.0.1:1", "GET", path, "1.1", 200)
    line = caplog.records[-1].getMessage()
    assert jwt not in line
    assert "x=1&access_token=[REDACTED]&y=2" in line
