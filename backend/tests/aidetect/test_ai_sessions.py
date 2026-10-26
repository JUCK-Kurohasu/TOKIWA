"""Session tracker behaviour, sessionizer persistence and the sessions API (end-to-end through ingest)."""

from __future__ import annotations

import time
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select

from tokiwa.aidetect.sessions import SessionTracker
from tokiwa.db.models.detection import AlertRow
from tokiwa.db.models.telemetry import ActorSessionRow, EventRow
from tokiwa.db.session import session_scope
from tokiwa.enrich.sessionizer import current_sessionizer, flush_current
from tokiwa.schemas.common import ActorType
from tokiwa.schemas.events import Endpoint, Event, EventKind, LLMAppInfo

from . import synth

# ----------------------------------------------------------------------------------------------- tracker (no I/O)


def test_idle_timeout_splits_sessions() -> None:
    tr = SessionTracker(idle_timeout_s=60)
    events = synth.benign(seed=1)[:6]
    late = synth.benign(seed=1)[6:8]
    for e in late:
        e.timestamp = e.timestamp + timedelta(hours=1)
    tr.observe_batch(events + late)
    assert len({e.session_id for e in events}) == 1
    assert {e.session_id for e in late}.isdisjoint({events[0].session_id})


def test_different_clients_same_ip_are_separate_sessions() -> None:
    tr = SessionTracker()
    a = synth.ai_agent(seed=1, ip="198.51.100.1")
    b = synth.benign(seed=1, ip="198.51.100.1")
    tr.observe_batch(a + b)
    assert len(tr) == 2
    agent = tr.get(a[0].session_id)
    assert agent is not None and agent.classification == ActorType.AI_AGENT
    assert agent.features["ip_tool_fingerprints"] == 1


def test_lru_bound_and_pending_snapshots() -> None:
    tr = SessionTracker(max_sessions=10)
    events = [synth._Builder(f"10.9.0.{i}", synth.chrome_headers(), seed=i).req("/") for i in range(25)]
    tr.observe_batch(events)
    assert len(tr) == 10 and tr.stats["evicted"] == 15
    snaps = tr.drain_dirty()
    assert len(snaps) == 25  # evicted sessions are still persisted once
    assert tr.drain_dirty() == []


def test_non_http_events_attach_and_canary_decides() -> None:
    tr = SessionTracker()
    http = synth.benign(seed=2)
    tr.observe_batch(http)
    s = tr.get(http[0].session_id)
    assert s is not None and s.classification == ActorType.BENIGN
    canary = Event(
        timestamp=http[-1].timestamp,
        kind=EventKind.DECEPTION,
        dataset="gate.deception",
        source=Endpoint(ip=http[0].source_ip),
        deception={"asset_kind": "ai_canary"},  # type: ignore[arg-type]
    )
    tr.observe_batch([canary])
    assert canary.session_id == s.id
    assert s.classification == ActorType.AI_AGENT and s.ai_score >= 0.99
    # LLM-app prompt from an unseen IP gets its own session
    prompt = Event(
        kind=EventKind.LLM_APP,
        dataset="app.llm",
        source=Endpoint(ip="203.0.113.250"),
        llm_app=LLMAppInfo(prompt="hi"),
    )
    tr.observe_batch([prompt])
    assert prompt.session_id is not None and prompt.session_id != s.id


def test_ai_verdict_is_sticky_and_peak_score_kept() -> None:
    tr = SessionTracker()
    events = synth.ai_agent(seed=4)
    tr.observe_batch(events)
    s = tr.get(events[0].session_id)
    assert s is not None
    peak = s.ai_score
    b = synth._Builder(events[0].source_ip or "", dict(events[0].http.headers), seed=9)  # type: ignore[union-attr]
    b.t = events[-1].timestamp
    calm = []
    for _ in range(40):
        b.wait(20, 40)
        calm.append(b.req("/api/v1/products"))
    tr.observe_batch(calm)
    assert s.ai_score == peak and s.classification == ActorType.AI_AGENT
    assert s.features["ai_score_current"] <= peak


def test_tracker_throughput() -> None:
    tr = SessionTracker()
    events: list[Event] = []
    for i in range(20):
        events += synth.ai_agent(seed=i, ip=f"198.51.100.{i}")
        events += synth.scanner(seed=i, ip=f"192.0.2.{i}")
    events = events[:5000]
    start = time.perf_counter()
    for k in range(0, len(events), 100):
        tr.observe_batch(events[k : k + 100])
    elapsed = time.perf_counter() - start
    assert elapsed < 10.0, f"{len(events)} events took {elapsed:.2f}s"


# ------------------------------------------------------------------------------------ ingest -> DB -> sessions API


def _payload(events: list[Event]) -> dict[str, object]:
    return {"events": [e.model_dump(mode="json") for e in events]}


async def test_ingest_sessions_api_end_to_end(
    client: httpx.AsyncClient, ingest_headers: dict[str, str], admin_headers: dict[str, str]
) -> None:
    agent = synth.ai_agent(seed=5)
    benign = synth.benign(seed=5)
    r = await client.post("/api/v1/ingest/events", json=_payload(agent + benign), headers=ingest_headers)
    assert r.status_code == 200, r.text
    assert r.json()["alerts"] >= 1

    r = await client.get("/api/v1/sessions", headers=admin_headers)
    assert r.status_code == 200, r.text
    page = r.json()
    assert page["total"] == 2
    top = page["items"][0]
    assert top["classification"] == "ai_agent" and top["ai_score"] >= 0.7
    assert top["source_ip"] == agent[0].source_ip and top["request_count"] == len(agent)
    assert top["features"]["indicators"] and top["features"]["scores"]["ai"] >= 0.7

    r = await client.get("/api/v1/sessions", params={"classification": "benign"}, headers=admin_headers)
    assert [s["source_ip"] for s in r.json()["items"]] == [benign[0].source_ip]
    r = await client.get("/api/v1/sessions", params={"min_ai_score": 0.7}, headers=admin_headers)
    assert r.json()["total"] == 1
    r = await client.get("/api/v1/sessions", params={"source_ip": benign[0].source_ip}, headers=admin_headers)
    assert r.json()["total"] == 1

    r = await client.get(f"/api/v1/sessions/{top['id']}", headers=admin_headers)
    assert r.status_code == 200
    detail = r.json()
    assert detail["session"]["id"] == top["id"]
    assert len(detail["events"]) == len(agent) and len(detail["timeline"]) == len(agent)
    tl = detail["timeline"]
    assert tl[0]["gap_ms"] is None and all(p["gap_ms"] is not None for p in tl[1:])
    assert {p["band"] for p in tl[1:]} >= {"burst", "think"}
    assert any(p["error"] for p in tl)

    assert (await client.get("/api/v1/sessions/nope", headers=admin_headers)).status_code == 404
    assert (await client.get("/api/v1/sessions")).status_code == 401

    async with session_scope() as db:
        rules = set((await db.execute(select(AlertRow.rule_id))).scalars().all())
        sids = set((await db.execute(select(EventRow.session_id))).scalars().all())
    assert {"ai.agent_session", "ai.adaptive_mutation", "ai.semantic_recon"} <= rules
    assert None not in sids and len(sids) == 2


@pytest.mark.usefixtures("db")
async def test_persistence_preserves_incident_id() -> None:
    from tokiwa.pipeline.service import process_events

    events = synth.ai_agent(seed=6)
    await process_events(events[:10])
    await flush_current()
    sid = events[0].session_id
    async with session_scope() as db:
        row = await db.get(ActorSessionRow, sid)
        assert row is not None
        row.incident_id = "inc-123"
    await process_events(events[10:])
    sz = current_sessionizer()
    assert sz is not None
    await sz.flush()
    async with session_scope() as db:
        row = await db.get(ActorSessionRow, sid)
        assert row is not None
        assert row.incident_id == "inc-123"
        assert row.request_count == len(events)
        assert row.classification == "ai_agent"
