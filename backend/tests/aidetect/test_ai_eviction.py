"""Live-session eviction under a flood (audit #88, repro docs/audit/2026-11/repro/L04/lab/evict.py).

The repro: with plain LRU (fixed 4096 slots), ~4100 one-request clients from fresh IPs pushed a quiet AI agent's
session out; its next requests started a new session with features reset to zero. The tracker now evicts
one-request low-score sessions first and gives sessions with AI / canary / decoy evidence a second chance. A small
capacity keeps these tests fast; the policy does not depend on the size.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from tokiwa.aidetect.sessions import LiveSession, SessionTracker
from tokiwa.enrich.sessionizer import Sessionizer
from tokiwa.schemas.common import ActorType
from tokiwa.schemas.events import Endpoint, Event, EventKind, HttpInfo

from . import synth

CAPACITY = 64


def _flood(ts: datetime, n: int, *, start: int = 0, requests: int = 1) -> list[Event]:
    """``n`` distinct clients (fresh IPs), ``requests`` plain GETs each — inert, low-score traffic."""
    out = []
    for i in range(start, start + n):
        for k in range(requests):
            out.append(
                Event(
                    timestamp=ts + timedelta(milliseconds=k),
                    kind=EventKind.HTTP,
                    dataset="gate.http",
                    source=Endpoint(ip=f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"),
                    http=HttpInfo(
                        method="GET", path="/", status=200, user_agent="Mozilla/5.0 (compatible; x)"
                    ),
                )
            )
    return out


def _plain_lru(tr: SessionTracker) -> None:
    """The pre-#88 policy, to show the tests reproduce the problem."""

    def oldest(exclude: LiveSession) -> LiveSession | None:
        return next((s for s in tr._by_key.values() if s is not exclude), None)

    tr._pick_victim = oldest  # type: ignore[method-assign]


@pytest.mark.parametrize("policy", ["weighted", "plain-lru"])
def test_flood_of_one_request_clients_does_not_split_an_agent(policy: str) -> None:
    agent = synth.ai_agent(seed=3)
    tr = SessionTracker(max_sessions=CAPACITY)
    if policy == "plain-lru":
        _plain_lru(tr)
    cut = len(agent) // 3
    tr.observe_batch(agent[:cut])
    tr.drain_dirty()
    ts = agent[cut - 1].timestamp
    for k in range(0, 3 * CAPACITY, 50):  # ~3x capacity of one-shot clients, in ingest-sized batches
        tr.observe_batch(_flood(ts, 50, start=k))
    tr.observe_batch(agent[cut:])
    sids = {e.session_id for e in agent}
    if policy == "plain-lru":
        assert len(sids) == 2  # the problem: the agent was evicted and restarted from zero
        return
    assert len(sids) == 1
    s = tr.get(sids.pop())
    assert s is not None and s.request_count == len(agent) and s.classification == ActorType.AI_AGENT
    assert len(tr) <= CAPACITY and tr.stats["evicted"] >= 2 * CAPACITY
    assert tr.stats["evicted_valuable"] == 0


def test_ai_session_gets_a_second_chance_against_multi_request_flood() -> None:
    """Flood clients with several requests each are not 'cheap', but still go before an AI-classified session."""
    agent = synth.ai_agent(seed=4)
    tr = SessionTracker(max_sessions=CAPACITY)
    tr.observe_batch(agent)
    s = tr.get(agent[0].session_id)
    assert s is not None and s.classification == ActorType.AI_AGENT
    ts = agent[-1].timestamp
    for k in range(2 * CAPACITY):  # one client per batch so each has its 6 requests before the next arrives
        tr.observe_batch(_flood(ts, 1, start=k, requests=6))
    assert tr.get(s.id) is s
    assert tr.stats["evicted_valuable"] > 0  # the 6-request flood sessions themselves


def test_only_protected_sessions_left_still_bounds_memory() -> None:
    tr = SessionTracker(max_sessions=16)
    for i in range(24):  # one agent per batch: each is scored (and protected) before the next one arrives
        tr.observe_batch(synth.ai_agent(seed=i, ip=f"198.51.100.{i}"))
    assert len(tr) <= 16 and tr.stats["evicted_valuable"] == 8
    assert all(s.classification == ActorType.AI_AGENT for s in tr.sessions())


def test_sessionizer_reads_the_limit_from_settings(settings, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    assert Sessionizer().tracker.max_sessions == settings.detection.max_live_sessions == 4096
    monkeypatch.setattr(settings.detection, "max_live_sessions", 128)
    assert Sessionizer().tracker.max_sessions == 128


def test_eviction_pressure_warning(settings, caplog: pytest.LogCaptureFixture) -> None:  # type: ignore[no-untyped-def]
    sz = Sessionizer()
    t0 = sz._evict_mark[0]
    sz.tracker.stats["evicted"] += 10
    assert not sz.check_eviction_pressure(t0 + 61)  # a few evictions of one-shot sessions: normal churn
    sz.tracker.stats["evicted"] += 5000
    with caplog.at_level("WARNING"):
        assert sz.check_eviction_pressure(t0 + 122)
    assert "under pressure" in caplog.text
    sz.tracker.stats["evicted"] += 5000
    assert not sz.check_eviction_pressure(t0 + 183)  # rate-limited
