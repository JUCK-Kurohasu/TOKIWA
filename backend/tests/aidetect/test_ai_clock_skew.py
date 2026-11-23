"""Future-dated events must not stop AI attribution (audit #19, repro docs/audit/2026-11/repro/L04/lab/ts_poison.py).

The repro: one event dated ahead of everything else (sensor clock +31 min, +1 day, +70 years) dragged
``SessionTracker.max_event_ts`` forward; every flush then expired all live sessions, so an AI agent's session fell
apart into fragments of a few requests and was never classified. The repro's events start in 2026-10 (the past),
so here the agent traffic is pinned to an injected wall clock instead: the poison is *future* relative to it, which
is what a live deployment sees. The poison carries the same ``sensor_id`` as the victim traffic because an unbound
ingest token can claim any sensor id — the cap itself has to hold.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from tokiwa.aidetect.sessions import SessionTracker
from tokiwa.db.models.core import AuditRow
from tokiwa.db.session import session_scope
from tokiwa.enrich.sessionizer import current_sessionizer
from tokiwa.schemas.common import ActorType
from tokiwa.schemas.events import Endpoint, Event, EventKind, HttpInfo
from tokiwa.util import utcnow

from . import synth

SENSOR = "gate-1"


def _agent() -> list[Event]:
    events = synth.ai_agent(seed=3)
    for e in events:
        e.sensor_id = SENSOR
    return events


def _probe(ts_offset_s: float, base: Event, ip: str = "10.9.9.9", sensor: str = SENSOR) -> Event:
    return Event(
        timestamp=base.timestamp + timedelta(seconds=ts_offset_s),
        kind=EventKind.HTTP,
        dataset="gate.http",
        sensor_id=sensor,
        source=Endpoint(ip=ip),
        http=HttpInfo(method="GET", path="/health", status=200, user_agent="kube-probe/1.30"),
    )


def _batches(events: list[Event], window_s: float = 1.0) -> list[list[Event]]:
    out: list[list[Event]] = []
    for e in sorted(events, key=lambda x: x.timestamp):
        if out and (e.timestamp - out[-1][0].timestamp).total_seconds() <= window_s:
            out[-1].append(e)
        else:
            out.append([e])
    return out


def _replay(
    agent: list[Event], *, poison_offset_s: float | None, max_skew_s: float = 120.0
) -> SessionTracker:
    """Live-like replay: the wall clock follows the traffic, flush (drain -> expire_idle) after every batch."""
    now = [agent[0].timestamp.timestamp()]
    tr = SessionTracker(clock=lambda: now[0], max_future_skew_s=max_skew_s)
    if poison_offset_s is not None:
        tr.observe_batch([_probe(poison_offset_s, agent[0])])
        tr.drain_dirty()
    for batch in _batches(agent):
        now[0] = batch[-1].timestamp.timestamp()
        tr.observe_batch(batch)
        tr.drain_dirty()
    return tr


@pytest.mark.parametrize(
    "offset_s", [31 * 60, 86_400, 70 * 365 * 86_400], ids=["+31min", "+1day", "+70years"]
)
def test_one_future_event_does_not_fragment_sessions(offset_s: int) -> None:
    agent = _agent()
    tr = _replay(agent, poison_offset_s=offset_s)
    sids = {e.session_id for e in agent}
    assert len(sids) == 1, f"agent split into {len(sids)} sessions"
    s = tr.get(sids.pop())
    assert s is not None and s.request_count == len(agent)
    assert s.classification == ActorType.AI_AGENT and s.ai_score >= 0.7
    assert tr.stats["future_capped"] == 1
    assert tr.max_event_ts <= agent[-1].timestamp.timestamp() + 120.0


def test_without_the_cap_the_repro_still_fragments() -> None:
    """Guards the test above: with an effectively unlimited skew the original bug comes back."""
    agent = _agent()
    tr = _replay(agent, poison_offset_s=86_400, max_skew_s=1e12)
    assert len({e.session_id for e in agent}) > 1
    assert tr.stats["expired"] > 1


def test_past_dated_events_keep_their_behaviour() -> None:
    """Late / re-sent events are neither clamped nor allowed to disturb the live session."""
    agent = _agent()
    tr = _replay(agent, poison_offset_s=None)
    sid = agent[0].session_id
    before = tr.max_event_ts
    # a re-sent copy of an earlier request of the same client joins the same session
    resent = copy.deepcopy(agent[5])
    resent.id = "resent-1"
    # a 3-hour-old request from someone else becomes its own (already idle) session
    old = _probe(-3 * 3600, agent[0], ip="10.8.8.8")
    tr.observe_batch([resent, old])
    assert resent.session_id == sid and resent.timestamp == agent[5].timestamp
    assert old.session_id is not None and old.session_id != sid
    assert tr.max_event_ts == before
    tr.drain_dirty()
    s = tr.get(sid)
    assert s is not None and s.request_count == len(agent) + 1 and s.classification == ActorType.AI_AGENT
    assert tr.get(old.session_id) is None  # idle relative to the reference clock -> finalized and persisted


@pytest.mark.parametrize("per_sensor", [True, False], ids=["per-sensor", "global-clock"])
def test_backlog_from_another_sensor_is_judged_on_its_own_clock(per_sensor: bool) -> None:
    """A sensor re-sending a 3-hour-old backlog while another sensor is live keeps its sessions whole."""
    agent = _agent()
    for e in agent:
        e.sensor_id = "gate-backlog"
    live_base = agent[-1]
    tr = SessionTracker(clock=lambda: live_base.timestamp.timestamp() + 3 * 3600 + 60)
    if not per_sensor:  # the old behaviour: one clock for everyone
        tr.reference_ts = lambda sensor: tr.max_event_ts  # type: ignore[method-assign]
    for i, batch in enumerate(_batches(agent)):
        live = _probe(3 * 3600 + i, live_base, ip="10.7.7.7", sensor="nginx-live")
        tr.observe_batch([live, *batch])
        tr.drain_dirty()
    sids = {e.session_id for e in agent}
    if per_sensor:
        assert len(sids) == 1
        s = tr.get(sids.pop())
        assert s is not None and s.classification == ActorType.AI_AGENT
    else:
        assert len(sids) > 1  # every flush expired the backlog session


def test_sensor_clocks_are_bounded() -> None:
    from tokiwa.aidetect.sessions import MAX_SENSOR_CLOCKS

    base = _agent()[0]
    tr = SessionTracker()
    tr.observe_batch([_probe(i, base, ip=f"10.6.{i // 256}.{i % 256}", sensor=f"s{i}") for i in range(300)])
    assert len(tr._sensor_ts) == MAX_SENSOR_CLOCKS
    assert tr.reference_ts("s0") == tr.max_event_ts  # recycled slot -> global mark


# ------------------------------------------------------------------------------------------------ ingest route


async def test_ingest_clamps_future_timestamps_only(
    client: httpx.AsyncClient, ingest_headers: dict[str, str], admin_headers: dict[str, str]
) -> None:
    now = utcnow()
    cases = {
        "198.51.100.61": now + timedelta(days=1),  # clamped
        "198.51.100.62": now + timedelta(seconds=60),  # within the tolerated skew
        "198.51.100.63": now - timedelta(hours=3),  # late delivery: untouched
    }
    payload = {
        "events": [
            {
                "kind": "http",
                "dataset": "nginx.access",
                "sensor_id": SENSOR,
                "timestamp": ts.isoformat(),
                "source": {"ip": ip},
                "http": {"method": "GET", "path": "/", "status": 200, "user_agent": "curl/8.5.0"},
                # a client cannot pre-seed the server-owned original timestamp
                "labels": {"ingest.original_timestamp": "1999-01-01T00:00:00+00:00"},
            }
            for ip, ts in cases.items()
        ]
    }
    r = await client.post("/api/v1/ingest/events", json=payload, headers=ingest_headers)
    assert r.status_code == 200, r.text

    stored = {}
    for ip in cases:
        r = await client.get("/api/v1/events", params={"source_ip": ip}, headers=admin_headers)
        assert r.status_code == 200, r.text
        (item,) = r.json()["items"]
        stored[ip] = item

    def ts(item: dict[str, object]) -> datetime:
        return datetime.fromisoformat(str(item["timestamp"]).replace("Z", "+00:00"))

    future = stored["198.51.100.61"]
    assert "clock_skew" in future["tags"]
    assert future["labels"]["ingest.original_timestamp"] == cases["198.51.100.61"].isoformat()
    assert abs((ts(future) - now).total_seconds()) < 60
    for ip in ("198.51.100.62", "198.51.100.63"):
        item = stored[ip]
        assert "clock_skew" not in item["tags"] and "ingest.original_timestamp" not in item["labels"]
        assert ts(item) == cases[ip]

    sz = current_sessionizer()
    assert sz is not None
    assert sz.tracker.max_event_ts <= utcnow().timestamp() + 120.0
    async with session_scope() as db:
        rows = (
            (await db.execute(select(AuditRow).where(AuditRow.action == "ingest.clock_skew"))).scalars().all()
        )
    assert len(rows) == 1 and rows[0].details["events"] == 1
