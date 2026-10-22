"""Dashboard summary / timeline: zeros on empty tables, aggregates over other modules' tables, caching."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import httpx
import pytest

from tokiwa.api.routes import dashboard
from tokiwa.db.models.detection import AlertRow, IncidentRow
from tokiwa.db.models.intel import VulnMatchRow, VulnRow
from tokiwa.db.models.llm import LLMCallRow
from tokiwa.db.models.response import ResponseActionRow
from tokiwa.db.models.telemetry import ActorSessionRow
from tokiwa.db.session import session_scope
from tokiwa.pipeline.store import store_events
from tokiwa.schemas.events import Endpoint, Event, EventKind
from tokiwa.util import new_id, utcnow

SEVERITIES = {"info", "low", "medium", "high", "critical"}


def _alert(**kw: Any) -> AlertRow:
    now = utcnow()
    base: dict[str, Any] = {
        "id": new_id(),
        "created_at": now,
        "updated_at": now,
        "first_seen": now,
        "last_seen": now,
        "fingerprint": new_id(),
        "rule_id": "web.sqli",
        "detector": "web.sqli",
        "title": "SQL injection attempt",
        "severity": "high",
        "category": "exploit_attempt",
        "count": 1,
    }
    base.update(kw)
    return AlertRow(**base)


def _incident(status: str, last_seen: datetime, title: str) -> IncidentRow:
    return IncidentRow(
        id=new_id(),
        created_at=last_seen,
        updated_at=last_seen,
        first_seen=last_seen,
        last_seen=last_seen,
        title=title,
        severity="high",
        status=status,
        category="ai_agent",
        actor_type="ai_agent",
    )


async def _seed() -> None:
    now = utcnow()
    old = now - timedelta(hours=30)
    async with session_scope() as s:
        s.add_all(
            [
                _alert(
                    source_ip="203.0.113.5", count=5, ai_score=0.9, category="ai_agent", severity="critical"
                ),
                _alert(source_ip="203.0.113.5", count=2, rule_id="web.traversal", title="Path traversal"),
                _alert(source_ip="198.51.100.7", count=3, rule_id="web.traversal", title="Path traversal"),
                _alert(source_ip=None, count=1, rule_id="port.new", title="New port", severity="medium"),
                # outside the 24h window
                _alert(source_ip="192.0.2.1", count=50, created_at=old, first_seen=old, last_seen=old),
            ]
        )
        s.add_all(
            [
                _incident("open", now - timedelta(minutes=5), "newest"),
                _incident("investigating", now - timedelta(minutes=10), "middle"),
                _incident("contained", now - timedelta(minutes=20), "contained"),
                _incident("resolved", now - timedelta(minutes=30), "resolved"),
                _incident("false_positive", now - timedelta(minutes=40), "fp"),
                _incident("open", now - timedelta(hours=2), "oldest"),
            ]
        )
        sess = {"client_fingerprint": "fp", "first_seen": now - timedelta(hours=1)}
        s.add_all(
            [
                ActorSessionRow(source_ip="203.0.113.5", last_seen=now, classification="ai_agent", **sess),
                ActorSessionRow(source_ip="203.0.113.6", last_seen=now, ai_score=0.95, **sess),
                ActorSessionRow(
                    source_ip="203.0.113.7", last_seen=now, ai_score=0.1, classification="human", **sess
                ),
                ActorSessionRow(source_ip="203.0.113.8", last_seen=old, classification="ai_agent", **sess),
            ]
        )
        s.add_all(
            [
                ResponseActionRow(action_type="block_ip", target="203.0.113.5", status="proposed"),
                ResponseActionRow(action_type="block_ip", target="203.0.113.6", status="proposed"),
                ResponseActionRow(action_type="block_ip", target="203.0.113.7", status="active"),
            ]
        )
        s.add_all(
            [
                VulnRow(id="CVE-2099-0001", kev=True),
                VulnRow(id="CVE-2099-0002", kev=False),
                VulnMatchRow(vuln_id="CVE-2099-0001", asset_id="a1", reason="version", status="open"),
                VulnMatchRow(vuln_id="CVE-2099-0001", asset_id="a2", reason="version", status="open"),
                VulnMatchRow(vuln_id="CVE-2099-0001", asset_id="a3", reason="version", status="resolved"),
                VulnMatchRow(vuln_id="CVE-2099-0002", asset_id="a1", reason="version", status="open"),
            ]
        )
        llm = {
            "provider": "anthropic",
            "model": "m",
            "tier": "fast",
            "purpose": "triage",
            "prompt_version": "p@1",
        }
        s.add_all(
            [
                LLMCallRow(status="ok", cost_usd=0.25, created_at=now, **llm),
                LLMCallRow(status="ok", cost_usd=0.5, created_at=now - timedelta(hours=1), **llm),
                LLMCallRow(status="ok", cost_usd=9.0, created_at=old, **llm),
            ]
        )
        await store_events(
            s,
            [
                Event(kind=EventKind.HTTP, dataset="gate.http", source=Endpoint(ip="203.0.113.5")),
                Event(kind=EventKind.HTTP, dataset="gate.http", source=Endpoint(ip="203.0.113.5")),
                Event(kind=EventKind.DNS, dataset="zeek.dns", timestamp=now - timedelta(hours=3)),
                Event(kind=EventKind.HTTP, dataset="gate.http", timestamp=old),
            ],
        )


async def test_summary_empty_tables_return_zeros(
    client: httpx.AsyncClient, viewer_headers: dict[str, str]
) -> None:
    r = await client.get("/api/v1/dashboard/summary", headers=viewer_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["alerts_24h"] == {"total": 0, "by_severity": dict.fromkeys(SEVERITIES, 0)}
    for key in ("open_incidents", "ai_sessions_24h", "events_24h", "pending_actions", "kev_matches"):
        assert body[key] == 0, key
    assert body["llm_cost_today_usd"] == 0
    assert body["llm_budget_usd"] == 5.0  # LLMSettings.daily_budget_usd default
    assert body["top_sources"] == [] and body["top_rules"] == [] and body["recent_incidents"] == []


async def test_summary_aggregates(client: httpx.AsyncClient, viewer_headers: dict[str, str]) -> None:
    await _seed()
    body = (await client.get("/api/v1/dashboard/summary", headers=viewer_headers)).json()
    assert body["alerts_24h"]["total"] == 4
    assert body["alerts_24h"]["by_severity"] == {"info": 0, "low": 0, "medium": 1, "high": 2, "critical": 1}
    assert body["open_incidents"] == 4  # open, investigating, contained, open(old)
    assert body["ai_sessions_24h"] == 2  # classified ai_agent OR ai_score >= threshold, within 24h
    assert body["events_24h"] == 3
    assert body["pending_actions"] == 2
    assert body["kev_matches"] == 2  # KEV vuln x open match only
    assert body["llm_cost_today_usd"] == pytest.approx(0.75)
    assert body["top_sources"] == [
        {"ip": "203.0.113.5", "count": 7, "ai_score": 0.9},
        {"ip": "198.51.100.7", "count": 3, "ai_score": None},
    ]
    assert body["top_rules"] == [
        {"rule_id": "web.sqli", "title": "SQL injection attempt", "count": 5},
        {"rule_id": "web.traversal", "title": "Path traversal", "count": 5},
        {"rule_id": "port.new", "title": "New port", "count": 1},
    ]  # ties are ordered by rule_id
    titles = [i["title"] for i in body["recent_incidents"]]
    assert titles == ["newest", "middle", "contained", "resolved", "fp"]
    assert body["recent_incidents"][0]["actor_type"] == "ai_agent"


async def test_summary_is_cached_briefly(client: httpx.AsyncClient, viewer_headers: dict[str, str]) -> None:
    first = (await client.get("/api/v1/dashboard/summary", headers=viewer_headers)).json()
    assert first["alerts_24h"]["total"] == 0
    async with session_scope() as s:
        s.add(_alert())
    cached = (await client.get("/api/v1/dashboard/summary", headers=viewer_headers)).json()
    assert cached["alerts_24h"]["total"] == 0
    dashboard.clear_cache()
    fresh = (await client.get("/api/v1/dashboard/summary", headers=viewer_headers)).json()
    assert fresh["alerts_24h"]["total"] == 1


async def test_summary_cache_expires(
    client: httpx.AsyncClient, viewer_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dashboard, "CACHE_TTL_SECONDS", 0.0)
    await client.get("/api/v1/dashboard/summary", headers=viewer_headers)
    async with session_scope() as s:
        s.add(_alert())
    body = (await client.get("/api/v1/dashboard/summary", headers=viewer_headers)).json()
    assert body["alerts_24h"]["total"] == 1


async def test_timeline(client: httpx.AsyncClient, viewer_headers: dict[str, str]) -> None:
    empty = (await client.get("/api/v1/dashboard/timeline", headers=viewer_headers)).json()
    assert empty["bucket_minutes"] == 60
    assert len(empty["buckets"]) == 24
    assert all(b["events"] == b["alerts"] == b["ai_alerts"] == 0 for b in empty["buckets"])

    await _seed()
    dashboard.clear_cache()
    body = (await client.get("/api/v1/dashboard/timeline", headers=viewer_headers)).json()
    buckets = body["buckets"]
    assert sum(b["events"] for b in buckets) == 3
    assert sum(b["alerts"] for b in buckets) == 4
    assert sum(b["ai_alerts"] for b in buckets) == 1  # category ai_agent / ai_score >= 0.7
    starts = [datetime.fromisoformat(b["ts"]) for b in buckets]
    assert all(s.timestamp() % 3600 == 0 for s in starts)


@pytest.mark.parametrize(
    ("hours", "minutes", "count"), [(1, 5, 12), (6, 10, 36), (24, 60, 24), (72, 120, 36), (168, 360, 28)]
)
async def test_timeline_auto_bucket(
    client: httpx.AsyncClient, viewer_headers: dict[str, str], hours: int, minutes: int, count: int
) -> None:
    body = (
        await client.get("/api/v1/dashboard/timeline", params={"hours": hours}, headers=viewer_headers)
    ).json()
    assert body["bucket_minutes"] == minutes
    assert len(body["buckets"]) == count


async def test_timeline_validation(client: httpx.AsyncClient, viewer_headers: dict[str, str]) -> None:
    explicit = await client.get(
        "/api/v1/dashboard/timeline", params={"hours": 2, "bucket_minutes": 30}, headers=viewer_headers
    )
    assert len(explicit.json()["buckets"]) == 4
    for bad in ({"hours": 0}, {"hours": 169}, {"bucket_minutes": 1}, {"hours": 168, "bucket_minutes": 5}):
        r = await client.get("/api/v1/dashboard/timeline", params=bad, headers=viewer_headers)
        assert r.status_code == 422, bad


async def test_requires_login(client: httpx.AsyncClient) -> None:
    for path in ("/api/v1/dashboard/summary", "/api/v1/dashboard/timeline"):
        assert (await client.get(path)).status_code == 401


async def test_malformed_incident_does_not_break_summary(
    client: httpx.AsyncClient, viewer_headers: dict[str, str]
) -> None:
    now = utcnow()
    async with session_scope() as s:
        s.add(_incident("open", now, "good"))
        s.add(_incident("not-a-status", now - timedelta(minutes=1), "bad"))
    r = await client.get("/api/v1/dashboard/summary", headers=viewer_headers)
    assert r.status_code == 200, r.text
    assert [i["title"] for i in r.json()["recent_incidents"]] == ["good"]
