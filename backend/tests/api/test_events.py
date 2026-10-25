"""Event search, single event, timeline and the shared pagination helper."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from tokiwa.api.pagination import PageQuery, paginate
from tokiwa.api.routes.events import BucketRange
from tokiwa.db.models.core import AuditRow
from tokiwa.db.session import session_scope
from tokiwa.pipeline.store import store_events
from tokiwa.schemas.events import Endpoint, Event, EventKind, HostInfo
from tokiwa.util import new_id, utcnow


async def _store(*events: Event) -> None:
    async with session_scope() as s:
        await store_events(s, list(events))


@pytest.fixture
async def seeded(client: httpx.AsyncClient, make_http_event: Callable[..., Event]) -> dict[str, Event]:
    now = utcnow()
    evs = {
        "login": make_http_event("/login", ip="198.51.100.1", ts=now - timedelta(minutes=1), session_id="s1"),
        "admin": make_http_event(
            "/wp-admin/setup.php", ip="198.51.100.2", ua="python-requests/2.32", ts=now - timedelta(minutes=2)
        ),
        "pct": make_http_event("/a%b_c", ip="198.51.100.2", ts=now - timedelta(minutes=3)),
        "old": make_http_event("/old", ip="198.51.100.3", ts=now - timedelta(hours=30)),
        "port": Event(
            kind=EventKind.PORT_CHANGE,
            dataset="host.ports",
            timestamp=now - timedelta(minutes=4),
            host=HostInfo(name="web-1"),
            source=Endpoint(ip="10.0.0.5"),
        ),
    }
    await _store(*evs.values())
    return evs


def _ids(r: httpx.Response) -> list[str]:
    assert r.status_code == 200, r.text
    return [e["id"] for e in r.json()["items"]]


async def test_list_newest_first_and_page(
    client: httpx.AsyncClient, viewer_headers: dict[str, str], seeded: dict[str, Event]
) -> None:
    r = await client.get("/api/v1/events", headers=viewer_headers)
    body = r.json()
    assert body["total"] == 5 and body["limit"] == 50 and body["offset"] == 0
    order = ["login", "admin", "pct", "port", "old"]
    assert _ids(r) == [seeded[k].id for k in order]
    # The full Event document round-trips.
    first = body["items"][0]
    assert first["http"]["path"] == "/login" and first["session_id"] == "s1"

    page = await client.get("/api/v1/events", params={"limit": 2, "offset": 2}, headers=viewer_headers)
    assert page.json()["total"] == 5
    assert _ids(page) == [seeded["pct"].id, seeded["port"].id]
    beyond = await client.get("/api/v1/events", params={"offset": 99}, headers=viewer_headers)
    assert beyond.json() == {"items": [], "total": 5, "limit": 50, "offset": 99}

    for bad in ({"limit": 0}, {"limit": 501}, {"offset": -1}):
        assert (await client.get("/api/v1/events", params=bad, headers=viewer_headers)).status_code == 422
    ok = await client.get("/api/v1/events", params={"limit": 500}, headers=viewer_headers)
    assert ok.json()["limit"] == 500


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"kind": "port_change"}, ["port"]),
        ({"dataset": "gate.http"}, ["login", "admin", "pct", "old"]),
        ({"source_ip": "198.51.100.2"}, ["admin", "pct"]),
        ({"session_id": "s1"}, ["login"]),
        ({"host": "web-1"}, ["port"]),
        ({"q": "WP-ADMIN"}, ["admin"]),  # path, case-insensitive
        ({"q": "python-requests"}, ["admin"]),  # user agent
        ({"q": "%"}, ["pct"]),  # LIKE wildcards are matched literally
        ({"source_ip": "198.51.100.2", "q": "setup"}, ["admin"]),
    ],
)
async def test_filters(
    client: httpx.AsyncClient,
    viewer_headers: dict[str, str],
    seeded: dict[str, Event],
    params: dict[str, str],
    expected: list[str],
) -> None:
    r = await client.get("/api/v1/events", params=params, headers=viewer_headers)
    assert _ids(r) == [seeded[k].id for k in expected]
    assert r.json()["total"] == len(expected)


async def test_time_filters(
    client: httpx.AsyncClient, viewer_headers: dict[str, str], seeded: dict[str, Event]
) -> None:
    now = utcnow()
    since = (now - timedelta(hours=1)).isoformat()
    until = (now - timedelta(seconds=150)).isoformat()
    r = await client.get("/api/v1/events", params={"since": since}, headers=viewer_headers)
    assert seeded["old"].id not in _ids(r) and r.json()["total"] == 4
    r = await client.get("/api/v1/events", params={"since": since, "until": until}, headers=viewer_headers)
    assert _ids(r) == [seeded["pct"].id, seeded["port"].id]
    # Naive datetimes are interpreted as UTC.
    naive = (now - timedelta(hours=1)).astimezone(UTC).replace(tzinfo=None).isoformat()
    r = await client.get("/api/v1/events", params={"since": naive}, headers=viewer_headers)
    assert r.json()["total"] == 4
    bad = await client.get("/api/v1/events", params={"kind": "nope"}, headers=viewer_headers)
    assert bad.status_code == 422


async def test_get_event(
    client: httpx.AsyncClient, viewer_headers: dict[str, str], seeded: dict[str, Event]
) -> None:
    ev = seeded["admin"]
    r = await client.get(f"/api/v1/events/{ev.id}", headers=viewer_headers)
    assert r.status_code == 200
    assert r.json()["http"]["user_agent"] == "python-requests/2.32"
    assert (await client.get("/api/v1/events/missing", headers=viewer_headers)).status_code == 404


async def test_requires_login(client: httpx.AsyncClient, admin_headers: dict[str, str]) -> None:
    for path in ("/api/v1/events", "/api/v1/events/x", "/api/v1/events/stats/timeline"):
        assert (await client.get(path)).status_code == 401
        assert (await client.get(path, headers={"Authorization": "Bearer junk"})).status_code == 401


async def test_timeline(
    client: httpx.AsyncClient, analyst_headers: dict[str, str], seeded: dict[str, Event]
) -> None:
    r = await client.get("/api/v1/events/stats/timeline", headers=analyst_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["bucket_minutes"] == 60
    buckets = body["buckets"]
    assert len(buckets) == 24
    starts = [datetime.fromisoformat(b["ts"]) for b in buckets]
    assert all(s.timestamp() % 3600 == 0 for s in starts)
    assert starts == sorted(starts)
    assert sum(b["total"] for b in buckets) == 4  # "old" (30h ago) is outside the window
    kinds: dict[str, int] = {}
    for b in buckets:
        assert b["total"] == sum(b["by_kind"].values())
        for k, n in b["by_kind"].items():
            kinds[k] = kinds.get(k, 0) + n
    assert kinds == {"http": 3, "port_change": 1}

    wide = await client.get(
        "/api/v1/events/stats/timeline", params={"hours": 72, "bucket_minutes": 1440}, headers=analyst_headers
    )
    assert len(wide.json()["buckets"]) == 3  # always covers >= 48h back, so "old" is included
    assert sum(b["total"] for b in wide.json()["buckets"]) == 5

    for bad in ({"hours": 169}, {"hours": 0}, {"bucket_minutes": 0}, {"hours": 168, "bucket_minutes": 1}):
        r = await client.get("/api/v1/events/stats/timeline", params=bad, headers=analyst_headers)
        assert r.status_code == 422, bad


async def test_timeline_empty(client: httpx.AsyncClient, viewer_headers: dict[str, str]) -> None:
    r = await client.get(
        "/api/v1/events/stats/timeline", params={"hours": 1, "bucket_minutes": 15}, headers=viewer_headers
    )
    buckets = r.json()["buckets"]
    assert len(buckets) == 4
    assert all(b["total"] == 0 and b["by_kind"] == {} for b in buckets)


def test_bucket_range() -> None:
    now = datetime(2026, 10, 22, 12, 34, 56, tzinfo=UTC)
    rng = BucketRange.build(24, 60, now=now)
    assert rng.count == 24
    assert rng.start == datetime(2026, 10, 21, 13, 0, tzinfo=UTC)
    assert rng.end == datetime(2026, 10, 22, 13, 0, tzinfo=UTC)
    assert rng.index(now) == 23
    assert rng.index(rng.start) == 0
    assert rng.index(rng.start - timedelta(microseconds=1)) is None
    assert rng.index(rng.end) is None
    assert rng.index(None) is None
    # naive timestamps (SQLite) are treated as UTC
    assert rng.index(datetime(2026, 10, 22, 12, 0)) == 23


@pytest.mark.usefixtures("db")
async def test_paginate_helper() -> None:
    async with session_scope() as s:
        for i in range(7):
            s.add(AuditRow(id=new_id(), actor="t", action=f"a{i}", details={}))
    stmt = select(AuditRow).order_by(AuditRow.action)
    async with session_scope() as s:
        page = await paginate(s, stmt, PageQuery(limit=3, offset=5), lambda r: r.action)
        assert page.total == 7 and page.items == ["a5", "a6"]
        assert (page.limit, page.offset) == (3, 5)
        empty = await paginate(s, stmt, PageQuery(offset=10), lambda r: r.action)
        assert empty.total == 7 and empty.items == []
        rows = await paginate(
            s,
            select(AuditRow.action, AuditRow.actor).order_by(AuditRow.action),
            PageQuery(limit=2),
            tuple,
            scalars=False,
        )
        assert rows.items == [("a0", "t"), ("a1", "t")]
        filtered = await paginate(s, stmt.where(AuditRow.action == "a3"), PageQuery(), lambda r: r.action)
        assert filtered.total == 1 and filtered.items == ["a3"]
