"""Read-access log (audit #167, finding L17-03): who viewed events / sessions / LLM call details."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

import httpx
from sqlalchemy import func, select

from tokiwa.access_log import AccessLogger, clean_filters
from tokiwa.db.models.access import AccessLogRow
from tokiwa.db.models.llm import LLMCallRow
from tokiwa.db.session import session_scope
from tokiwa.pipeline.store import store_events
from tokiwa.schemas.events import Event
from tokiwa.schemas.system import Role, User
from tokiwa.util import new_id, utcnow

ACCESS = "/api/v1/audit/access"


async def _access(client: httpx.AsyncClient, admin: dict[str, str], **params: Any) -> list[dict[str, Any]]:
    r = await client.get(ACCESS, params={"limit": 500, **params}, headers=admin)
    assert r.status_code == 200, r.text
    items: list[dict[str, Any]] = r.json()["items"]
    return items


async def test_reads_are_logged_and_polling_is_merged(
    client: httpx.AsyncClient,
    role_headers: dict[str, dict[str, str]],
    make_http_event: Callable[..., Event],
) -> None:
    admin, viewer = role_headers["admin"], role_headers["viewer"]
    ev = make_http_event("/login", ip="198.51.100.5", session_id="s-1")
    async with session_scope() as s:
        await store_events(s, [ev])

    for _ in range(5):  # a list page polling with the same filter
        assert (
            await client.get("/api/v1/events", params={"source_ip": "198.51.100.5"}, headers=viewer)
        ).status_code == 200
    await client.get("/api/v1/events", params={"q": "login"}, headers=viewer)
    await client.get(f"/api/v1/events/{ev.id}", headers=viewer)
    await client.get("/api/v1/sessions", headers=viewer)

    rows = await _access(client, admin, route="events.*")
    by_filter = {(r["route"], tuple(sorted(r["filters"].items())), r["target"]): r for r in rows}
    poll = by_filter[("events.list", (("source_ip", "198.51.100.5"),), None)]
    assert poll["hits"] == 5 and poll["items"] == 5 and poll["role"] == "viewer"
    assert poll["actor"].startswith("viewer-")
    assert by_filter[("events.list", (("q", "login"),), None)]["hits"] == 1
    assert by_filter[("events.get", (), ev.id)]["items"] == 1
    assert len(rows) == 3  # 7 event reads -> 3 rows
    sessions = await _access(client, admin, route="sessions.list")
    assert len(sessions) == 1 and sessions[0]["filters"] == {}

    # only admins can read the access log; filters work
    assert (await client.get(ACCESS, headers=viewer)).status_code == 403
    assert await _access(client, admin, actor="nobody") == []
    assert len(await _access(client, admin, target=ev.id)) == 1


async def test_llm_call_detail_read_is_logged(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    call_id = new_id()
    async with session_scope() as s:
        s.add(
            LLMCallRow(
                id=call_id, created_at=utcnow(), provider="mock", model="m", tier="fast", purpose="triage",
                prompt_version="v1", status="ok", input_tokens=1, output_tokens=1, cache_read_tokens=0,
                cache_write_tokens=0, web_search_requests=0, cost_usd=0.0, latency_ms=1.0, related={},
            )
        )  # fmt: skip
    assert (await client.get(f"/api/v1/llm/calls/{call_id}", headers=admin_headers)).status_code == 200
    rows = await _access(client, admin_headers, route="llm.calls.get")
    assert [r["target"] for r in rows] == [call_id]


async def test_window_rollover_writes_back_counts(db: None) -> None:
    user = User(id=new_id(), username="u1", role=Role.VIEWER, created_at=utcnow())
    log = AccessLogger(window=timedelta(minutes=5))
    t0 = utcnow()
    async with session_scope() as s:
        for i in range(3):
            await log.record(
                s,
                user,
                "events.list",
                filters={"dataset": "gate.http"},
                count=10,
                now=t0 + timedelta(seconds=i),
            )
        # window over: counters of the first row are written back, a second row starts
        await log.record(
            s, user, "events.list", filters={"dataset": "gate.http"}, count=4, now=t0 + timedelta(minutes=6)
        )
    async with session_scope() as s:
        rows = list((await s.execute(select(AccessLogRow).order_by(AccessLogRow.created_at))).scalars())
    assert [(r.hits, r.items) for r in rows] == [(3, 30), (1, 4)]
    async with session_scope() as s:
        await log.flush(s, now=t0 + timedelta(minutes=20))
        assert log._open == {}  # ended windows are forgotten
        assert (await s.execute(select(func.count()).select_from(AccessLogRow))).scalar_one() == 2


async def test_open_windows_are_bounded(db: None) -> None:
    log = AccessLogger(max_open=3)
    now = utcnow()
    async with session_scope() as s:
        for i in range(6):
            user = User(id=new_id(), username=f"u{i}", role=Role.ANALYST, created_at=utcnow())
            await log.record(s, user, "events.get", target=f"e{i}", count=1, now=now)
    assert len(log._open) == 3


def test_clean_filters() -> None:
    out = clean_filters({"a": None, "b": "", "c": [], "q": "x" * 500, "n": 3, "obj": {"k": [1, 2]}})
    assert set(out) == {"q", "n", "obj"}
    assert len(out["q"]) == 200 and out["n"] == 3 and out["obj"] == '{"k": [1, 2]}'
