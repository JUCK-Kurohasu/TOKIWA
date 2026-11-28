"""Audit #25: one event with a value the database rejects must not fail the whole ingest batch.

On PostgreSQL a VARCHAR overflow (17-char method, 256-char Host), a NUL byte (text and jsonb reject U+0000) or a
lone surrogate made ``INSERT`` raise, the batch answered 500, and the sensor re-sent the same batch forever
(head-of-line blocking): one crafted request blinded the sensor. SQLite accepts all of these, so the tests check
the stored values, not only the status code. Run against PostgreSQL with ``TOKIWA_TEST_DATABASE_URL``.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from tokiwa.db.models.detection import AlertRow
from tokiwa.db.models.telemetry import EventRow
from tokiwa.db.session import session_scope
from tokiwa.util import new_id


def _http_event(**http: Any) -> dict[str, Any]:
    base = {"method": "GET", "host": "shop.example", "path": "/", "status": 200, "user_agent": "Mozilla/5.0"}
    base.update(http)
    return {
        "id": new_id(),
        "kind": "http",
        "dataset": "nginx.access",
        "source": {"ip": "198.51.100.25"},
        "http": base,
    }


async def _post(
    client: httpx.AsyncClient, headers: dict[str, str], events: list[dict[str, Any]]
) -> httpx.Response:
    # ensure_ascii escapes a lone surrogate as "\\ud800", which the server's JSON parser turns back into one.
    body = json.dumps({"events": events}, ensure_ascii=True)
    return await client.post(
        "/api/v1/ingest/events", content=body, headers={**headers, "Content-Type": "application/json"}
    )


async def _rows() -> list[EventRow]:
    async with session_scope() as s:
        return list((await s.execute(select(EventRow))).scalars())


@pytest.mark.parametrize(
    "poison",
    [
        {"method": "PROPFINDXXXXXXXXXXXXX"},
        {"host": "h" * 300 + ".example"},
        {"user_agent": "curl\x00evil"},
        {"path": "/a\x00b", "user_agent": "x\ud800y"},
    ],
    ids=["long-method", "long-host", "nul-ua", "nul-path-surrogate"],
)
async def test_poison_value_does_not_fail_batch(
    client: httpx.AsyncClient, ingest_headers: dict[str, str], poison: dict[str, str]
) -> None:
    good = _http_event()
    bad = _http_event(**poison)
    r = await _post(client, ingest_headers, [good, bad])
    assert r.status_code == 200, r.text
    rows = {row.id: row for row in await _rows()}
    assert good["id"] in rows and bad["id"] in rows  # both stored, the good one is not collateral damage
    stored = rows[bad["id"]]
    assert stored.http_method is None or len(stored.http_method) <= 16
    assert stored.http_host is None or len(stored.http_host) <= 255
    for value in (stored.user_agent, stored.http_path, str(stored.data)):
        assert value is None or ("\x00" not in value and "\ud800" not in value)


async def test_actor_session_with_poison_ua_is_persisted(
    client: httpx.AsyncClient, ingest_headers: dict[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    """The sessionizer copies the UA into actor_sessions; on PostgreSQL that upsert used to fail and retry forever."""
    from tokiwa.db.models.telemetry import ActorSessionRow
    from tokiwa.enrich.sessionizer import flush_current

    r = await _post(client, ingest_headers, [_http_event(user_agent="curl\x00evil\ud800")])
    assert r.status_code == 200, r.text
    await flush_current()
    async with session_scope() as s:
        sessions = list((await s.execute(select(ActorSessionRow))).scalars())
    assert sessions
    assert all("\x00" not in (x.user_agent or "") and "\ud800" not in (x.user_agent or "") for x in sessions)
    assert "failed to persist" not in caplog.text


async def test_attack_strings_with_nul_reach_alert_rows(
    client: httpx.AsyncClient, ingest_headers: dict[str, str]
) -> None:
    """Detectors copy attacker strings into alert entities / details; those rows must be clean too."""
    bad = _http_event(path="/search?q=1' OR 1=1--\x00", user_agent="sqlmap/1.8\x00")
    r = await _post(client, ingest_headers, [bad])
    assert r.status_code == 200, r.text
    async with session_scope() as s:
        alerts = list((await s.execute(select(AlertRow))).scalars())
    assert alerts  # the SQLi / scanner detectors fired
    for a in alerts:
        assert "\x00" not in str(a.entities) and "\x00" not in str(a.details) and "\x00" not in a.title


async def test_duplicate_event_ids_do_not_fail_batch(
    client: httpx.AsyncClient, ingest_headers: dict[str, str]
) -> None:
    """A sensor retrying a batch the server already committed (timeout on the response) re-sends the same ids."""
    first = _http_event()
    r1 = await _post(client, ingest_headers, [first])
    assert r1.status_code == 200
    again = _http_event()
    r2 = await _post(client, ingest_headers, [first, again, dict(again)])
    assert r2.status_code == 200, r2.text
    ids = [row.id for row in await _rows()]
    assert sorted(ids) == sorted({first["id"], again["id"]})


async def test_overlong_event_id_does_not_fail_batch(
    client: httpx.AsyncClient, ingest_headers: dict[str, str]
) -> None:
    bad = _http_event()
    bad["id"] = "x" * 200
    good = _http_event()
    r = await _post(client, ingest_headers, [bad, good])
    assert r.status_code == 200, r.text
    rows = await _rows()
    assert len(rows) == 2
    assert all(len(row.id) <= 64 for row in rows)


@pytest.mark.usefixtures("db")
async def test_store_events_isolates_a_rejected_row(make_http_event) -> None:  # type: ignore[no-untyped-def]
    """The per-row fallback: an id inserted concurrently (here: already present) skips only that row."""
    from tokiwa.pipeline.store import store_events

    first, second, third = make_http_event(), make_http_event(), make_http_event()
    async with session_scope() as s:
        assert await store_events(s, [first]) == []
    async with session_scope() as s:
        assert await store_events(s, [second, first, third]) == [first.id]
    assert sorted(r.id for r in await _rows()) == sorted([first.id, second.id, third.id])


def test_clean_json_keeps_clean_objects_and_cleans_keys() -> None:
    from tokiwa.db.sanitize import clean_json, clean_text

    clean = {"a": ["b", {"c": 1}]}
    assert clean_json(clean) is clean
    dirty = {"ok": 1, "k\x00ey": ["v\x00", "w\udfff"], "n": None}
    assert clean_json(dirty) == {"ok": 1, "key": ["v", "w�"], "n": None}
    assert clean_text("plain") == "plain"
