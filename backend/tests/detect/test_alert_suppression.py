"""False-positive feedback (audit #166) and allowlists for authorised testing (audit #173).

#166: marking an alert false_positive suppressed nothing - the next identical request raised a new alert and a new
triage LLM call. #173: an authorised scan / load test produced incidents and block proposals with no way to
declare it. Both go through ``alert_suppressions`` (tokiwa.detect.suppress), consulted in DetectionEngine.persist.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from tokiwa.bus import bus
from tokiwa.config import Settings
from tokiwa.db.models.alert_suppression import AlertSuppressionRow
from tokiwa.db.models.detection import AlertRow
from tokiwa.db.session import session_scope
from tokiwa.detect import suppress
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event
from tokiwa.util import utcnow

SQLI_QUERY = "id=1%20UNION%20SELECT%20null,version()--"
MakeEvent = Callable[..., Event]


async def _ingest(client: httpx.AsyncClient, headers: dict[str, str], *events: Event) -> None:
    r = await client.post(
        "/api/v1/ingest/events", json={"events": [e.model_dump(mode="json") for e in events]}, headers=headers
    )
    assert r.status_code == 200, r.text


async def _alerts(rule_id: str) -> list[AlertRow]:
    async with session_scope() as s:
        rows = (await s.execute(select(AlertRow).where(AlertRow.rule_id == rule_id))).scalars().all()
        return sorted(rows, key=lambda r: r.created_at)


@pytest.fixture(autouse=True)
def _no_auto_triage(settings: Settings) -> None:
    """Background triage of the first alert races the PATCH below (it can write ``triaging`` over
    ``false_positive``); these tests are about the engine, and ``published`` shows what triage would get."""
    settings.triage.auto_triage = False


@pytest.fixture
def published(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, Any]]:
    """Every bus event (alert.created is what triage, notification and correlation react to)."""
    seen: list[tuple[str, Any]] = []
    original = bus.publish

    async def spy(topic: str, payload: Any) -> None:
        seen.append((topic, payload))
        await original(topic, payload)

    monkeypatch.setattr(bus, "publish", spy)
    return seen


def _created(published: list[tuple[str, Any]], rule_id: str) -> int:
    return sum(1 for topic, a in published if topic == "alert.created" and a.rule_id == rule_id)


async def test_false_positive_absorbs_the_same_finding(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    ingest_headers: dict[str, str],
    make_http_event: MakeEvent,
    published: list[tuple[str, Any]],
) -> None:
    await _ingest(client, ingest_headers, make_http_event("/items", query=SQLI_QUERY))
    [alert] = await _alerts("web.sqli")
    r = await client.patch(
        f"/api/v1/alerts/{alert.id}",
        json={"status": "false_positive", "reason": "internal docs search"},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    listed = (
        await client.get(
            "/api/v1/alert-suppressions", params={"source_alert_id": alert.id}, headers=admin_headers
        )
    ).json()["items"]
    assert len(listed) == 1
    supp = listed[0]
    assert supp["kind"] == "false_positive" and supp["active"] is True
    assert supp["rule_id"] == "web.sqli" and supp["path_key"] == "/items"
    assert supp["source_cidr"] == "203.0.113.10/32"
    assert supp["match"]["location"] == "query" and supp["match"]["param"] == "id"
    assert supp["expires_at"] is not None  # detection.fp_suppress_hours (168 h)

    published.clear()
    await _ingest(client, ingest_headers, make_http_event("/items", query=SQLI_QUERY))
    rows = await _alerts("web.sqli")
    assert len(rows) == 1 and rows[0].count == 2  # counted on the marked alert, no new alert
    assert _created(published, "web.sqli") == 0  # -> no triage, notification or incident

    # another source, or new evidence (an extra signature) is not covered by the narrow default scope
    await _ingest(client, ingest_headers, make_http_event("/items", query=SQLI_QUERY, ip="198.51.100.7"))
    stacked = SQLI_QUERY + ";DROP%20TABLE%20users"
    await _ingest(client, ingest_headers, make_http_event("/items", query=stacked))
    rows = await _alerts("web.sqli")
    assert len(rows) == 3, [(r.source_ip, r.count, r.status, r.details.get("signatures")) for r in rows]
    assert _created(published, "web.sqli") == 2

    # un-marking lifts the suppression
    r = await client.patch(
        f"/api/v1/alerts/{alert.id}", json={"status": "acknowledged"}, headers=admin_headers
    )
    assert r.status_code == 200
    active = (await client.get("/api/v1/alert-suppressions", headers=admin_headers)).json()["items"]
    assert active == []


async def test_false_positive_options(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    ingest_headers: dict[str, str],
    make_http_event: MakeEvent,
) -> None:
    await _ingest(client, ingest_headers, make_http_event("/a", query=SQLI_QUERY))
    [a] = await _alerts("web.sqli")
    r = await client.patch(
        f"/api/v1/alerts/{a.id}", json={"status": "false_positive", "suppress": False}, headers=admin_headers
    )
    assert r.status_code == 200
    assert (await client.get("/api/v1/alert-suppressions", headers=admin_headers)).json()["total"] == 0

    await _ingest(client, ingest_headers, make_http_event("/b", query=SQLI_QUERY))
    b = next(x for x in await _alerts("web.sqli") if x.id != a.id)
    r = await client.patch(
        f"/api/v1/alerts/{b.id}",
        json={"status": "false_positive", "suppress_any_source": True, "suppress_permanent": True},
        headers=admin_headers,
    )
    assert r.status_code == 200
    [supp] = (await client.get("/api/v1/alert-suppressions", headers=admin_headers)).json()["items"]
    assert supp["source_cidr"] is None and supp["expires_at"] is None
    await _ingest(client, ingest_headers, make_http_event("/b", query=SQLI_QUERY, ip="192.0.2.99"))
    assert len(await _alerts("web.sqli")) == 2  # widened scope: other sources are absorbed too


async def test_allowlist_records_quietly(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    ingest_headers: dict[str, str],
    make_http_event: MakeEvent,
    published: list[tuple[str, Any]],
) -> None:
    r = await client.post(
        "/api/v1/alert-suppressions",
        json={"source_cidr": "10.20.0.0/24", "hours": 4, "reason": "authorised scan SEC-1"},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["kind"] == "allowlist" and r.json()["mode"] == "downgrade"
    scanner_ua = "sqlmap/1.8 (https://sqlmap.org)"
    events = [
        make_http_event(
            "/items", query=SQLI_QUERY, ip="10.20.0.70", ua=scanner_ua, headers={"user-agent": scanner_ua}
        ),
        make_http_event("/.env", ip="10.20.0.70"),
    ]
    published.clear()
    await _ingest(client, ingest_headers, *events)
    async with session_scope() as s:
        rows = (await s.execute(select(AlertRow).where(AlertRow.source_ip == "10.20.0.70"))).scalars().all()
    assert rows, "allowlisted requests are still recorded"
    assert {r.severity for r in rows} == {"info"}
    assert {r.status for r in rows} == {"acknowledged"}
    assert all(suppress.ALLOWLISTED_TAG in r.tags for r in rows)
    assert all(r.details["suppression"]["kind"] == "allowlist" for r in rows)
    assert not [t for t, _ in published if t in ("alert.created", "alert.updated")]

    # a source outside the CIDR is unaffected
    await _ingest(client, ingest_headers, make_http_event("/items", query=SQLI_QUERY, ip="10.20.1.5"))
    assert [a.severity for a in await _alerts("web.sqli") if a.source_ip == "10.20.1.5"] == ["high"]


async def test_allowlist_validation_and_lift(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    async def post(body: dict[str, Any], headers: dict[str, str] = admin_headers) -> httpx.Response:
        return await client.post("/api/v1/alert-suppressions", json=body, headers=headers)

    assert (await post({"hours": 1})).status_code == 422  # no CIDR
    assert (await post({"source_cidr": "0.0.0.0/0", "hours": 1})).status_code == 422  # too wide
    assert (await post({"source_cidr": "10.0.0.0/8"})).status_code == 422  # no expiry
    assert (await post({"source_cidr": "10.0.0.0/8", "hours": 10_000})).status_code == 422  # > max
    assert (await post({"kind": "false_positive", "hours": 1})).status_code == 422  # no rule_id

    r = await client.post(
        "/api/v1/users",
        json={"username": "ana", "password": "correct-horse-battery", "role": "analyst"},
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text
    login = await client.post(
        "/api/v1/auth/login", json={"username": "ana", "password": "correct-horse-battery"}
    )
    analyst = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert (await post({"source_cidr": "10.0.0.0/24", "hours": 1}, analyst)).status_code == 403

    ok = await post(
        {"source_cidr": "2001:db8::/48", "hours": 1, "rule_id": "web.request_flood", "path": "/API/x/"}
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["path_key"] == "/api/x"
    sid = ok.json()["id"]
    assert (await client.post(f"/api/v1/alert-suppressions/{sid}/lift", headers=analyst)).status_code == 200
    assert (await client.post(f"/api/v1/alert-suppressions/{sid}/lift", headers=analyst)).status_code == 409
    assert (await client.post("/api/v1/alert-suppressions/nope/lift", headers=analyst)).status_code == 404
    everything = (
        await client.get("/api/v1/alert-suppressions", params={"active": "false"}, headers=analyst)
    ).json()
    assert everything["total"] == 1 and everything["items"][0]["active"] is False


async def test_expired_rows_are_ignored(
    client: httpx.AsyncClient, ingest_headers: dict[str, str], make_http_event: MakeEvent
) -> None:
    now = utcnow()
    async with session_scope() as s:
        s.add(
            AlertSuppressionRow(
                kind="allowlist",
                mode="suppress",
                source_cidr="203.0.113.0/24",
                match={},
                expires_at=now - timedelta(minutes=1),
                created_at=now - timedelta(hours=2),
                updated_at=now - timedelta(hours=2),
            )
        )
    await _ingest(client, ingest_headers, make_http_event("/items", query=SQLI_QUERY))
    assert [a.severity for a in await _alerts("web.sqli")] == ["high"]


def _draft(**kw: Any) -> AlertDraft:
    base: dict[str, Any] = {
        "rule_id": "web.sqli",
        "title": "t",
        "severity": Severity.HIGH,
        "category": AlertCategory.EXPLOIT_ATTEMPT,
        "source_ip": "203.0.113.10",
        "entities": {"path": "/items/42"},
        "details": {"signatures": ["sqli.union_select"], "location": "query", "param": "id"},
    }
    base.update(kw)
    return AlertDraft(**base)


def test_matching_rules() -> None:
    row = AlertSuppressionRow(
        kind="false_positive",
        mode="suppress",
        rule_id="web.sqli",
        path_key="/items/{n}",
        source_cidr="203.0.113.10/32",
        match={
            "signatures": ["sqli.comment_terminated", "sqli.union_select"],
            "location": "query",
            "param": "id",
        },
        max_severity="high",
    )
    assert suppress.row_matches(row, _draft())
    assert not suppress.row_matches(row, _draft(severity=Severity.CRITICAL))  # escalation
    assert not suppress.row_matches(row, _draft(source_ip="203.0.113.11"))
    assert not suppress.row_matches(row, _draft(entities={"path": "/orders/1"}))
    assert not suppress.row_matches(row, _draft(rule_id="web.xss"))
    new_sig = {"signatures": ["sqli.union_select", "sqli.stacked_query"], "location": "query", "param": "id"}
    assert not suppress.row_matches(row, _draft(details=new_sig))
    other_param = {"signatures": ["sqli.union_select"], "location": "query", "param": "q"}
    assert not suppress.row_matches(row, _draft(details=other_param))
    sigma = AlertSuppressionRow(kind="false_positive", rule_id="sigma:x", match={"selections": ["a", "b"]})
    assert suppress.row_matches(sigma, _draft(rule_id="sigma:x", details={"matched": ["a"]}))
    assert not suppress.row_matches(sigma, _draft(rule_id="sigma:x", details={"matched": ["c"]}))
