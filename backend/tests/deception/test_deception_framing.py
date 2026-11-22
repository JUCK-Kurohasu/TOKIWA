"""Audit #133 (L03-10): a canary trip that a third party can induce must not frame its source.

Before: one ``<img src="https://<site>/api/internal/<canary>/">`` on a forum made every viewer's IP a critical
``ai_agent`` incident with a ``block_ip`` proposal (executed at once with auto-approve).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from tokiwa.aidetect.sessions import SessionTracker
from tokiwa.bus import bus
from tokiwa.config import DeceptionSettings, RedactionSettings, reset_settings_cache
from tokiwa.correlate.scoring import AlertFacts, boosted_severity, infer_actor_type
from tokiwa.deception.matcher import DeceptionIndex, TripType, match_event
from tokiwa.deception.policy import build_gate_decoys
from tokiwa.deception.provenance import Provenance, decisive_canary_hit, induced_by
from tokiwa.detect.detectors.deception_trip import DeceptionTripDetector
from tokiwa.gate.capture import EventBuilder, Exchange
from tokiwa.llm.mock import MockProvider
from tokiwa.respond.policy import build_gate_policy
from tokiwa.schemas.common import ActorType, Severity
from tokiwa.schemas.events import DeceptionInfo, Endpoint, Event, EventKind, HttpInfo
from tokiwa.schemas.response import DeceptionAsset, DeceptionKind, DecoyRoute
from tokiwa.schemas.triage import ActionType

KEY = b"unit-test-derive-key"
THRESHOLD = 0.7  # detection.ai_agent_threshold default

MakeAsset = Callable[..., DeceptionAsset]
MakeEvent = Callable[..., Event]

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
IMG_CROSS_SITE = {
    "host": "shop.example",
    "user-agent": CHROME,
    "sec-fetch-dest": "image",
    "sec-fetch-site": "cross-site",
    "sec-fetch-mode": "no-cors",
    "referer": "https://forum.example/thread/1",
}


def _index(assets: list[DeceptionAsset], **over: Any) -> DeceptionIndex:
    return DeceptionIndex.build(assets, key=KEY, settings=DeceptionSettings(**over))


# ------------------------------------------------------------------------------------------- provenance


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        (IMG_CROSS_SITE, ["sec-fetch-site=cross-site", "sec-fetch-dest=image", "referer=forum.example"]),
        # a user post with <img> on the protected site itself: same-origin, but a sub-resource
        (
            {"host": "shop.example", "sec-fetch-site": "same-origin", "sec-fetch-dest": "image"},
            ["sec-fetch-dest=image"],
        ),
        (
            {"host": "shop.example", "sec-fetch-site": "same-site", "sec-fetch-dest": "document"},
            ["sec-fetch-site=same-site"],
        ),
        ({"host": "shop.example", "sec-fetch-dest": "iframe"}, ["sec-fetch-dest=iframe"]),
        ({"host": "shop.example", "sec-purpose": "prefetch"}, ["prefetch"]),
        ({"host": "shop.example", "origin": "https://evil.example"}, ["origin=evil.example"]),
        ({"host": "shop.example", "origin": "null"}, ["origin=null"]),
        ({"host": "shop.example:8443", "referer": "https://forum.example:8443/x"}, ["referer=forum.example"]),
        # deliberate: typed URL / own page / scripts without browser headers
        ({"host": "shop.example", "sec-fetch-site": "none", "sec-fetch-dest": "document"}, []),
        ({"host": "shop.example", "sec-fetch-site": "same-origin", "sec-fetch-dest": "empty"}, []),
        ({"host": "shop.example", "referer": "https://shop.example:8443/products"}, []),
        ({"host": "shop.example", "referer": "/relative"}, []),
        ({"user-agent": "python-httpx/0.28"}, []),
        ({"Sec-Fetch-Site": "cross-site"}, ["sec-fetch-site=cross-site"]),  # header names in any case
    ],
)
def test_induced_by(make_http_event: MakeEvent, headers: dict[str, str], expected: list[str]) -> None:
    ev = make_http_event("/x", headers=headers)
    assert ev.http is not None
    ev.http.host = headers.get("host")
    assert induced_by(ev) == expected


def test_matcher_grades_provenance(make_asset: MakeAsset, make_http_event: MakeEvent) -> None:
    canary = make_asset(DeceptionKind.AI_CANARY)
    env = make_asset(DeceptionKind.DECOY_PATH, "/.env")
    honey = make_asset(DeceptionKind.HONEYTOKEN, "/creds.txt")
    index = _index([canary, env, honey])
    v = canary.token

    def one(ev: Event) -> tuple[TripType, Provenance, bool]:
        (trip,) = match_event(ev, index)
        return trip.trip_type, trip.provenance, trip.ai_followed

    ua = {"user-agent": "python-httpx/0.28", "host": "shop.example"}
    assert one(make_http_event("/api/orders", headers={**ua, "X-Debug-Auth": v})) == (
        TripType.AI_CANARY_FOLLOWED,
        Provenance.DIRECT,
        True,
    )
    assert one(make_http_event(f"/api/internal/{v}/", headers=ua)) == (
        TripType.AI_CANARY_FOLLOWED,
        Provenance.PASSIVE,
        False,
    )
    assert one(make_http_event("/search", query=f"q={v}", headers=ua)) == (
        TripType.AI_CANARY_TOKEN,
        Provenance.PASSIVE,
        False,
    )
    assert one(make_http_event("/x", headers={**ua, "x-trace": v})) == (
        TripType.AI_CANARY_TOKEN,
        Provenance.DIRECT,
        False,
    )
    # header follow from a third-party page (CORS) still carries the browser's cross-site marker
    assert one(make_http_event("/api/orders", headers={**IMG_CROSS_SITE, "x-debug-auth": v}))[1] == (
        Provenance.INDUCED
    )
    assert one(make_http_event(f"/api/internal/{v}/", headers=IMG_CROSS_SITE))[1] == Provenance.INDUCED
    # the same <img> trick works for any decoy and honeytoken: no basis for a block either
    assert one(make_http_event("/.env", headers=IMG_CROSS_SITE)) == (
        TripType.DECOY_PATH,
        Provenance.INDUCED,
        False,
    )
    assert one(make_http_event("/.env", headers=ua))[1] == Provenance.DIRECT
    assert one(make_http_event("/api", query=f"k={honey.token}", headers=IMG_CROSS_SITE))[1] == (
        Provenance.INDUCED
    )
    # opt-out restores the old grading of induced requests (the path-only rule stays)
    old = _index([canary, env], downgrade_browser_induced=False)
    (trip,) = match_event(make_http_event("/.env", headers=IMG_CROSS_SITE), old)
    assert trip.provenance == Provenance.DIRECT and trip.induced_by == []


def test_downgraded_alerts_carry_no_ai_verdict(make_asset: MakeAsset, make_http_event: MakeEvent) -> None:
    canary = make_asset(DeceptionKind.AI_CANARY)
    env = make_asset(DeceptionKind.DECOY_PATH, "/.env")
    index = _index([canary, env])
    det = DeceptionTripDetector()
    threshold = THRESHOLD
    cases = [
        (
            make_http_event(f"/api/internal/{canary.token}/", headers={"user-agent": "curl/8"}),
            Severity.MEDIUM,
        ),
        (make_http_event(f"/api/internal/{canary.token}/", headers=IMG_CROSS_SITE), Severity.LOW),
        (make_http_event("/x", query=f"ref={canary.token}", headers={"host": "a"}), Severity.MEDIUM),
        (make_http_event("/.env", headers=IMG_CROSS_SITE), Severity.LOW),
    ]
    for ev, severity in cases:
        (trip,) = match_event(ev, index)
        d = det._draft(ev, trip, threshold)
        assert d.severity == severity and str(d.category) == "deception"
        assert not any("ai_canary" in t for t in d.tags), d.tags
        assert "ai_canary" not in d.entities.values() and "ai_agent" not in d.tags
        facts = AlertFacts(d.rule_id, str(d.category), str(d.severity), d.ai_score, d.tags, d.entities)
        assert infer_actor_type([facts], ai_score=d.ai_score, ai_threshold=threshold) != ActorType.AI_AGENT
        boost = boosted_severity(d.severity, ai_score=d.ai_score, ai_threshold=threshold)
        assert boost.severity == d.severity  # no AI boost to high
        assert d.details["provenance"] in ("passive", "induced")
    # the deliberate follow keeps its decisive verdict
    (trip,) = match_event(make_http_event("/", headers={"x-debug-auth": canary.token}), index)
    d = det._draft(make_http_event("/"), trip, threshold)
    assert d.severity == Severity.CRITICAL and "ai_canary" in d.tags and d.ai_score == pytest.approx(0.99)


def _deception_event(ip: str, headers: dict[str, str], path: str) -> Event:
    return Event(
        kind=EventKind.DECEPTION,
        dataset="gate.deception",
        source=Endpoint(ip=ip),
        http=HttpInfo(method="GET", host=headers.get("host"), path=path, headers=headers),
        deception=DeceptionInfo(asset_id="c1", asset_kind="ai_canary"),
    )


def test_sessionizer_counts_only_deliberate_canary_hits(
    make_asset: MakeAsset, monkeypatch: pytest.MonkeyPatch, settings
) -> None:  # type: ignore[no-untyped-def]
    from tokiwa.deception import service

    canary = make_asset(DeceptionKind.AI_CANARY)
    v = canary.token
    assert v is not None
    monkeypatch.setattr(service, "cached_index", lambda: _index([canary]))
    tr = SessionTracker()
    img = _deception_event("198.51.100.7", IMG_CROSS_SITE, f"/api/internal/{v}/")
    page = _deception_event("198.51.100.8", {"user-agent": "crawler/1"}, "/api/internal/openapi.json")
    follow = _deception_event(
        "203.0.113.50", {"user-agent": "python-httpx/0.28", "x-debug-auth": v}, f"/api/internal/{v}/"
    )
    wrong = _deception_event("203.0.113.51", {"user-agent": "curl/8", "x-debug-auth": "dbg_nope"}, "/x")
    assert not decisive_canary_hit(img) and not decisive_canary_hit(page) and decisive_canary_hit(follow)
    assert not decisive_canary_hit(wrong)  # a value that is not a canary decides nothing
    http = [
        Event(
            kind=EventKind.HTTP,
            dataset="gate.http",
            source=Endpoint(ip=e.source_ip),
            http=e.http.model_copy() if e.http else None,
        )
        for e in (img, page, follow)
    ]
    tr.observe_batch(http)
    tr.observe_batch([img, page, follow])
    by_ip = {e.source_ip: tr.get(e.session_id or "") for e in (img, page, follow)}
    assert by_ip["198.51.100.7"].classification != ActorType.AI_AGENT  # type: ignore[union-attr]
    assert by_ip["198.51.100.8"].classification != ActorType.AI_AGENT  # type: ignore[union-attr]
    assert by_ip["203.0.113.50"].classification == ActorType.AI_AGENT  # type: ignore[union-attr]
    assert by_ip["198.51.100.7"].extras.decoy_hits == 1  # type: ignore[union-attr]


# ------------------------------------------------------------------------------- end to end (repro)


@pytest.fixture
def auto_approve_everything(settings, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    """The worst case the audit names: auto-approve on for every action type."""
    monkeypatch.setenv("TOKIWA_RESPONSE__AUTO_APPROVE_ENABLED", "true")
    monkeypatch.setenv("TOKIWA_RESPONSE__AUTO_APPROVE_ACTIONS", json.dumps([t.value for t in ActionType]))
    reset_settings_cache()


def _gate_events(ip: str, path: str, headers: dict[str, str], decoy: DecoyRoute | None) -> list[Event]:
    """Exactly what the Gate ships for one request (HTTP event + DECEPTION event when a decoy answered)."""
    ex = Exchange(
        method="GET",
        scheme="https",
        path=path,
        query="",
        raw_headers=[(k.encode(), v.encode()) for k, v in headers.items()],
        client_ip=ip,
        client_port=40000,
        server_ip="10.0.0.5",
        server_port=8080,
    )
    ex.status = 200
    if decoy is not None:
        ex.decoy = decoy
        ex.tag("gate:decoy")
    builder = EventBuilder(sensor_id="gate-1", capture_body_bytes=4096, redaction=RedactionSettings())
    return builder.build(ex)


async def test_induced_canary_trips_never_block_even_with_auto_approve(
    auto_approve_everything: None,
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    ingest_headers: dict[str, str],
    mock_llm: MockProvider,
) -> None:
    routes, html = await build_gate_decoys()
    assert html is not None
    value = next(r.path for r in routes if r.path.startswith("/api/internal/dbg_"))[
        len("/api/internal/") : -1
    ]
    landing = next(r for r in routes if r.path == f"/api/internal/{value}*")
    openapi = next(r for r in routes if r.path == "/api/internal/openapi.json")
    env = next(r for r in routes if r.path == "/.env")
    canary_path = f"/api/internal/{value}/"

    victims = {
        # L03-10 repro 1: cross-site <img> on a forum
        "198.51.100.7": _gate_events("198.51.100.7", canary_path, IMG_CROSS_SITE, landing),
        # a user post on the protected site itself
        "198.51.100.8": _gate_events(
            "198.51.100.8",
            canary_path,
            {**IMG_CROSS_SITE, "sec-fetch-site": "same-origin", "referer": "https://shop.example/posts/9"},
            landing,
        ),
        # a link posted in a chat: the preview bot sends no Sec-Fetch-* at all
        "198.51.100.9": _gate_events(
            "198.51.100.9",
            canary_path,
            {"host": "shop.example", "user-agent": "Slackbot-LinkExpanding 1.0"},
            landing,
        ),
        # a link-following crawler fetching the canary page the hidden HTML links to
        "198.51.100.10": _gate_events(
            "198.51.100.10",
            "/api/internal/openapi.json",
            {"host": "shop.example", "user-agent": "crawler/2"},
            openapi,
        ),
    }
    # the same trick with the best-known decoy: the deception trip is low. (web.sensitive_file_probe still raises
    # its own high alert for /.env - another detector's framing residual, see the lane NOTES.)
    env_ip = "198.51.100.11"
    env_events = _gate_events(env_ip, "/.env", IMG_CROSS_SITE, env)
    # positive control: an agent that sends the canary header itself is still decisive
    agent_ip = "203.0.113.50"
    agent = _gate_events(
        agent_ip,
        canary_path,
        {"host": "shop.example", "user-agent": "python-httpx/0.28.1", "x-debug-auth": value},
        landing,
    )
    events = [e for evs in victims.values() for e in evs] + env_events + agent
    r = await client.post(
        "/api/v1/ingest/events",
        json={"events": [e.model_dump(mode="json") for e in events]},
        headers=ingest_headers,
    )
    assert r.status_code == 200, r.text
    for _ in range(3):  # alert -> incident -> triage -> proposal -> auto-approve
        await bus.drain()

    alerts = (await client.get("/api/v1/alerts?limit=200", headers=admin_headers)).json()["items"]
    for a in alerts:
        if a["source_ip"] in victims:
            assert Severity(a["severity"]).rank < Severity.HIGH.rank, (
                a["rule_id"],
                a["title"],
                a["source_ip"],
            )
    trip_alerts = {a["source_ip"]: a for a in alerts if a["rule_id"] == "deception.trip"}
    assert trip_alerts["198.51.100.7"]["severity"] == "low"
    assert trip_alerts["198.51.100.8"]["severity"] == "low"
    assert trip_alerts["198.51.100.9"]["severity"] == "medium"
    assert trip_alerts[env_ip]["severity"] == "low"
    assert "198.51.100.10" not in trip_alerts  # fetching a canary page is not a trip

    incidents = (await client.get("/api/v1/incidents?limit=200", headers=admin_headers)).json()["items"]
    for inc in incidents:
        if set(inc["source_ips"]) & set(victims):
            assert inc["actor_type"] != "ai_agent", inc
            assert Severity(inc["severity"]).rank < Severity.HIGH.rank, inc

    actions = (await client.get("/api/v1/response/actions?limit=200", headers=admin_headers)).json()["items"]
    assert not [a for a in actions if a["target"] in victims], actions
    policy = await build_gate_policy()
    framed = set(policy.blocked) | set(policy.deceive) | set(policy.rate_limited) | set(policy.tarpit)
    assert not {n.split("/")[0] for n in framed} & set(victims)

    # the control proves the pipeline would have blocked: decisive follow -> auto-approved block
    assert any(a["target"] == agent_ip and a["action_type"] == "block_ip" for a in actions), actions
    assert any(n.split("/")[0] == agent_ip for n in policy.blocked)
    agent_inc = next(i for i in incidents if agent_ip in i["source_ips"])
    assert agent_inc["actor_type"] == "ai_agent" and agent_inc["severity"] == "critical"
