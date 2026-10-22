"""Matcher / index: which events are trips and how they are classified (pure, no DB)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from tokiwa.config import DeceptionSettings, RedactionSettings
from tokiwa.deception.matcher import DeceptionIndex, TripType, match_event, normalize_path
from tokiwa.deception.tokens import Flavor, Slot, honey_values
from tokiwa.llm.redact import redact_headers, redact_text
from tokiwa.schemas.events import DeceptionInfo, Event, EventKind, LLMAppInfo
from tokiwa.schemas.response import DeceptionAsset, DeceptionKind

KEY = b"unit-test-derive-key"
MakeAsset = Callable[..., DeceptionAsset]
MakeEvent = Callable[..., Event]


def _index(assets: list[DeceptionAsset], **overrides: Any) -> DeceptionIndex:
    return DeceptionIndex.build(assets, key=KEY, settings=DeceptionSettings(**overrides))


def _one(event: Event, index: DeceptionIndex) -> TripType | None:
    trips = match_event(event, index)
    assert len(trips) <= 1
    return trips[0].trip_type if trips else None


def _gate_redact(event: Event) -> Event:
    """What the Gate does before shipping (headers, query, body are masked)."""
    cfg = RedactionSettings()
    assert event.http is not None
    event.http.headers = redact_headers(event.http.headers, cfg)
    event.http.query = redact_text(event.http.query, cfg)
    event.http.request_body = redact_text(event.http.request_body, cfg)
    return event


@pytest.mark.parametrize(
    "path", ["/.env", "//.env", "/static/../.env", "/%2eenv", "/%252eenv", "/.ENV", "/.env/"]
)
def test_decoy_path_variants(make_asset: MakeAsset, make_http_event: MakeEvent, path: str) -> None:
    idx = _index([make_asset(DeceptionKind.DECOY_PATH, "/.env")])
    assert _one(make_http_event(path), idx) == TripType.DECOY_PATH


@pytest.mark.parametrize("path", ["/", "/.envx", "/env", "/index.html", "/api/internal/"])
def test_non_decoy_paths(make_asset: MakeAsset, make_http_event: MakeEvent, path: str) -> None:
    idx = _index([make_asset(DeceptionKind.DECOY_PATH, "/.env")])
    assert match_event(make_http_event(path), idx) == []


def test_normalize_path() -> None:
    assert normalize_path("//a//b/../.Env") == "/a/.env"
    assert normalize_path("/x/") == "/x/"
    assert normalize_path(None) == "/"
    assert normalize_path("a\\b") == "/a/b"


def test_honeytoken_values_in_any_field(make_asset: MakeAsset, make_http_event: MakeEvent) -> None:
    decoy = make_asset(DeceptionKind.DECOY_PATH, "/.env")
    values = honey_values(DeceptionKind.DECOY_PATH, decoy.token or "", KEY)
    idx = _index([decoy])
    cases = [
        make_http_event("/api/v1/orders", body=f'{{"key": "{decoy.token}"}}', method="POST"),
        make_http_event("/download", query=f"ref={decoy.token}"),
        make_http_event("/", headers={"x-internal-key": decoy.token or ""}),
        make_http_event(
            "/s3", query=f"X-Amz-Credential={values[Slot.AWS_KEY_ID]}%2F20261022%2Fap-northeast-1"
        ),
        make_http_event("/login", method="POST", body=f"username={values[Slot.DB_USER]}&password=x"),
    ]
    for ev in cases:
        trips = match_event(_gate_redact(ev), idx)
        assert [t.trip_type for t in trips] == [TripType.HONEYTOKEN], ev.http
        assert trips[0].asset.id == decoy.id


def test_url_encoded_token_is_found(make_asset: MakeAsset, make_http_event: MakeEvent) -> None:
    honey = make_asset(DeceptionKind.HONEYTOKEN, None, flavor=Flavor.API_KEY)
    encoded = "".join(f"%{ord(c):02X}" for c in honey.token or "")
    assert _one(make_http_event("/x", query=f"q={encoded}"), _index([honey])) == TripType.HONEYTOKEN


def test_redaction_limits_are_real(make_asset: MakeAsset, make_http_event: MakeEvent) -> None:
    """Documented blind spots: sensitive headers and secret-looking parameters are masked before detection."""
    honey = make_asset(DeceptionKind.HONEYTOKEN, None)
    idx = _index([honey])
    hidden = [
        make_http_event("/", headers={"authorization": f"Bearer {honey.token}"}),
        make_http_event("/", headers={"x-api-key": honey.token or ""}),
        make_http_event("/", query=f"api_key={honey.token}"),
    ]
    for ev in hidden:
        assert match_event(_gate_redact(ev), idx) == []


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"headers": {"x-debug-auth": "{tok}"}}, TripType.AI_CANARY_FOLLOWED),
        ({"path": "/api/internal/{tok}/"}, TripType.AI_CANARY_FOLLOWED),
        ({"path": "/api/internal/{tok}/users"}, TripType.AI_CANARY_FOLLOWED),
        ({"headers": {"referer": "http://app.lab/api/internal/{tok}/"}}, TripType.AI_CANARY_FOLLOWED),
        ({"referrer": "http://app.lab/api/internal/{tok}/config"}, TripType.AI_CANARY_FOLLOWED),
        ({"body": "debug value is {tok}"}, TripType.AI_CANARY_TOKEN),
        ({"path": "/{tok}"}, TripType.AI_CANARY_TOKEN),  # not the instructed composition
        ({"query": "ref={tok}"}, TripType.AI_CANARY_TOKEN),
        ({"headers": {"x-other": "{tok}"}}, TripType.AI_CANARY_TOKEN),
    ],
)
def test_ai_canary_followed_vs_observed(
    make_asset: MakeAsset, make_http_event: MakeEvent, kwargs: dict[str, Any], expected: TripType
) -> None:
    canary = make_asset(DeceptionKind.AI_CANARY, None)
    tok = canary.token or ""
    filled: dict[str, Any] = {}
    for k, v in kwargs.items():
        filled[k] = (
            {hk: hv.format(tok=tok) for hk, hv in v.items()} if isinstance(v, dict) else v.format(tok=tok)
        )
    path = filled.pop("path", "/")
    ev = make_http_event(path, **{k: v for k, v in filled.items() if k != "referrer"})
    if "referrer" in filled:
        assert ev.http is not None
        ev.http.referrer = filled["referrer"]
    trips = match_event(_gate_redact(ev), _index([canary]))
    assert [t.trip_type for t in trips] == [expected]
    assert trips[0].token == tok


def test_custom_canary_header(make_asset: MakeAsset, make_http_event: MakeEvent) -> None:
    canary = make_asset(DeceptionKind.AI_CANARY, None)
    idx = _index([canary], canary_header="X-Trace-Key")
    ev = make_http_event("/", headers={"x-trace-key": canary.token or ""})
    assert _one(ev, idx) == TripType.AI_CANARY_FOLLOWED
    ev2 = make_http_event("/", headers={"x-debug-auth": canary.token or ""})
    assert _one(ev2, idx) == TripType.AI_CANARY_TOKEN


def test_decoy_derived_canary_counts_as_ai_canary(make_asset: MakeAsset, make_http_event: MakeEvent) -> None:
    decoy = make_asset(DeceptionKind.DECOY_PATH, "/.env")
    canary = honey_values(DeceptionKind.DECOY_PATH, decoy.token or "", KEY)[Slot.CANARY]
    ev = make_http_event(f"/api/internal/{canary}/", headers={"x-debug-auth": canary})
    trips = match_event(ev, _index([decoy]))
    assert len(trips) == 1 and trips[0].ai_followed and trips[0].asset.id == decoy.id


def test_canary_page_fetch_is_not_a_trip(make_asset: MakeAsset, make_http_event: MakeEvent) -> None:
    robots = make_asset(DeceptionKind.AI_CANARY, "/robots.txt")
    idx = _index([robots])
    assert match_event(make_http_event("/robots.txt"), idx) == []
    gate_ev = make_http_event("/robots.txt")
    gate_ev.kind = EventKind.DECEPTION
    gate_ev.deception = DeceptionInfo(asset_id=robots.id, asset_kind="ai_canary")
    assert match_event(gate_ev, idx) == []


def test_gate_deception_event_names_asset(make_asset: MakeAsset, make_http_event: MakeEvent) -> None:
    decoy = make_asset(DeceptionKind.DECOY_PATH, "/backup.sql")
    ev = make_http_event("/somewhere-else")
    ev.kind = EventKind.DECEPTION
    ev.deception = DeceptionInfo(asset_id=decoy.id, asset_kind="decoy_path")
    assert _one(ev, _index([decoy])) == TripType.DECOY_PATH


def test_one_trip_per_asset_with_strongest_type(make_asset: MakeAsset, make_http_event: MakeEvent) -> None:
    decoy = make_asset(DeceptionKind.DECOY_PATH, "/.env")
    canary = honey_values(DeceptionKind.DECOY_PATH, decoy.token or "", KEY)[Slot.CANARY]
    ev = make_http_event("/.env", headers={"x-debug-auth": canary}, query=f"k={decoy.token}")
    trips = match_event(ev, _index([decoy]))
    assert len(trips) == 1
    assert trips[0].trip_type == TripType.AI_CANARY_FOLLOWED
    assert trips[0].path_hit and set(trips[0].slots) == {"api_key", "canary"}


def test_two_assets_two_trips(make_asset: MakeAsset, make_http_event: MakeEvent) -> None:
    decoy = make_asset(DeceptionKind.DECOY_PATH, "/.env")
    honey = make_asset(DeceptionKind.HONEYTOKEN, None)
    ev = make_http_event("/.env", body=f"token {honey.token}")
    types = sorted(t.trip_type.value for t in match_event(ev, _index([decoy, honey])))
    assert types == ["decoy_path", "honeytoken"]


def test_labyrinth_depth_and_toggle(make_asset: MakeAsset, make_http_event: MakeEvent) -> None:
    lab = make_asset(DeceptionKind.LABYRINTH, "/archive/*")
    assert match_event(make_http_event("/archive/a/"), _index([lab])) == []  # off by default
    idx = _index([lab], labyrinth_enabled=True)
    trips = match_event(make_http_event("/archive/a/b/c/"), idx)
    assert trips[0].trip_type == TripType.LABYRINTH and trips[0].depth == 3
    assert match_event(make_http_event("/archive"), idx)[0].depth == 0
    assert match_event(make_http_event("/archived"), idx) == []


def test_wildcard_decoy_path(make_asset: MakeAsset, make_http_event: MakeEvent) -> None:
    idx = _index([make_asset(DeceptionKind.DECOY_PATH, "/backup/*")])
    assert _one(make_http_event("/backup/db-2024.tar.gz"), idx) == TripType.DECOY_PATH
    assert _one(make_http_event("/backup"), idx) == TripType.DECOY_PATH
    assert match_event(make_http_event("/backups"), idx) == []


def test_disabled_assets_and_disabled_feature(make_asset: MakeAsset, make_http_event: MakeEvent) -> None:
    off = make_asset(DeceptionKind.DECOY_PATH, "/.env", enabled=False)
    assert _index([off]).empty
    on = make_asset(DeceptionKind.DECOY_PATH, "/.env")
    assert _index([on], enabled=False).empty
    assert match_event(make_http_event("/.env"), _index([on], enabled=False)) == []


def test_non_http_events_are_scanned(make_asset: MakeAsset) -> None:
    honey = make_asset(DeceptionKind.HONEYTOKEN, None)
    idx = _index([honey])
    llm = Event(
        kind=EventKind.LLM_APP, dataset="app.chat", llm_app=LLMAppInfo(prompt=f"use key {honey.token} pls")
    )
    assert _one(llm, idx) == TripType.HONEYTOKEN
    raw = Event(kind=EventKind.CUSTOM, dataset="x", raw={"line": f"GET /?k={honey.token}"})
    assert _one(raw, idx) == TripType.HONEYTOKEN
    benign = Event(kind=EventKind.CUSTOM, dataset="x", message="nothing to see")
    assert match_event(benign, idx) == []
