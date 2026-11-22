"""Audit #30 (L03-02): transcription variants of a canary value must still trip.

markdownify (common in agent web tools) turns ``dbg_x`` into ``dbg\\_x``; pipelines lower-case values; LLMs
mis-copy 24 random characters. Variants were measured against the Gate in ``repro/L03/variants_v1.txt``.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from typing import Any

import pytest

from tokiwa.config import DeceptionSettings
from tokiwa.deception.matcher import DeceptionIndex, TripType, canary_header_attempt, match_event
from tokiwa.deception.provenance import Provenance
from tokiwa.deception.tokens import Flavor, generate_token
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.detectors.deception_trip import DeceptionTripDetector
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event
from tokiwa.schemas.response import DeceptionAsset, DeceptionKind

KEY = b"unit-test-derive-key"
MakeAsset = Callable[..., DeceptionAsset]
MakeEvent = Callable[..., Event]
UA = {"user-agent": "python-httpx/0.28", "host": "shop.example"}


def _index(assets: list[DeceptionAsset], **over: Any) -> DeceptionIndex:
    return DeceptionIndex.build(assets, key=KEY, settings=DeceptionSettings(**over))


@pytest.fixture
def canary(make_asset: MakeAsset) -> DeceptionAsset:
    # the "_" after the prefix is what markdownify escapes; force an inner "_"-free body for determinism
    return make_asset(DeceptionKind.AI_CANARY, token="dbg_" + generate_token(Flavor.CANARY)[4:])


def _trip(ev: Event, index: DeceptionIndex) -> tuple[TripType, Provenance] | None:
    trips = match_event(ev, index)
    assert len(trips) <= 1
    return (trips[0].trip_type, trips[0].provenance) if trips else None


def test_markdown_escaped_and_case_variants_trip(canary: DeceptionAsset, make_http_event: MakeEvent) -> None:
    index = _index([canary])
    v = canary.token
    assert v is not None
    esc = v.replace("_", "\\_")
    followed_direct = (TripType.AI_CANARY_FOLLOWED, Provenance.DIRECT)
    followed_passive = (TripType.AI_CANARY_FOLLOWED, Provenance.PASSIVE)
    cases: list[tuple[Event, tuple[TripType, Provenance]]] = [
        (make_http_event("/", headers={**UA, "X-Debug-Auth": esc}), followed_direct),  # md_escaped_hdr
        (make_http_event("/", headers={**UA, "X-Debug-Auth": v.lower()}), followed_direct),  # lowercase_hdr
        (make_http_event("/", headers={**UA, "x-debug-auth": v.upper()}), followed_direct),
        (make_http_event(f"/api/internal/{esc}/", headers=UA), followed_passive),  # md_escaped_path
        (make_http_event(f"/api/internal/{esc.replace(chr(92), '%5C')}/", headers=UA), followed_passive),
        (make_http_event(f"/API/Internal/{v.upper()}/users", headers=UA), followed_passive),
        (
            make_http_event("/next", headers={**UA, "referer": f"https://app.lab/api/internal/{esc}/"}),
            followed_passive,
        ),
        (
            make_http_event("/search", query=f"ref={esc}", headers=UA),
            (TripType.AI_CANARY_TOKEN, Provenance.PASSIVE),
        ),
    ]
    for ev, expected in cases:
        assert _trip(ev, index) == expected, (
            ev.http.path if ev.http else None,
            ev.http.headers if ev.http else None,
        )
    # the trip records the stored value, not the variant
    (trip,) = match_event(make_http_event("/", headers={**UA, "X-Debug-Auth": esc}), index)
    assert trip.token == v


def test_honeytoken_case_variant(make_asset: MakeAsset, make_http_event: MakeEvent) -> None:
    honey = make_asset(DeceptionKind.HONEYTOKEN, "/creds.txt")
    index = _index([honey])
    assert honey.token is not None
    ev = make_http_event("/api/orders", headers={**UA, "x-service-key": honey.token.lower()})
    assert _trip(ev, index) == (TripType.HONEYTOKEN, Provenance.DIRECT)


@pytest.mark.parametrize(
    "mangle",
    [
        lambda v: v[:12],  # cut
        # one character mis-copied (compared case-insensitively since #30, so change the letter, not its case)
        lambda v: v[:-1] + ("Z" if v[-1].lower() != "z" else "Y"),
        lambda v: base64.b64encode(v.encode()).decode(),  # b64_hdr
        lambda v: "dbg_" + "x" * 24,
    ],
    ids=["truncated", "typo", "base64", "made_up"],
)
def test_canary_header_with_unknown_value_is_an_attempt(
    canary: DeceptionAsset, make_http_event: MakeEvent, mangle: Callable[[str], str]
) -> None:
    index = _index([canary])
    assert canary.token is not None
    ev = make_http_event("/", headers={**UA, "X-Debug-Auth": mangle(canary.token)})
    assert match_event(ev, index) == []
    assert canary_header_attempt(ev, index) == mangle(canary.token)


def test_attempt_needs_served_canaries_and_a_value(
    canary: DeceptionAsset, make_asset: MakeAsset, make_http_event: MakeEvent
) -> None:
    ev = make_http_event("/", headers={**UA, "X-Debug-Auth": "something"})
    assert canary_header_attempt(ev, _index([canary], ai_canaries=False)) is None
    assert canary_header_attempt(ev, _index([make_asset(DeceptionKind.LABYRINTH)])) is None  # no canary value
    assert canary_header_attempt(make_http_event("/", headers=UA), _index([canary])) is None
    redacted = make_http_event("/", headers={**UA, "X-Debug-Auth": "[REDACTED:secret]"})
    assert canary_header_attempt(redacted, _index([canary])) is None


async def test_attempt_alert_is_medium_and_not_an_ai_verdict(
    canary: DeceptionAsset, make_http_event: MakeEvent, monkeypatch: pytest.MonkeyPatch, settings
) -> None:  # type: ignore[no-untyped-def]
    from tokiwa.detect.detectors import deception_trip

    index = _index([canary])

    async def fake_index() -> DeceptionIndex:
        return index

    monkeypatch.setattr(deception_trip, "get_index", fake_index)
    det = DeceptionTripDetector()
    ctx = DetectionContext(settings=settings)
    assert canary.token is not None
    (a,) = await det.process(make_http_event("/", headers={**UA, "X-Debug-Auth": canary.token[:10]}), ctx)
    assert a.severity == Severity.MEDIUM and str(a.category) == "deception" and a.ai_score is None
    assert not any("ai_canary" in t for t in a.tags) and a.details["trip_type"] == "canary_attempt"
    # the correct value: a decisive trip, no extra attempt alert
    (b,) = await det.process(make_http_event("/", headers={**UA, "X-Debug-Auth": canary.token}), ctx)
    assert b.severity == Severity.CRITICAL and "ai_canary" in b.tags
    # sent by a browser from another site (CORS): not even an attempt
    cross = {
        **UA,
        "X-Debug-Auth": "garbled",
        "sec-fetch-site": "cross-site",
        "origin": "https://evil.example",
    }
    assert await det.process(make_http_event("/", headers=cross), ctx) == []
