"""detect-web: stateful rate/behaviour detectors (error burst, credential attacks, request flood)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from tokiwa.config import Settings
from tokiwa.detect.base import Detector
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.engine import DetectionEngine
from tokiwa.schemas.alerts import AlertDraft
from tokiwa.schemas.events import Event

T0 = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def ctx(settings: Settings) -> DetectionContext:
    return DetectionContext(settings)


@pytest.fixture
def engine_detectors(settings: Settings) -> dict[str, Detector]:
    return DetectionEngine(settings).all_detectors()


async def _feed(det: Detector, ctx: DetectionContext, events: list[Event]) -> list[AlertDraft]:
    out: list[AlertDraft] = []
    for ev in events:
        out.extend(await det.process(ev, ctx))
    return out


def _series(
    make: Callable[..., Event], n: int, step: float, **kw: Any
) -> list[Event]:  # n events, `step` seconds apart, path may be a format string with {i}
    path = kw.pop("path", "/")
    return [make(path.format(i=i), ts=T0 + timedelta(seconds=i * step), **kw) for i in range(n)]


# --- web.error_burst -----------------------------------------------------------------------------------


async def test_error_burst_fires_once_per_window(
    engine_detectors: dict[str, Detector], ctx: DetectionContext, make_http_event: Callable[..., Event]
) -> None:
    det = engine_detectors["web.error_burst"]
    events = _series(make_http_event, 60, 0.5, path="/dir{i}/", status=404)
    out = await _feed(det, ctx, events)
    assert len(out) == 1
    a = out[0]
    assert a.rule_id == "web.error_burst" and a.fingerprint == "web.error_burst|203.0.113.10"
    assert a.details["errors"] >= 30 and a.details["unique_paths"] >= 15
    assert a.details["status_counts"]["404"] >= 30
    assert 1 <= len(a.evidence_event_ids) <= 20 and set(a.evidence_event_ids) <= {e.id for e in events}
    # continuing the burst after the cooldown window yields a new (deduplicated by fingerprint) draft
    later = _series(make_http_event, 40, 0.5, path="/more{i}/", status=404)
    for e in later:
        e.timestamp += timedelta(seconds=120)
    assert len(await _feed(det, ctx, later)) == 1


async def test_error_burst_negatives(
    engine_detectors: dict[str, Detector], settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    det = engine_detectors["web.error_burst"]
    # same missing path over and over (broken client / favicon) -> not a brute force
    same = _series(make_http_event, 60, 0.5, path="/favicon.ico", status=404)
    assert await _feed(det, DetectionContext(settings), same) == []
    # busy legit client: mostly 200 with some 404s -> ratio too low
    mixed = [
        make_http_event(f"/p{i}", ts=T0 + timedelta(seconds=i * 0.2), status=404 if i % 4 == 0 else 200)
        for i in range(200)
    ]
    assert await _feed(det, DetectionContext(settings), mixed) == []
    # slow scan spread beyond the window
    slow = _series(make_http_event, 40, 5.0, path="/s{i}", status=404)
    assert await _feed(det, DetectionContext(settings), slow) == []


async def test_error_burst_is_per_source(
    engine_detectors: dict[str, Detector], ctx: DetectionContext, make_http_event: Callable[..., Event]
) -> None:
    det = engine_detectors["web.error_burst"]
    events = [
        make_http_event(f"/x{i}", ip=f"198.51.100.{i % 3}", ts=T0 + timedelta(seconds=i * 0.3), status=404)
        for i in range(60)
    ]
    assert await _feed(det, ctx, events) == []  # 20 per source < 30


# --- web.credential_stuffing ---------------------------------------------------------------------------


def _login_failures(
    make: Callable[..., Event], n: int, users: Callable[[int], str], **kw: Any
) -> list[Event]:
    return [
        make(
            kw.get("path", "/login"),
            method="POST",
            ts=T0 + timedelta(seconds=i * 2),
            status=kw.get("status", 401),
            body=f"username={users(i)}&password=%5BREDACTED%3Asecret%5D",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        for i in range(n)
    ]


async def test_credential_stuffing_many_users(
    engine_detectors: dict[str, Detector], ctx: DetectionContext, make_http_event: Callable[..., Event]
) -> None:
    det = engine_detectors["web.credential_stuffing"]
    out = await _feed(det, ctx, _login_failures(make_http_event, 15, lambda i: f"user{i}"))
    assert len(out) == 1
    a = out[0]
    assert a.severity == "high" and a.details["classification"] == "credential_stuffing"
    assert a.details["unique_usernames"] >= 4
    assert "T1110.004" in a.mitre and a.category == "credential_attack"
    assert a.fingerprint == "web.credential_stuffing|203.0.113.10|/login"
    assert "user1" not in str(a.model_dump())  # usernames are hashed, never stored


async def test_password_guessing_single_user(
    engine_detectors: dict[str, Detector], ctx: DetectionContext, make_http_event: Callable[..., Event]
) -> None:
    det = engine_detectors["web.credential_stuffing"]
    out = await _feed(det, ctx, _login_failures(make_http_event, 12, lambda i: "admin"))
    assert len(out) == 1
    assert out[0].severity == "medium" and out[0].details["classification"] == "password_guessing"
    assert "T1110.001" in out[0].mitre


async def test_credential_negatives(
    engine_detectors: dict[str, Detector], settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    det = engine_detectors["web.credential_stuffing"]
    few = _login_failures(make_http_event, 5, lambda i: f"u{i}")
    assert await _feed(det, DetectionContext(settings), few) == []
    not_login = _login_failures(make_http_event, 20, lambda i: f"u{i}", path="/api/v1/reports")
    assert await _feed(det, DetectionContext(settings), not_login) == []
    ok = _login_failures(make_http_event, 20, lambda i: f"u{i}", status=302)
    assert await _feed(det, DetectionContext(settings), ok) == []


async def test_credential_login_regex_configurable(
    engine_detectors: dict[str, Detector], settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    det = engine_detectors["web.credential_stuffing"]
    settings.detection.web.login_path_regex = r"^/sso/verify$"
    events = _login_failures(make_http_event, 12, lambda i: f"u{i}", path="/sso/verify")
    assert len(await _feed(det, DetectionContext(settings), events)) == 1
    settings.detection.web.login_path_regex = "(broken"  # invalid -> falls back to the default regex
    events = _login_failures(make_http_event, 12, lambda i: f"u{i}", path="/wp-login.php")
    assert len(await _feed(det, DetectionContext(settings), events)) == 1


# --- web.request_flood ---------------------------------------------------------------------------------


async def test_request_flood(
    engine_detectors: dict[str, Detector], ctx: DetectionContext, make_http_event: Callable[..., Event]
) -> None:
    det = engine_detectors["web.request_flood"]
    events = _series(make_http_event, 400, 0.02)  # 50 rps for 8 s
    out = await _feed(det, ctx, events)
    assert len(out) == 1
    a = out[0]
    assert a.rule_id == "web.request_flood" and a.category == "anomaly"
    assert a.details["requests"] >= 200 and a.details["threshold_rps"] == 20.0
    assert a.fingerprint == "web.request_flood|203.0.113.10"


async def test_request_flood_negative_and_config(
    engine_detectors: dict[str, Detector], settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    det = engine_detectors["web.request_flood"]
    normal = _series(make_http_event, 300, 0.1)  # 10 rps
    assert await _feed(det, DetectionContext(settings), normal) == []
    settings.detection.web.flood_max_rps = 5
    out = await _feed(det, DetectionContext(settings), normal)
    # 30 s above threshold with a 10 s window/cooldown -> one draft per window, same fingerprint (engine dedup)
    assert len(out) == 3
    assert {d.fingerprint for d in out} == {"web.request_flood|203.0.113.10"}


async def test_rate_detectors_through_engine_run(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    engine = DetectionEngine(settings)
    events = _series(make_http_event, 60, 0.5, path="/probe{i}.bak", status=404)
    drafts = [d for d in await engine.run(events) if d.rule_id.startswith("web.")]
    rules = {d.rule_id for d in drafts}
    assert "web.error_burst" in rules
    assert "web.sensitive_file_probe" in rules  # each *.bak probe is also a signature hit
    assert all(d.details["detector"] == d.rule_id for d in drafts)
