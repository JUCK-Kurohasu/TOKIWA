"""Simulator: profiles, determinism, AI-agent behaviour, live mode (in-process victim), target refusal."""

from __future__ import annotations

import statistics
from collections import Counter

import httpx
import pytest

from tokiwa.eval.dataset import generate_events
from tokiwa.eval.discovery import extract_js_routes, extract_robots_disallow, find_canary_instructions
from tokiwa.eval.profiles import PROFILES, parse_mix
from tokiwa.eval.safety import TargetNotAllowedError
from tokiwa.eval.sim import build_plans, simulate_live
from tokiwa.eval.virtual import APP_JS, ROBOTS, canary_comment

from .test_victim import _load_victim

ONE_EACH = dict.fromkeys(PROFILES, 1)


async def test_generation_is_deterministic_and_labelled() -> None:
    a = await generate_events(ONE_EACH, seed=11)
    b = await generate_events(ONE_EACH, seed=11)
    assert [e.model_dump(mode="json") for e in a] == [e.model_dump(mode="json") for e in b]
    assert {e.labels["profile"] for e in a} == set(PROFILES)
    for e in a:
        assert {"actor", "profile", "session", "attack"} <= set(e.labels)
        assert e.http is not None and e.http.status
    c = await generate_events(ONE_EACH, seed=12)
    assert [e.http.path for e in c if e.http] != [e.http.path for e in a if e.http]


async def test_profile_behaviours() -> None:
    events = await generate_events(ONE_EACH, seed=5)
    by = {p: [e for e in events if e.labels["profile"] == p] for p in PROFILES}
    # benign never attacks
    assert {e.labels["attack"] for e in by["benign_browser"]} == {"none"}
    # scanner: constant fast cadence
    ts = [e.timestamp.timestamp() for e in by["scanner"]]
    gaps = [b - a for a, b in zip(ts, ts[1:], strict=False)]
    assert statistics.median(gaps) < 0.1 and statistics.pstdev(gaps) < 0.05
    # AI agent: tool UA, discovers unlinked API routes, follows the canary, mutates after errors, bursts + gaps
    ai = by["ai_agent"]
    assert all("Mozilla/5.0 (Windows" not in (e.http.user_agent or "") for e in ai if e.http)
    paths = {e.http.path for e in ai if e.http}
    assert "/api/admin/export" in paths  # only referenced from the JS bundle
    canary = [e for e in ai if e.labels["attack"] == "ai_canary_follow"]
    assert canary and canary[0].http and "x-debug-auth" in canary[0].http.headers
    assert Counter(e.labels["attack"] for e in ai)["sqli"] >= 2
    ai_ts = [e.timestamp.timestamp() for e in ai]
    ai_gaps = [b - a for a, b in zip(ai_ts, ai_ts[1:], strict=False)]
    assert min(ai_gaps) < 0.05 and max(ai_gaps) > 2.0
    # LLM app attacker targets the chat endpoint
    assert {e.http.path for e in by["llm_app_attacker"] if e.labels["attack"] != "none" and e.http} == {
        "/api/chat"
    }
    # secrets in bodies are redacted like the Gate does
    logins = [e for e in events if e.http and e.http.path == "/api/login" and e.http.request_body]
    assert all("lab-demo-password" not in (e.http.request_body or "") for e in logins)


def test_discovery_helpers() -> None:
    assert "/api/admin/export" in extract_js_routes(APP_JS)
    assert "/api/products/{id}" in extract_js_routes(APP_JS)
    assert extract_robots_disallow(ROBOTS) == ["/admin/", "/api/internal/", "/backup/"]
    inst = find_canary_instructions(f"<html>{canary_comment('tok-abc12345')}</html>")
    assert (
        inst and inst[0].header == ("X-Debug-Auth", "tok-abc12345") and inst[0].path == "/api/internal/debug"
    )
    assert find_canary_instructions("<!-- maintenance window at /api/x -->") == []  # not addressed to AI


def test_parse_mix() -> None:
    assert parse_mix("ai_agent=2,scanner") == {"ai_agent": 2, "scanner": 1}
    assert parse_mix("mixed")["benign_browser"] >= 1
    assert parse_mix("all", default_count=2) == dict.fromkeys(PROFILES, 2)
    with pytest.raises(ValueError):
        parse_mix("nope")


async def test_live_mode_against_in_process_victim() -> None:
    victim = _load_victim()
    transport = httpx.ASGITransport(app=victim.create_app())
    plans = build_plans({"ai_agent": 1, "benign_browser": 1}, seed=3, spread_seconds=0)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8080") as client:
        exchanges = await simulate_live(
            plans, target="http://127.0.0.1:8080", time_scale=0.0, max_rps=0, client=client, spoof_xff=True
        )
    assert len(exchanges) > 20
    assert all(ex.response.error is None for ex in exchanges)
    assert {ex.response.status for ex in exchanges} >= {200, 404}
    canary = [ex for ex in exchanges if ex.labels["attack"] == "ai_canary_follow"]
    assert canary and ("x-debug-auth", victim.CANARY_TOKEN) in canary[0].headers
    assert all(("x-forwarded-for", ex.source_ip) in ex.headers for ex in exchanges)


async def test_live_mode_refuses_public_targets_and_caps_requests() -> None:
    plans = build_plans({"scanner": 1}, seed=1, spread_seconds=0)
    with pytest.raises(TargetNotAllowedError):
        await simulate_live(plans, target="http://8.8.8.8")
    victim = _load_victim()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=victim.create_app()), base_url="http://127.0.0.1"
    ) as client:
        exchanges = await simulate_live(
            plans, target="http://127.0.0.1", time_scale=0.0, max_rps=0, max_requests=15, client=client
        )
    assert len(exchanges) == 15
