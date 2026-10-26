"""Classification of synthetic sessions (acceptance: 100% on the four actor types) + scoring explainability."""

from __future__ import annotations

import pytest

from tokiwa.aidetect import scoring
from tokiwa.aidetect.features import build_observations, compute_features
from tokiwa.aidetect.fingerprints import fingerprint_info
from tokiwa.aidetect.sessions import SessionTracker
from tokiwa.schemas.common import ActorType

from . import synth

SEEDS = range(1, 6)


def _classify_pure(events):  # type: ignore[no-untyped-def]
    h = events[0].http
    fp = fingerprint_info(h.user_agent, h.headers, scheme=h.scheme)
    feats = compute_features(build_observations(events), fp=fp)
    return feats, scoring.score_features(feats)


@pytest.mark.parametrize("profile", sorted(synth.GENERATORS))
@pytest.mark.parametrize("seed", SEEDS)
def test_synthetic_sessions_classified(profile: str, seed: int) -> None:
    events = synth.GENERATORS[profile](seed=seed)
    # pure-function path
    _, res = _classify_pure(events)
    assert str(res.classification) == synth.EXPECTED[profile], (profile, seed, res)
    # tracker path (what the sessionizer does): one session per actor, same verdict
    tr = SessionTracker(idle_timeout_s=1800)
    tr.observe_batch(events)
    sessions = tr.sessions()
    assert len(sessions) == 1
    s = sessions[0]
    assert str(s.classification) == synth.EXPECTED[profile]
    assert all(e.session_id == s.id for e in events)


def test_ai_score_separation() -> None:
    ai = [_classify_pure(synth.ai_agent(seed=s))[1].ai_score for s in SEEDS]
    others = [
        _classify_pure(gen(seed=s))[1].ai_score
        for name, gen in synth.GENERATORS.items()
        if not name.startswith("ai_agent")
        for s in SEEDS
    ]
    assert min(ai) >= scoring.DEFAULT_AI_THRESHOLD
    assert max(others) < 0.3


def test_indicators_are_explainable() -> None:
    feats, res = _classify_pure(synth.ai_agent(seed=2))
    keys = [i["key"] for i in res.indicators]
    assert {"adaptive_mutation", "discovery_then_use", "burst_think_rhythm"} <= set(keys)
    for ind in res.indicators:
        assert ind["ja"] and ind["en"] and ind["evidence"]
        assert ind["weight"] == scoring.AI_WEIGHTS[ind["key"]]
    # positives first, sorted by contribution
    contribs = [i["contribution"] for i in res.indicators if i["direction"] == "for"]
    assert contribs == sorted(contribs, reverse=True)
    merged = res.as_features()
    assert set(merged["scores"]) == {"ai", "scanner", "hostile"}
    assert feats["adaptive_mutations"] >= 2
    assert feats["api_after_discovery_hits"] >= 4


def test_canary_is_decisive_and_few_requests_unknown() -> None:
    feats, res = _classify_pure(synth.benign(seed=1)[:3])
    assert res.classification == ActorType.UNKNOWN
    feats["canary_hits"] = 1
    res2 = scoring.score_features(feats)
    assert res2.classification == ActorType.AI_AGENT
    assert res2.ai_score >= scoring.CANARY_FLOOR


def test_weights_live_in_one_place() -> None:
    sig = scoring.signals({})
    for table in (scoring.AI_WEIGHTS, scoring.SCANNER_WEIGHTS, scoring.HOSTILE_WEIGHTS):
        assert set(table) <= set(sig)
    assert set(scoring.AI_WEIGHTS) <= set(scoring.INDICATOR_LABELS)
