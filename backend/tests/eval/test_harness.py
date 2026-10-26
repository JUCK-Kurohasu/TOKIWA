"""Evaluation harness end-to-end (mock LLM, small dataset) + metric unit tests + regression compare."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tokiwa.config import Settings
from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.eval.dataset import Truth, generate_events, read_dataset, split_truth, write_dataset
from tokiwa.eval.harness import ReplayOptions, RunResults, make_batches
from tokiwa.eval.metrics import compute_metrics, percentile, roc_auc
from tokiwa.eval.profiles import PROFILES
from tokiwa.eval.report import compare_runs, run_evaluation
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind

SEEN_LABELS: list[dict[str, str]] = []


@register_detector
class _EvalQuoteDetector(Detector):
    """Test-only detector (disabled by default; enabled through the harness overrides)."""

    id = "evaltest.quote"
    name = "eval test: quote/angle bracket in request"
    category = AlertCategory.EXPLOIT_ATTEMPT
    kinds = frozenset({EventKind.HTTP})
    enabled_by_default = False

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        if event.labels:
            SEEN_LABELS.append(event.labels)
        h = event.http
        blob = f"{h.path if h else ''}{h.query if h else ''}{h.request_body if h else ''}"
        if any(m in blob for m in ("%27", "'", "%3C", "<")):
            ua = (h.user_agent or "").lower() if h else ""
            ai = 0.95 if any(t in ua for t in ("httpx", "aiohttp", "go-http", "claude")) else 0.1
            return [self.draft(event, title="quote", severity=Severity.MEDIUM, ai_score=ai)]
        return []


@pytest.fixture
async def small_dataset(tmp_path: Path) -> Path:
    path = tmp_path / "ds.jsonl"
    write_dataset(path, await generate_events(dict.fromkeys(PROFILES, 1), seed=21), {"seed": 21})
    return path


async def test_eval_run_end_to_end(settings: Settings, small_dataset: Path, tmp_path: Path) -> None:
    SEEN_LABELS.clear()
    run1 = tmp_path / "runs" / "r1"
    doc = await run_evaluation(
        small_dataset, run1, ReplayOptions(llm="mock", detector_overrides={"evaltest.quote": True})
    )
    assert (run1 / "metrics.json").is_file() and (run1 / "report.md").is_file()
    assert not (run1 / "work").exists()
    assert SEEN_LABELS == []  # ground truth never reaches detectors
    m = doc["metrics"]
    assert "evaltest.quote" in m["pipeline"]["detectors_enabled"]
    assert m["detection"]["attack_session_rate"] and m["detection"]["attack_session_rate"] > 0.5
    assert m["detection"]["benign_session_fpr"] == 0.0
    assert m["alerts"]["precision"] == 1.0
    assert m["ai_attribution"]["recall"] == 1.0 and m["ai_attribution"]["auc"] == 1.0
    assert m["per_profile"]["ai_agent"]["detected"] == 1
    assert m["latency"]["events"] == doc["dataset"]["events"]
    assert "AI attribution" in (run1 / "report.md").read_text(encoding="utf-8")

    # same dataset without the detector -> regression against run1
    run2 = tmp_path / "runs" / "r2"
    doc2 = await run_evaluation(small_dataset, run2, ReplayOptions(), compare=run1)
    cmp_doc = doc2["comparison"]
    assert cmp_doc["has_regression"] and "detection.attack_session_rate" in cmp_doc["regressions"]
    assert "Regression check" in (run2 / "report.md").read_text(encoding="utf-8")
    assert json.loads((run2 / "metrics.json").read_text())["comparison"]["previous_run"] == "r1"


async def test_live_llm_requires_a_provider(settings: Settings, small_dataset: Path, tmp_path: Path) -> None:
    from tokiwa.eval.harness import EvalError

    with pytest.raises(EvalError):
        await run_evaluation(small_dataset, tmp_path / "live", ReplayOptions(llm="live", budget_usd=0.01))


def test_split_truth_strips_labels() -> None:
    e = Event(
        kind=EventKind.HTTP,
        dataset="gate.http",
        labels={"actor": "ai_agent", "session": "s1"},
        tags=["sim:x", "keep"],
    )
    clean, truth = split_truth([e])
    assert clean[0].labels == {} and clean[0].tags == ["keep"]
    assert e.labels  # original untouched
    assert truth.sessions["s1"].is_ai


def test_batches_follow_gate_windows() -> None:
    from datetime import UTC, datetime, timedelta

    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    evs = [
        Event(kind=EventKind.HTTP, dataset="x", timestamp=t0 + timedelta(seconds=s))
        for s in (0, 0.2, 0.9, 1.5, 5)
    ]
    assert [len(b) for b in make_batches(evs, window_seconds=1.0, max_size=100)] == [3, 1, 1]
    assert [len(b) for b in make_batches(evs, window_seconds=10.0, max_size=2)] == [2, 2, 1]


def _ev(eid: str, session: str, actor: str, attack: str, ip: str) -> Event:
    return Event(
        id=eid,
        kind=EventKind.HTTP,
        dataset="gate.http",
        source={"ip": ip},  # type: ignore[arg-type]
        labels={"actor": actor, "profile": actor, "session": session, "attack": attack},
    )


def test_metrics_attribution_and_llm_agreement() -> None:
    truth = Truth.from_events(
        [
            _ev("a1", "ai", "ai_agent", "sqli", "203.0.113.1"),
            _ev("a2", "ai", "ai_agent", "recon", "203.0.113.1"),
            _ev("b1", "ben", "benign", "none", "203.0.113.2"),
            _ev("h1", "hum", "human", "xss", "203.0.113.3"),
        ]
    )
    triage = {
        "tier": "fast",
        "result": {"actor_type": "ai_agent", "confidence": 0.9, "ai_agent_likelihood": 0.9},
    }
    res = RunResults(
        events=[
            {"id": "a1", "session_id": "S1"},
            {"id": "a2", "session_id": "S1"},
            {"id": "b1", "session_id": "S2"},
        ],
        alerts=[
            {
                "id": "x",
                "rule_id": "r.sqli",
                "severity": "high",
                "evidence_event_ids": ["a1"],
                "ai_score": None,
                "triage": triage,
                "count": 2,
            },
            {
                "id": "y",
                "rule_id": "r.noise",
                "severity": "low",
                "evidence_event_ids": ["b1"],
                "ai_score": None,
            },
            {
                "id": "z",
                "rule_id": "r.ip",
                "severity": "medium",
                "evidence_event_ids": [],
                "source_ip": "203.0.113.3",
            },
        ],
        sessions=[
            {"id": "S1", "ai_score": 0.8, "classification": "ai_agent", "request_count": 2},
            {"id": "S2", "ai_score": 0.1, "classification": "benign", "request_count": 1},
        ],
        llm_calls=[
            {"cost_usd": 0.01, "input_tokens": 100, "output_tokens": 50, "status": "ok", "purpose": "triage"}
        ],
        batch_latencies_ms=[1.0, 3.0],
        batch_sizes=[2, 2],
    )
    m = compute_metrics(truth, res, ai_threshold=0.7)
    assert m["detection"]["attack_session_rate"] == 1.0
    assert (
        m["detection"]["benign_session_fpr"] == 1.0
        and m["detection"]["benign_session_fpr_medium_plus"] == 0.0
    )
    # attack events a1, a2, h1: only a1 is cited as evidence (h1's alert is attributed via source_ip only)
    assert m["detection"]["event_recall"] == 0.3333
    assert m["alerts"]["true_positive"] == 2 and m["alerts"]["false_positive"] == 1
    assert {r["rule_id"]: r["precision"] for r in m["per_detector"]}["r.noise"] == 0.0
    ai = m["ai_attribution"]
    assert (ai["tp"], ai["fp"], ai["fn"]) == (1, 0, 0) and ai["auc"] == 1.0
    assert ai["confusion"]["ai_agent"] == {"ai_agent": 1}
    assert m["llm"]["actor_agreement"] == 1.0 and m["llm"]["by_tier"] == {"fast": 1}
    assert m["cost"]["cost_per_alert_usd"] == round(0.01 / 3, 6)
    assert m["latency"]["batch_p50_ms"] == 2.0


def test_roc_auc_and_percentile() -> None:
    assert roc_auc([0.9, 0.8], [0.1, 0.8]) == 0.875
    assert roc_auc([], [0.1]) is None
    assert percentile([1, 2, 3, 4], 50) == 2.5
    assert percentile([], 95) is None


def test_compare_runs_directions() -> None:
    prev = {"metrics": {"detection": {"benign_session_fpr": 0.1, "attack_session_rate": 0.8}}}
    cur = {"metrics": {"detection": {"benign_session_fpr": 0.0, "attack_session_rate": 0.79}}}
    out = compare_runs(cur, prev)
    status = {d["metric"]: d["status"] for d in out["deltas"]}
    assert status["detection.benign_session_fpr"] == "improved"
    assert status["detection.attack_session_rate"] == "unchanged"  # within tolerance
    assert not out["has_regression"]


async def test_dataset_roundtrip(tmp_path: Path) -> None:
    events = await generate_events({"llm_app_attacker": 1}, seed=2)
    path = tmp_path / "x.jsonl"
    info = write_dataset(path, events, {"seed": 2})
    assert (tmp_path / "x.meta.json").is_file() and info["summary"]["sessions"] == 1
    assert [e.id for e in read_dataset(path)] == [e.id for e in events]
