"""#178: regression comparison checks that the two runs are comparable and watches alert volume per detector."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from tokiwa.eval.cli import app as eval_app
from tokiwa.eval.report import (
    EXIT_NOT_COMPARABLE,
    EXIT_REGRESSION,
    compare_runs,
    comparison_exit_code,
    render_comparison,
)


def _doc(**metrics: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "run": {"id": "r"},
        "comparability": {
            "schema": 1,
            "dataset_sha256": "a" * 64,
            "dataset_events": 248,
            "dataset_generator_version": "1",
            "dataset_seed": 42,
            "dataset_mix": {"ai_agent": 2},
            "llm_mode": "mock",
            "llm_provider": "mock",
            "detectors_enabled": ["sigma", "web.sqli"],
            "sigma_rules_loaded": 25,
            "replay": {"speed": 0.0, "batch_window_seconds": 1.0, "batch_size": 100},
            "settings": {"detection": {"ai_agent_threshold": 0.7, "web": {"flood_max_rps": 20.0}}},
        },
        "metrics": {
            "detection": {"attack_session_rate": 1.0, "attack_session_rate_medium_plus": 1.0},
            "alerts": {"total": 87, "precision": 1.0, "by_detector": {"sigma": 19, "web.sqli": 68}},
        },
    }
    for path, value in metrics.items():
        cur = base["metrics"]
        *parents, leaf = path.split("__")
        for p in parents:
            cur = cur.setdefault(p, {})
        cur[leaf] = value
    return base


def test_identical_runs_are_comparable_and_clean() -> None:
    out = compare_runs(_doc(), _doc())
    assert out["comparable"] and out["mismatches"] == []
    assert not out["has_regression"]
    assert comparison_exit_code(out, fail_on_regression=True, allow_mismatch=False) == 0


def test_sigma_outage_is_caught_by_alert_volume_and_comparability() -> None:
    """The audit case: Sigma off (87 -> 68 alerts) passed as 'regressions: none' because rates stayed at 1.0."""
    prev = _doc()
    cur = _doc(alerts__total=68, alerts__by_detector={"web.sqli": 68})
    cur["comparability"]["sigma_rules_loaded"] = 0
    out = compare_runs(cur, prev)
    assert "alerts.total" in out["regressions"]
    assert "alerts.by_detector[sigma]" in out["regressions"]
    assert "alerts.by_detector[web.sqli]" not in out["regressions"]
    assert out["mismatches"] == ["sigma_rules_loaded: 25 -> 0"]
    assert comparison_exit_code(out, fail_on_regression=True, allow_mismatch=False) == EXIT_NOT_COMPARABLE
    assert comparison_exit_code(out, fail_on_regression=True, allow_mismatch=True) == EXIT_REGRESSION
    assert comparison_exit_code(out, fail_on_regression=False, allow_mismatch=False) == 0


def test_stable_metrics_have_a_floor_and_flag_both_directions() -> None:
    small = compare_runs(_doc(alerts__total=89), _doc())  # +2 of 87: under 10 % and at the floor
    assert "alerts.total" not in small["regressions"]
    more = compare_runs(_doc(alerts__total=120), _doc())
    status = {d["metric"]: d["status"] for d in more["deltas"]}
    assert status["alerts.total"] == "changed" and "alerts.total" in more["regressions"]


def test_different_dataset_is_not_comparable_with_explanations() -> None:
    cur = _doc()
    cur["comparability"].update(dataset_sha256="b" * 64, dataset_seed=2, dataset_events=300)
    mism = compare_runs(cur, _doc())["mismatches"]
    assert mism[0] == "dataset_sha256: aaaaaaaaaaaa -> bbbbbbbbbbbb"
    assert "  (dataset_seed: 42 -> 2)" in mism and "  (dataset_events: 248 -> 300)" in mism


def test_settings_detectors_and_provider_differences_are_listed() -> None:
    cur = _doc()
    c = cur["comparability"]
    c["settings"]["detection"]["web"]["flood_max_rps"] = 50.0
    c["detectors_enabled"] = ["web.sqli", "web.xss"]
    c["llm_provider"] = "anthropic"
    mism = compare_runs(cur, _doc())["mismatches"]
    assert "settings.detection.web.flood_max_rps: 20.0 -> 50.0" in mism
    assert "detectors_enabled: +['web.xss'] -['sigma']" in mism
    assert "llm_provider: 'mock' -> 'anthropic'" in mism


def test_missing_record_is_a_mismatch_but_missing_keys_on_both_sides_are_not() -> None:
    old = _doc()
    del old["comparability"]
    assert "previous run has no comparability record" in compare_runs(_doc(), old)["mismatches"][0]
    a, b = _doc(), _doc()
    del a["comparability"]["sigma_rules_loaded"], b["comparability"]["sigma_rules_loaded"]
    assert compare_runs(a, b)["comparable"]


def test_report_marks_not_comparable() -> None:
    cur = _doc(alerts__total=68)
    cur["comparability"]["sigma_rules_loaded"] = 0
    md = "\n".join(render_comparison(compare_runs(cur, _doc())))
    assert "NOT COMPARABLE" in md and "sigma_rules_loaded: 25 -> 0" in md
    assert "| alerts.total | 87 | 68 |" in md


def test_cli_compare_exit_codes(tmp_path: Path) -> None:
    prev, cur = tmp_path / "prev.json", tmp_path / "cur.json"
    prev.write_text(json.dumps(_doc()), encoding="utf-8")
    bad = _doc(alerts__total=68, alerts__by_detector={"web.sqli": 68})
    bad["comparability"]["sigma_rules_loaded"] = 0
    cur.write_text(json.dumps(bad), encoding="utf-8")
    runner = CliRunner()

    r = runner.invoke(eval_app, ["compare", str(cur), str(prev), "--fail-on-regression"])
    assert r.exit_code == EXIT_NOT_COMPARABLE, r.output
    assert "NOT COMPARABLE" in r.output and "sigma_rules_loaded: 25 -> 0" in r.output

    r = runner.invoke(eval_app, ["compare", str(cur), str(prev), "--fail-on-regression", "--allow-mismatch"])
    assert r.exit_code == EXIT_REGRESSION, r.output
    assert "alerts.total" in r.output

    r = runner.invoke(eval_app, ["compare", str(cur), str(prev)])
    assert r.exit_code == 0 and "NOT COMPARABLE" in r.output

    r = runner.invoke(eval_app, ["compare", str(prev), str(prev), "--fail-on-regression"])
    assert r.exit_code == 0 and "regressions: none" in r.output
