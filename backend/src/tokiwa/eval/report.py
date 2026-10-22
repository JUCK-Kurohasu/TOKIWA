"""Evaluation reports (JSON + Markdown) and regression comparison between two runs (requirements 7-6).

``metrics.json`` is the machine-readable record; ``report.md`` is for humans. ``compare_runs`` diffs the key
metrics of two ``metrics.json`` files and flags regressions beyond a tolerance, so a change to detector weights or
prompts can be judged against the previous baseline (``tokiwa eval run --compare <prev>``).
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tokiwa import __version__
from tokiwa.eval.dataset import dataset_summary, read_dataset, split_truth
from tokiwa.eval.harness import ReplayOptions, replay
from tokiwa.eval.metrics import compute_metrics
from tokiwa.util import utcnow

# (dotted path, direction, tolerance, tolerance kind). abs: absolute delta; rel: relative to previous value.
KEY_METRICS: list[tuple[str, str, float, str]] = [
    ("detection.attack_session_rate", "higher", 0.02, "abs"),
    ("detection.benign_session_fpr", "lower", 0.02, "abs"),
    ("detection.benign_session_fpr_medium_plus", "lower", 0.02, "abs"),
    ("detection.event_recall", "higher", 0.02, "abs"),
    ("detection.event_fpr", "lower", 0.01, "abs"),
    ("alerts.precision", "higher", 0.02, "abs"),
    ("ai_attribution.precision", "higher", 0.02, "abs"),
    ("ai_attribution.recall", "higher", 0.02, "abs"),
    ("ai_attribution.f1", "higher", 0.02, "abs"),
    ("ai_attribution.auc", "higher", 0.02, "abs"),
    ("llm.actor_agreement", "higher", 0.05, "abs"),
    ("llm.verdict_agreement", "higher", 0.05, "abs"),
    ("llm.ai_agreement", "higher", 0.05, "abs"),
    ("cost.cost_per_alert_usd", "lower", 0.2, "rel"),
    ("cost.tokens_per_alert", "lower", 0.2, "rel"),
    ("latency.batch_p95_ms", "lower", 0.5, "rel"),
    ("latency.triage_p95_s", "lower", 0.5, "rel"),
]


def get_path(data: dict[str, Any], dotted: str) -> Any:
    cur: Any = data
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


@dataclass
class Delta:
    metric: str
    previous: float | None
    current: float | None
    delta: float | None
    status: str  # improved / regressed / unchanged / n/a


def compare_runs(current: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    """Diff two metrics documents (the ``metrics`` section of metrics.json, or the whole file)."""
    cur = current.get("metrics", current)
    prev = previous.get("metrics", previous)
    rows: list[Delta] = []
    keys = list(KEY_METRICS)
    for profile in sorted(set(cur.get("per_profile", {})) | set(prev.get("per_profile", {}))):
        actor = (
            cur.get("per_profile", {}).get(profile) or prev.get("per_profile", {}).get(profile) or {}
        ).get("actor")
        direction = "lower" if actor == "benign" else "higher"
        keys.append((f"per_profile.{profile}.detection_rate", direction, 0.02, "abs"))
    for path, direction, tol, kind in keys:
        a, b = get_path(prev, path), get_path(cur, path)
        if not isinstance(a, int | float) or not isinstance(b, int | float):
            rows.append(Delta(path, a, b, None, "n/a"))
            continue
        delta = round(float(b) - float(a), 6)
        limit = tol if kind == "abs" else abs(float(a)) * tol
        worse = delta < -limit if direction == "higher" else delta > limit
        better = delta > limit if direction == "higher" else delta < -limit
        rows.append(
            Delta(path, a, b, delta, "regressed" if worse else ("improved" if better else "unchanged"))
        )
    regressions = [r.metric for r in rows if r.status == "regressed"]
    return {
        "previous_run": previous.get("run", {}).get("id"),
        "regressions": regressions,
        "has_regression": bool(regressions),
        "deltas": [r.__dict__ for r in rows],
    }


def load_metrics(path: Path) -> dict[str, Any]:
    """Accept a run directory or a metrics.json path."""
    if path.is_dir():
        path = path / "metrics.json"
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def _fmt(v: Any) -> str:
    if v is None:
        return "–"
    if isinstance(v, float):
        return f"{v:.4g}"
    return str(v)


def _pct(v: Any) -> str:
    return "–" if v is None else f"{float(v) * 100:.1f}%"


def render_markdown(doc: dict[str, Any]) -> str:
    run, ds, m = doc.get("run", {}), doc.get("dataset", {}), doc["metrics"]
    det, ai, llm, cost, lat, al = (
        m["detection"],
        m["ai_attribution"],
        m["llm"],
        m["cost"],
        m["latency"],
        m["alerts"],
    )
    out: list[str] = [
        f"# TOKIWA evaluation report — {run.get('id', '')}",
        "",
        f"- dataset: `{run.get('dataset')}` ({ds.get('events')} events, {ds.get('sessions')} sessions)",
        f"- LLM: `{run.get('llm')}` (provider: {cost.get('provider')}), replay speed: {run.get('speed')}",
        f"- detectors enabled: {len(m['pipeline']['detectors_enabled'])} / registered: "
        f"{len(m['pipeline']['detectors_registered'])}; enrichers: {', '.join(m['pipeline']['enrichers']) or '–'}",
        "",
        "## Summary",
        "",
        "| metric | value |",
        "|---|---|",
        f"| attack session detection rate | {_pct(det['attack_session_rate'])} "
        f"({det['attack_sessions_detected']}/{det['attack_sessions']}) |",
        f"| benign session FPR (any / medium+) | {_pct(det['benign_session_fpr'])} / "
        f"{_pct(det['benign_session_fpr_medium_plus'])} |",
        f"| event recall (lower bound) | {_pct(det['event_recall'])} |",
        f"| benign event FPR | {_pct(det['event_fpr'])} |",
        f"| alert precision | {_pct(al['precision'])} ({al['total']} alerts, {al['unattributed']} unattributed) |",
        f"| AI attribution P / R / F1 | {_fmt(ai['precision'])} / {_fmt(ai['recall'])} / {_fmt(ai['f1'])} |",
        f"| AI attribution ROC-AUC | {_fmt(ai['auc'])} |",
        f"| LLM agreement actor / verdict / AI | {_pct(llm['actor_agreement'])} / "
        f"{_pct(llm['verdict_agreement'])} / {_pct(llm['ai_agreement'])} ({llm['triaged']} triaged) |",
        f"| LLM cost total / per alert | ${_fmt(cost['cost_usd'])} / ${_fmt(cost['cost_per_alert_usd'])} |",
        f"| tokens per alert | {_fmt(cost['tokens_per_alert'])} |",
        f"| ingest→alert batch p50 / p95 | {_fmt(lat['batch_p50_ms'])} ms / {_fmt(lat['batch_p95_ms'])} ms |",
        f"| alert→triage p50 / p95 | {_fmt(lat['triage_p50_s'])} s / {_fmt(lat['triage_p95_s'])} s "
        f"(source: {lat['triage_source']}) |",
        f"| replay throughput | {_fmt(lat['throughput_eps'])} events/s |",
        "",
        "## Detection by profile",
        "",
        "| profile | actor | sessions | detected | rate | medium+ | alerts |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, row in m["per_profile"].items():
        out.append(
            f"| {name} | {row['actor']} | {row['sessions']} | {row['detected']} | {_pct(row['detection_rate'])} "
            f"| {row['detected_medium_plus']} | {row['alerts']} |"
        )
    out += [
        "",
        "## AI attribution",
        "",
        f"threshold = {ai['threshold']}",
        "",
        "Confusion (truth → predicted):",
        "",
    ]
    preds = sorted({p for c in ai["confusion"].values() for p in c})
    if preds:
        out.append("| truth \\ predicted | " + " | ".join(preds) + " |")
        out.append("|---|" + "---|" * len(preds))
        for actor, row in ai["confusion"].items():
            out.append(f"| {actor} | " + " | ".join(str(row.get(p, 0)) for p in preds) + " |")
    out.append("")
    out.append("AUC by score source: " + ", ".join(f"{k}={_fmt(v)}" for k, v in ai["auc_by_source"].items()))
    out += ["", "## Detectors", "", "| rule | alerts | hits | TP | FP | unattributed | precision | actors |"]
    out.append("|---|---|---|---|---|---|---|---|")
    for r in m["per_detector"]:
        actors = ", ".join(f"{k}:{v}" for k, v in r["actors"].items())
        out.append(
            f"| `{r['rule_id']}` | {r['alerts']} | {r['hits']} | {r['tp']} | {r['fp']} | {r['unattributed']} "
            f"| {_pct(r['precision'])} | {actors} |"
        )
    if not m["per_detector"]:
        out.append("| (no alerts) | | | | | | | |")
    out += [
        "",
        "## LLM",
        "",
        f"- calls: {cost['llm_calls']} by status {cost['by_status']} by purpose {cost['by_purpose']}",
        f"- tokens in/out: {cost['input_tokens']} / {cost['output_tokens']}",
        f"- triage records by tier: {llm['by_tier']}",
    ]
    cmp_doc = doc.get("comparison")
    if cmp_doc:
        out += ["", f"## Regression check vs `{cmp_doc.get('previous_run')}`", ""]
        verdict = "REGRESSION" if cmp_doc["has_regression"] else "no regression"
        out += [f"**{verdict}**", "", "| metric | previous | current | Δ | status |", "|---|---|---|---|---|"]
        for d in cmp_doc["deltas"]:
            if d["status"] == "n/a" and d["previous"] is None and d["current"] is None:
                continue
            out.append(
                f"| {d['metric']} | {_fmt(d['previous'])} | {_fmt(d['current'])} | {_fmt(d['delta'])} | {d['status']} |"
            )
    notes = m["pipeline"].get("notes") or []
    if notes:
        out += ["", "## Notes", ""] + [f"- {n}" for n in notes]
    out += [
        "",
        "---",
        "Event recall is a lower bound (windowed detectors cite a subset of events; evidence is capped per alert).",
        "Ground truth comes from simulator labels; see eval/README.md for definitions.",
        "",
    ]
    return "\n".join(out)


def write_report(out_dir: Path, doc: dict[str, Any]) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    jpath = out_dir / "metrics.json"
    mpath = out_dir / "report.md"
    jpath.write_text(json.dumps(doc, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    mpath.write_text(render_markdown(doc), encoding="utf-8")
    return jpath, mpath


async def run_evaluation(
    dataset: Path,
    out_dir: Path,
    opts: ReplayOptions | None = None,
    *,
    compare: Path | None = None,
    keep_work: bool = False,
) -> dict[str, Any]:
    """Dataset -> replay -> metrics -> ``out_dir/metrics.json`` + ``out_dir/report.md``. Returns the document."""
    opts = opts or ReplayOptions()
    events = read_dataset(dataset)
    clean, truth = split_truth(events)
    work = out_dir / "work"
    results = await replay(clean, work, opts)
    doc: dict[str, Any] = {
        "run": {
            "id": out_dir.name,
            "created_at": utcnow().isoformat(),
            "dataset": str(dataset),
            "llm": opts.llm,
            "speed": opts.speed,
            "batch_window_seconds": opts.batch_window_seconds,
            "batch_size": opts.batch_size,
            "detector_overrides": opts.detector_overrides,
            "tokiwa_version": __version__,
        },
        "dataset": dataset_summary(events),
        "metrics": compute_metrics(truth, results),
    }
    if compare is not None:
        doc["comparison"] = compare_runs(doc, load_metrics(compare))
    write_report(out_dir, doc)
    if not keep_work:
        shutil.rmtree(work, ignore_errors=True)
    return doc
