"""Evaluation reports (JSON + Markdown) and regression comparison between two runs (requirements 7-6).

``metrics.json`` is the machine-readable record; ``report.md`` is for humans. ``compare_runs`` diffs the key
metrics of two ``metrics.json`` files and flags regressions beyond a tolerance, so a change to detector weights or
prompts can be judged against the previous baseline (``tokiwa eval run --compare <prev>``).

A diff only means something when both runs replayed the same data under the same conditions. Every run therefore
records a ``comparability`` block (dataset sha256, LLM provider, enabled detectors, loaded Sigma rules, thresholds,
replay batching); ``compare_runs`` lists every difference under ``mismatches`` and the CLI refuses to give a
regression verdict on a mismatched pair unless ``--allow-mismatch`` is passed (#178).
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

from tokiwa import __version__
from tokiwa.eval.dataset import dataset_summary, meta_path, read_dataset, split_truth
from tokiwa.eval.harness import ReplayOptions, RunResults, replay
from tokiwa.eval.metrics import compute_metrics
from tokiwa.util import utcnow


class MetricSpec(NamedTuple):
    """One compared metric.

    direction: ``higher`` / ``lower`` is better, or ``stable`` (a change either way beyond the tolerance is
    reported as ``changed`` and counts as a regression: on an identical dataset and configuration, alert volume
    should not move by itself). kind: ``abs`` absolute delta, ``rel`` relative to the previous value. min_delta:
    changes smaller than this never count (keeps small counts from flapping).
    """

    path: str
    direction: str
    tolerance: float
    kind: str
    min_delta: float = 0.0


KEY_METRICS: list[MetricSpec] = [
    MetricSpec("detection.attack_session_rate_medium_plus", "higher", 0.02, "abs"),
    MetricSpec("detection.attack_session_rate", "higher", 0.02, "abs"),
    MetricSpec("detection.benign_session_fpr", "lower", 0.02, "abs"),
    MetricSpec("detection.benign_session_fpr_medium_plus", "lower", 0.02, "abs"),
    MetricSpec("detection.event_recall", "higher", 0.02, "abs"),
    MetricSpec("detection.event_fpr", "lower", 0.01, "abs"),
    MetricSpec("alerts.total", "stable", 0.1, "rel", 2.0),
    MetricSpec("alerts.precision", "higher", 0.02, "abs"),
    MetricSpec("ai_attribution.precision", "higher", 0.02, "abs"),
    MetricSpec("ai_attribution.recall", "higher", 0.02, "abs"),
    MetricSpec("ai_attribution.f1", "higher", 0.02, "abs"),
    MetricSpec("ai_attribution.auc", "higher", 0.02, "abs"),
    MetricSpec("llm.actor_agreement", "higher", 0.05, "abs"),
    MetricSpec("llm.verdict_agreement", "higher", 0.05, "abs"),
    MetricSpec("llm.ai_agreement", "higher", 0.05, "abs"),
    MetricSpec("cost.cost_per_alert_usd", "lower", 0.2, "rel"),
    MetricSpec("cost.tokens_per_alert", "lower", 0.2, "rel"),
    MetricSpec("latency.batch_p95_ms", "lower", 0.5, "rel"),
    MetricSpec("latency.triage_p95_s", "lower", 0.5, "rel"),
]
# Alert count per detector (``alerts.by_detector``): a detector that silently stops (or starts flooding) shows up
# here even when the session-level rates stay at their ceiling.
PER_DETECTOR = MetricSpec("alerts.by_detector", "stable", 0.2, "rel", 2.0)
PER_PROFILE_TOLERANCE = 0.02

# comparability keys: a difference in any of these makes the two runs "not comparable".
STRICT_KEYS = (
    "dataset_sha256",
    "llm_provider",
    "detectors_enabled",
    "sigma_rules_loaded",
    "replay",
    "settings",
)
# Explanations only (the dataset identity is its sha256): shown when the datasets differ.
EXPLANATORY_KEYS = ("dataset_events", "dataset_generator_version", "dataset_seed", "dataset_mix")


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
    status: str  # improved / regressed / changed / unchanged / n/a


def _delta(name: str, a: Any, b: Any, spec: MetricSpec) -> Delta:
    if not isinstance(a, int | float) or not isinstance(b, int | float):
        return Delta(name, a, b, None, "n/a")
    delta = round(float(b) - float(a), 6)
    limit = max(spec.tolerance if spec.kind == "abs" else abs(float(a)) * spec.tolerance, spec.min_delta)
    if spec.direction == "stable":
        status = "changed" if abs(delta) > limit else "unchanged"
    else:
        worse = delta < -limit if spec.direction == "higher" else delta > limit
        better = delta > limit if spec.direction == "higher" else delta < -limit
        status = "regressed" if worse else ("improved" if better else "unchanged")
    return Delta(name, a, b, delta, status)


def _flatten(data: Any, prefix: str = "") -> dict[str, Any]:
    if not isinstance(data, dict):
        return {prefix: data}
    out: dict[str, Any] = {}
    for k, v in data.items():
        out.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    return out


def comparability_mismatches(current: dict[str, Any], previous: dict[str, Any]) -> list[str]:
    """Human-readable differences that make two runs not comparable (empty list: comparable)."""
    a, b = previous.get("comparability"), current.get("comparability")
    if not isinstance(a, dict) or not isinstance(b, dict):
        which = " and ".join(name for name, c in (("previous", a), ("current", b)) if not isinstance(c, dict))
        return [
            f"{which} run has no comparability record (metrics.json written before this check existed); "
            "re-run the baseline with this version"
        ]
    out: list[str] = []
    for key in STRICT_KEYS:
        va, vb = a.get(key), b.get(key)
        if va is None and vb is None:
            continue
        if key == "detectors_enabled" and isinstance(va, list) and isinstance(vb, list):
            added, removed = sorted(set(vb) - set(va)), sorted(set(va) - set(vb))
            if added or removed:
                out.append(f"detectors_enabled: +{added} -{removed}")
        elif isinstance(va, dict) and isinstance(vb, dict):
            fa, fb = _flatten(va), _flatten(vb)
            for k in sorted(set(fa) | set(fb)):
                if fa.get(k) != fb.get(k):
                    out.append(f"{key}.{k}: {fa.get(k)!r} -> {fb.get(k)!r}")
        elif va != vb:
            if key == "dataset_sha256":
                out.append(f"dataset_sha256: {str(va)[:12]} -> {str(vb)[:12]}")
                for ek in EXPLANATORY_KEYS:
                    if a.get(ek) != b.get(ek):
                        out.append(f"  ({ek}: {a.get(ek)!r} -> {b.get(ek)!r})")
            else:
                out.append(f"{key}: {va!r} -> {vb!r}")
    return out


def compare_runs(current: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    """Diff two runs (whole metrics.json documents; a bare ``metrics`` section is accepted but then cannot be
    checked for comparability)."""
    cur = current.get("metrics", current)
    prev = previous.get("metrics", previous)
    rows: list[Delta] = [
        _delta(spec.path, get_path(prev, spec.path), get_path(cur, spec.path), spec) for spec in KEY_METRICS
    ]
    det_prev = get_path(prev, PER_DETECTOR.path) or {}
    det_cur = get_path(cur, PER_DETECTOR.path) or {}
    if det_prev or det_cur:
        for det in sorted(set(det_prev) | set(det_cur)):
            # a detector absent on one side produced 0 alerts there
            rows.append(
                _delta(f"{PER_DETECTOR.path}[{det}]", det_prev.get(det, 0), det_cur.get(det, 0), PER_DETECTOR)
            )
    for profile in sorted(set(cur.get("per_profile", {})) | set(prev.get("per_profile", {}))):
        actor = (
            cur.get("per_profile", {}).get(profile) or prev.get("per_profile", {}).get(profile) or {}
        ).get("actor")
        direction = "lower" if actor == "benign" else "higher"
        path = f"per_profile.{profile}.detection_rate"
        spec = MetricSpec(path, direction, PER_PROFILE_TOLERANCE, "abs")
        rows.append(_delta(path, get_path(prev, path), get_path(cur, path), spec))
    for gen in sorted(set(cur.get("by_generator", {})) | set(prev.get("by_generator", {}))):
        for sub in ("attack_detection_medium_plus", "ai_recall"):
            path = f"by_generator.{gen}.{sub}.value"
            spec = MetricSpec(path, "higher", PER_PROFILE_TOLERANCE, "abs")
            rows.append(_delta(path, get_path(prev, path), get_path(cur, path), spec))
    regressions = [r.metric for r in rows if r.status in ("regressed", "changed")]
    mismatches = comparability_mismatches(current, previous)
    return {
        "previous_run": previous.get("run", {}).get("id"),
        "comparable": not mismatches,
        "mismatches": mismatches,
        "regressions": regressions,
        "has_regression": bool(regressions),
        "deltas": [r.__dict__ for r in rows],
    }


# exit codes of `tokiwa eval run --compare` / `tokiwa eval compare` with --fail-on-regression
EXIT_REGRESSION = 1
EXIT_NOT_COMPARABLE = 3


def comparison_summary(cmp_doc: dict[str, Any], *, allow_mismatch: bool = False) -> list[str]:
    """Lines for the CLI (shared by ``eval run --compare`` and ``eval compare``)."""
    lines: list[str] = []
    mismatches = cmp_doc.get("mismatches") or []
    if mismatches:
        head = "WARNING: runs are NOT COMPARABLE" + (
            " (compared anyway: --allow-mismatch)" if allow_mismatch else " (pass --allow-mismatch to accept)"
        )
        lines.append(head)
        lines += [f"  {m}" for m in mismatches]
    lines.append("regressions: " + (", ".join(cmp_doc.get("regressions") or []) or "none"))
    return lines


def comparison_exit_code(cmp_doc: dict[str, Any], *, fail_on_regression: bool, allow_mismatch: bool) -> int:
    """0 ok; 1 regression; 3 not comparable (only with --fail-on-regression, unless --allow-mismatch)."""
    if not fail_on_regression:
        return 0
    if cmp_doc.get("mismatches") and not allow_mismatch:
        return EXIT_NOT_COMPARABLE
    return EXIT_REGRESSION if cmp_doc.get("has_regression") else 0


def comparability_record(
    dataset: Path, opts: ReplayOptions, results: RunResults, *, n_events: int
) -> dict[str, Any]:
    """What must match for two runs to be compared (see module docstring). Stored as metrics.json ``comparability``."""
    meta: dict[str, Any] = {}
    mpath = meta_path(dataset)
    if mpath.is_file():
        try:
            loaded = json.loads(mpath.read_text(encoding="utf-8"))
            meta = loaded if isinstance(loaded, dict) else {}
        except (OSError, ValueError):
            meta = {}
    digest = hashlib.sha256()
    with dataset.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return {
        "schema": 1,
        "dataset_sha256": digest.hexdigest(),
        "dataset_events": n_events,
        "dataset_generator_version": meta.get("generator_version"),
        "dataset_seed": meta.get("seed"),
        "dataset_mix": meta.get("mix"),
        "llm_mode": opts.llm,
        "llm_provider": results.llm_provider,
        "detectors_enabled": sorted(results.detectors_enabled),
        "sigma_rules_loaded": results.sigma_rules_loaded,
        "replay": {
            "speed": opts.speed,
            "batch_window_seconds": opts.batch_window_seconds,
            "batch_size": opts.batch_size,
        },
        "settings": results.settings_snapshot,
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


def _ci(iv: dict[str, Any]) -> str:
    if not iv or iv.get("ci_low") is None:
        return "–"
    return f"{_pct(iv['ci_low'])} – {_pct(iv['ci_high'])}"


def _ref_note(iv: dict[str, Any]) -> str:
    notes = []
    if iv.get("reference_only"):
        notes.append("参考値 (n<30)")
    if iv.get("clustered"):
        notes.append("events clustered: CI too narrow")
    return "; ".join(notes)


def _rate_row(m: dict[str, Any], label: str, path: str) -> str:
    """One summary row: value, x/n, interval and the 参考値 marker (from ``metrics.intervals``)."""
    iv = (m.get("intervals") or {}).get(path)
    if not iv:  # metrics.json from before intervals existed
        return f"| {label} | {_pct(get_path(m, path))} | – | – | |"
    return f"| {label} | {_pct(iv['value'])} | {iv['x']} / {iv['n']} | {_ci(iv)} | {_ref_note(iv)} |"


def render_by_generator(m: dict[str, Any]) -> list[str]:
    """Scripted vs holdout vs imported sessions (#174)."""
    gens = m.get("by_generator") or {}
    if not gens:
        return []
    out = [
        "",
        "## By generator",
        "",
        "`scripted`: profiles that act out the detection hypotheses (detectors were tuned on them). `holdout` / `artex`:",
        "not used for tuning — read these as the generalisation estimate.",
        "",
        "| generator | sessions | attack detection medium+ | 95% CI | AI flagged / AI sessions | 95% CI | non-AI flagged AI | note |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for gen, row in gens.items():
        det, rec, fpr = row["attack_detection_medium_plus"], row["ai_recall"], row["ai_fpr"]
        ref = any(iv.get("reference_only") and iv.get("n") for iv in (det, rec, fpr))
        out.append(
            f"| {gen} | {row['sessions']} | {det['x']}/{det['n']} | {_ci(det)} | {rec['x']}/{rec['n']} | {_ci(rec)} "
            f"| {fpr['x']}/{fpr['n']} | {'参考値 (n<30)' if ref else ''} |"
        )
    per_profile = (m.get("ai_attribution") or {}).get("per_profile") or {}
    if per_profile:
        out += ["", "| profile | actor | holdout | sessions | flagged AI |", "|---|---|---|---|---|"]
        for name, row in per_profile.items():
            out.append(
                f"| {name} | {row['actor']} | {'yes' if row.get('holdout') else ''} | {row['sessions']} "
                f"| {row['predicted_ai']} ({_pct(row.get('predicted_ai_rate'))}) |"
            )
    return out


def render_comparison(cmp_doc: dict[str, Any]) -> list[str]:
    out = ["", f"## Regression check vs `{cmp_doc.get('previous_run')}`", ""]
    verdict = "REGRESSION" if cmp_doc["has_regression"] else "no regression"
    mismatches = cmp_doc.get("mismatches") or []
    if mismatches:
        verdict = f"NOT COMPARABLE ({verdict} by the numbers below, but the runs differ)"
        out += ["The two runs differ in what they replayed or how:", ""] + [f"- `{m}`" for m in mismatches]
        out.append("")
    out += [f"**{verdict}**", "", "| metric | previous | current | Δ | status |", "|---|---|---|---|---|"]
    for d in cmp_doc["deltas"]:
        if d["status"] == "n/a" and d["previous"] is None and d["current"] is None:
            continue
        out.append(
            f"| {d['metric']} | {_fmt(d['previous'])} | {_fmt(d['current'])} | {_fmt(d['delta'])} | {d['status']} |"
        )
    return out


def render_markdown(doc: dict[str, Any]) -> str:
    run, ds, m = doc.get("run", {}), doc.get("dataset", {}), doc["metrics"]
    ai, llm, cost, lat, al = (
        m["ai_attribution"],
        m["llm"],
        m["cost"],
        m["latency"],
        m["alerts"],
    )
    mock = cost.get("provider") == "mock"
    llm_tag = " — **mock: rule fallback, not LLM quality**" if mock else ""
    out: list[str] = [
        f"# TOKIWA evaluation report — {run.get('id', '')}",
        "",
        f"- dataset: `{run.get('dataset')}` ({ds.get('events')} events, {ds.get('sessions')} sessions)",
        f"- LLM: `{run.get('llm')}` (provider: {cost.get('provider')}), replay speed: {run.get('speed')}",
        f"- detectors enabled: {len(m['pipeline']['detectors_enabled'])} / registered: "
        f"{len(m['pipeline']['detectors_registered'])}; Sigma file rules loaded: "
        f"{_fmt(m['pipeline'].get('sigma_rules_loaded'))}; enrichers: {', '.join(m['pipeline']['enrichers']) or '–'}",
        "",
        "## Summary",
        "",
        "Rates with numerator/denominator and a 95 % Clopper–Pearson interval. **参考値** = fewer than 30 trials:",
        "the interval, not the point value, is what the data supports. The primary detection metric is medium+.",
        "",
        "| metric | value | x / n | 95% CI | note |",
        "|---|---|---|---|---|",
        _rate_row(
            m, "attack session detection, medium+ (primary)", "detection.attack_session_rate_medium_plus"
        ),
        _rate_row(m, "attack session detection, any severity (secondary)", "detection.attack_session_rate"),
        _rate_row(m, "benign session FPR, medium+", "detection.benign_session_fpr_medium_plus"),
        _rate_row(m, "benign session FPR, any severity", "detection.benign_session_fpr"),
        _rate_row(m, "event recall (lower bound)", "detection.event_recall"),
        _rate_row(m, "benign event FPR", "detection.event_fpr"),
        _rate_row(
            m,
            f"alert precision ({al['total']} alerts, {al['unattributed']} unattributed, "
            f"{al.get('attributed_by_ip_fallback', '–')} via source-IP fallback)",
            "alerts.precision",
        ),
        _rate_row(m, "AI attribution precision", "ai_attribution.precision"),
        _rate_row(m, "AI attribution recall", "ai_attribution.recall"),
        _rate_row(m, "AI attribution FPR (non-AI sessions flagged AI)", "ai_attribution.fpr"),
        f"| AI attribution F1 / ROC-AUC | {_fmt(ai['f1'])} / {_fmt(ai['auc'])} | "
        f"{ai.get('auc_positives', '–')} AI / {ai.get('auc_negatives', '–')} non-AI sessions | – | "
        f"{'参考値 (n<30)' if min(ai.get('auc_positives') or 0, ai.get('auc_negatives') or 0) < 30 else ''} |",
        _rate_row(m, f"LLM agreement: actor type{llm_tag}", "llm.actor_agreement"),
        _rate_row(m, f"LLM agreement: malicious verdict{llm_tag}", "llm.verdict_agreement"),
        _rate_row(m, f"LLM agreement: AI verdict{llm_tag}", "llm.ai_agreement"),
        "",
        "Event-level intervals assume independent events; events are clustered by session, so those two are too",
        "narrow. Source-IP fallback attribution relies on the simulator's one-address-per-session layout.",
        "",
        "## Cost and latency",
        "",
        "| metric | value |",
        "|---|---|",
        f"| LLM calls / triaged records | {cost['llm_calls']} / {llm['triaged']} |",
        f"| LLM cost actual total / per alert | ${_fmt(cost['cost_usd'])} / ${_fmt(cost['cost_per_alert_usd'])} |",
        *(
            [
                f"| LLM cost if these calls were live (estimate) | ~${_fmt(cost.get('estimated_cost_usd'))} "
                "(mock token estimates × price table; not measured) |"
            ]
            if cost.get("estimated_cost_usd") is not None
            else []
        ),
        f"| tokens per alert{' (estimated: chars/4, output 200)' if mock else ''} | {_fmt(cost['tokens_per_alert'])} |",
        f"| ingest→alert batch p50 / p95 | {_fmt(lat['batch_p50_ms'])} ms / {_fmt(lat['batch_p95_ms'])} ms |",
        f"| alert→triage p50 / p95 | {_fmt(lat['triage_p50_s'])} s / {_fmt(lat['triage_p95_s'])} s "
        f"(source: {lat['triage_source']}) |",
        f"| replay throughput | {_fmt(lat['throughput_eps'])} events/s |",
        "",
        "## Detection by profile",
        "",
        "| profile | actor | sessions | medium+ | medium+ 95% CI | any severity | alerts | note |",
        "|---|---|---|---|---|---|---|---|",
    ]
    ivs = m.get("intervals") or {}
    for name, row in m["per_profile"].items():
        iv = ivs.get(f"per_profile.{name}.detection_rate_medium_plus") or {}
        out.append(
            f"| {name} | {row['actor']} | {row['sessions']} | {row['detected_medium_plus']}"
            f" ({_pct(row.get('detection_rate_medium_plus'))}) | {_ci(iv)} | {row['detected']}"
            f" ({_pct(row['detection_rate'])}) | {row['alerts']} | {_ref_note(iv)} |"
        )
    out += render_by_generator(m)
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
    out += [
        "",
        "## Detectors",
        "",
        "| rule | alerts | hits | TP | FP | unattributed | via source-IP fallback | precision | actors |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in m["per_detector"]:
        actors = ", ".join(f"{k}:{v}" for k, v in r["actors"].items())
        out.append(
            f"| `{r['rule_id']}` | {r['alerts']} | {r['hits']} | {r['tp']} | {r['fp']} | {r['unattributed']} "
            f"| {r.get('ip_fallback', '–')} | {_pct(r['precision'])} | {actors} |"
        )
    if not m["per_detector"]:
        out.append("| (no alerts) | | | | | | | | |")
    out += [
        "",
        "## LLM (mock provider — rule-based fallback, NOT an LLM measurement)" if mock else "## LLM",
        "",
    ]
    if mock:
        out += [
            "> The mock provider answers triage with the rule-based fallback: `ai_agent_likelihood` copies the alert's",
            "> `ai_score`, so the agreement values above are the rules agreeing with themselves, and the triage score",
            "> adds no information to AI attribution. Not measured here: real LLM triage quality and mistakes,",
            "> refusals, robustness to prompt injection through telemetry, real cost / latency / budget behaviour.",
            "> Run `tokiwa eval run --llm live --budget-usd <cap>` for those.",
            "",
        ]
    out += [
        f"- calls: {cost['llm_calls']} by status {cost['by_status']} by purpose {cost['by_purpose']}",
        f"- tokens in/out{' (estimated)' if mock else ''}: {cost['input_tokens']} / {cost['output_tokens']}",
        f"- triage records by tier: {llm['by_tier']}"
        + (f" (tier the pipeline asked for: {llm.get('by_tier_requested')})" if mock else ""),
    ]
    est_by_model = cost.get("estimated_cost_by_model_usd") or {}
    if est_by_model:
        out += [
            "",
            "| model (would have been called) | calls | actual USD | estimated USD if live |",
            "|---|---|---|---|",
        ]
        calls_by_model = cost.get("by_model") or {}
        for model, usd in est_by_model.items():
            out.append(f"| `{model}` | {calls_by_model.get(model, '–')} | 0 | ~{_fmt(usd)} |")
        out += ["", f"Estimate basis: {cost.get('estimated_cost_basis')}."]
    cmp_doc = doc.get("comparison")
    if cmp_doc:
        out += render_comparison(cmp_doc)
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
    approx = sum(1 for e in events if e.labels.get("timing") == "approx")
    if approx:
        results.notes.append(
            f"{approx} event(s) have approximate timestamps (ARTEX import: 1 s resolution, response-completion "
            "time, spread evenly within a second): gap/burst rhythm features on them are importer artefacts"
        )
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
        "comparability": comparability_record(dataset, opts, results, n_events=len(events)),
        "metrics": compute_metrics(truth, results),
    }
    if compare is not None:
        doc["comparison"] = compare_runs(doc, load_metrics(compare))
    write_report(out_dir, doc)
    if not keep_work:
        shutil.rmtree(work, ignore_errors=True)
    return doc
