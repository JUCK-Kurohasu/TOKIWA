"""``tokiwa eval`` — evaluation harness.

    tokiwa eval run --dataset eval/datasets/lab-mini.jsonl [--llm mock|live] [--out eval/runs/<ts>]
                    [--compare eval/runs/<prev>] [--fail-on-regression] [--allow-mismatch]
    tokiwa eval compare <run-or-metrics.json> <previous-run-or-metrics.json> [--fail-on-regression]
                        [--allow-mismatch]
    tokiwa eval import-artex <artex traffic> --out eval/datasets/artex-<name>.jsonl [--host gate]
                             [--since T] [--until T] [--split-gap-minutes 30]
    tokiwa eval info <dataset.jsonl>

``--llm live`` calls the configured real LLM (cost!). It requires an explicit ``--budget-usd`` which becomes the
daily budget of the throw-away eval database, i.e. a hard cap for this run.

Exit codes with ``--fail-on-regression``: 1 = regression, 3 = the two runs are not comparable (different dataset,
LLM provider, detectors, Sigma rules, thresholds or batching; see ``report.comparability_mismatches``) — pass
``--allow-mismatch`` to compare them anyway.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import typer

from tokiwa.eval.artex import (
    DEFAULT_SOURCE_IP,
    ArtexImportError,
    ImportStats,
    import_artex,
    parse_time_bound,
)
from tokiwa.eval.dataset import dataset_summary, read_dataset, write_dataset
from tokiwa.eval.harness import EvalError, ReplayOptions
from tokiwa.eval.report import (
    compare_runs,
    comparison_exit_code,
    comparison_summary,
    load_metrics,
    run_evaluation,
)
from tokiwa.util import utcnow

app = typer.Typer(
    help="Evaluation harness: replay labelled datasets through the pipeline and score them",
    no_args_is_help=True,
)


def default_runs_dir() -> Path:
    """``eval/runs`` at the repository root whether invoked from the root or from ``backend/``."""
    for base in (Path("eval"), Path("../eval")):
        if base.is_dir():
            return base / "runs"
    return Path("eval/runs")


def _rate(intervals: dict[str, dict[str, object]], path: str) -> str:
    """``5/5 [95% CI 0.478-1]*`` (``*`` = n < 30, reference only)."""
    iv = intervals.get(path)
    if not iv or not iv.get("n"):
        return "-"
    star = "*" if iv.get("reference_only") else ""
    return f"{iv['x']}/{iv['n']} [95% CI {iv['ci_low']:.3g}-{iv['ci_high']:.3g}]{star}"


def _overrides(enable: list[str], disable: list[str]) -> dict[str, bool]:
    out = dict.fromkeys(enable, True)
    out.update(dict.fromkeys(disable, False))
    return out


@app.command("run")
def run(
    dataset: Path = typer.Option(
        ..., "--dataset", "-d", exists=True, dir_okay=False, help="Labelled JSONL dataset"
    ),
    llm: str = typer.Option(
        "mock", "--llm", help="mock (offline, free) or live (configured provider, costs money)"
    ),
    out: Path | None = typer.Option(
        None, "--out", "-o", help="Run directory (default eval/runs/<UTC timestamp>)"
    ),
    compare: Path | None = typer.Option(
        None, "--compare", help="Previous run dir or metrics.json to diff against"
    ),
    fail_on_regression: bool = typer.Option(
        False, help="Exit 1 when --compare finds a regression (3 when the runs are not comparable)"
    ),
    allow_mismatch: bool = typer.Option(
        False, help="Give a regression verdict even when the runs differ in dataset/LLM/detectors/settings"
    ),
    speed: float = typer.Option(0.0, help="0 = as fast as possible, 1 = real time, 10 = 10x faster"),
    batch_size: int = typer.Option(100, help="Max events per ingest batch (Gate default 100)"),
    enable_detector: list[str] = typer.Option([], "--enable-detector", help="Force-enable a detector id"),
    disable_detector: list[str] = typer.Option([], "--disable-detector", help="Force-disable a detector id"),
    budget_usd: float | None = typer.Option(None, help="Required with --llm live: hard USD cap for this run"),
    keep_work: bool = typer.Option(False, help="Keep the throw-away eval DB under <out>/work"),
    as_json: bool = typer.Option(False, "--json", help="Print metrics JSON instead of a summary"),
) -> None:
    """Replay a dataset through enrich -> detect -> correlate -> triage and write metrics.json + report.md."""
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    if llm not in ("mock", "live"):
        raise typer.BadParameter("--llm must be mock or live")
    if llm == "live" and budget_usd is None:
        typer.echo(
            "--llm live calls a paid API: pass --budget-usd <cap> to confirm the spending limit", err=True
        )
        raise typer.Exit(2)
    out_dir = out or default_runs_dir() / utcnow().strftime("%Y%m%dT%H%M%SZ")
    opts = ReplayOptions(
        llm=llm,  # type: ignore[arg-type]
        speed=speed,
        batch_size=batch_size,
        detector_overrides=_overrides(enable_detector, disable_detector),
        budget_usd=budget_usd,
    )
    try:
        doc = asyncio.run(run_evaluation(dataset, out_dir, opts, compare=compare, keep_work=keep_work))
    except EvalError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from exc
    m = doc["metrics"]
    if as_json:
        typer.echo(json.dumps(m, ensure_ascii=False, indent=2, default=str))
    else:
        ivs = m.get("intervals") or {}
        typer.echo(f"report: {out_dir / 'report.md'}")
        typer.echo(
            "attack sessions detected (medium+) "
            + _rate(ivs, "detection.attack_session_rate_medium_plus")
            + ", any severity "
            + _rate(ivs, "detection.attack_session_rate")
        )
        typer.echo(
            "benign session FPR (medium+) "
            + _rate(ivs, "detection.benign_session_fpr_medium_plus")
            + ", any severity "
            + _rate(ivs, "detection.benign_session_fpr")
            + f"; alerts {m['alerts']['total']} (precision {m['alerts']['precision']}, "
            f"{m['alerts'].get('attributed_by_ip_fallback', 0)} via source-IP fallback)"
        )
        typer.echo(
            "AI attribution precision "
            + _rate(ivs, "ai_attribution.precision")
            + ", recall "
            + _rate(ivs, "ai_attribution.recall")
            + f", AUC {m['ai_attribution']['auc']}"
        )
        if any(iv.get("reference_only") for iv in ivs.values()):
            typer.echo("(*) n < 30: reference value only — read the 95% interval, not the point value")
        cost = m["cost"]
        if cost.get("provider") == "mock":
            typer.echo(
                f"LLM: mock provider = rule-based fallback; LLM agreement/triage values are NOT LLM quality. "
                f"calls {cost['llm_calls']}, actual $0, ~${cost.get('estimated_cost_usd')} if live "
                "(estimated tokens x price table)"
            )
        else:
            typer.echo(f"LLM ({cost.get('provider')}): calls {cost['llm_calls']} cost ${cost['cost_usd']}")
        for note in m["pipeline"]["notes"]:
            typer.echo(f"note: {note}")
    cmp_doc = doc.get("comparison")
    if cmp_doc:
        for line in comparison_summary(cmp_doc, allow_mismatch=allow_mismatch):
            typer.echo(line)
        code = comparison_exit_code(
            cmp_doc, fail_on_regression=fail_on_regression, allow_mismatch=allow_mismatch
        )
        if code:
            raise typer.Exit(code)


@app.command("compare")
def compare_cmd(
    current: Path = typer.Argument(..., exists=True, help="Run dir or metrics.json"),
    previous: Path = typer.Argument(..., exists=True, help="Baseline run dir or metrics.json"),
    fail_on_regression: bool = typer.Option(
        False, help="Exit 1 when a regression is found (3 when the runs are not comparable)"
    ),
    allow_mismatch: bool = typer.Option(
        False, help="Give a regression verdict even when the runs differ in dataset/LLM/detectors/settings"
    ),
) -> None:
    """Diff the key metrics of two runs (after checking that they are comparable)."""
    result = compare_runs(load_metrics(current), load_metrics(previous))
    for d in result["deltas"]:
        if d["status"] != "n/a":
            typer.echo(f"{d['status']:10s} {d['metric']:48s} {d['previous']} -> {d['current']}")
    for line in comparison_summary(result, allow_mismatch=allow_mismatch):
        typer.echo(line)
    code = comparison_exit_code(result, fail_on_regression=fail_on_regression, allow_mismatch=allow_mismatch)
    if code:
        raise typer.Exit(code)


@app.command("import-artex")
def import_artex_cmd(
    source: Path = typer.Argument(
        ...,
        exists=True,
        help="traffic.json / extracted task archive dir / evidence .zip / index.sqlite / API dump",
    ),
    out: Path = typer.Option(..., "--out", "-o", help="Output dataset JSONL"),
    host: str | None = typer.Option(None, help="Only exchanges for this target host (e.g. the lab Gate)"),
    session: str | None = typer.Option(None, help="Session label (default artex:<host>)"),
    source_ip: str = typer.Option(
        DEFAULT_SOURCE_IP, help="Synthetic source IP (ARTEX does not record its own)"
    ),
    since: str | None = typer.Option(
        None, help="Keep exchanges at/after this time (unix seconds or ISO 8601; UTC if no offset)"
    ),
    until: str | None = typer.Option(None, help="Keep exchanges at/before this time (same formats)"),
    split_gap_minutes: float | None = typer.Option(
        None,
        help="Start a new session (own label #n and source IP) after this many silent minutes, per host. "
        "ARTEX archives are per host, so separate tasks would otherwise merge into one session",
    ),
) -> None:
    """Convert ARTEX recorded traffic into a labelled dataset (actor=ai_agent) for `tokiwa eval run`."""
    stats = ImportStats()
    try:
        events = import_artex(
            source,
            source_ip=source_ip,
            session=session,
            host=host,
            since=parse_time_bound(since) if since else None,
            until=parse_time_bound(until) if until else None,
            split_gap_seconds=split_gap_minutes * 60 if split_gap_minutes else None,
            stats=stats,
        )
    except (ArtexImportError, ValueError, OSError) as exc:
        typer.echo(f"import failed: {exc}", err=True)
        raise typer.Exit(2) from exc
    if not events:
        for line in _empty_import_hints(stats, host):
            typer.echo(line, err=True)
        raise typer.Exit(1)
    meta = {
        "mode": "artex-import",
        "source": str(source),
        "host": host,
        "since": since,
        "until": until,
        "split_gap_minutes": split_gap_minutes,
        "timing": "approx (1 s resolution, response-completion time)",
    }
    write_dataset(out, events, meta)
    typer.echo(f"imported {len(events)} exchange(s) in {len(stats.sessions)} session(s) -> {out}")
    for label, count in sorted(stats.sessions.items()):
        typer.echo(f"  {label}: {count}")
    typer.echo(
        "note: ARTEX timestamps are approximate; rhythm (gap/burst) features of this data are importer artefacts"
    )


def _empty_import_hints(stats: ImportStats, host: str | None) -> list[str]:
    """Different causes need different advice: nothing recorded vs. a filter that removed everything."""
    if stats.read == 0:
        return [
            "no exchanges found in the ARTEX source.",
            "hint: ARTEX records target traffic only while traffic recording is ON (system setting "
            "traffic_capture, default OFF; LLM records: llm_record). It may have been OFF during the task — "
            "enable it before creating the task (docs/purple-team.md §2).",
        ]
    if stats.after_host == 0:
        seen = ", ".join(f"{h} ({n})" for h, n in stats.hosts_seen.most_common(10))
        return [f"no exchanges for --host {host!r}; hosts in the source: {seen}"]
    lines = ["no exchanges inside --since/--until"]
    if stats.first_ts is not None and stats.last_ts is not None:
        lines.append(f"source covers {_utc(stats.first_ts)} .. {_utc(stats.last_ts)} (UTC, response times)")
    if stats.no_timestamp:
        lines.append(f"{stats.no_timestamp} exchange(s) had no timestamp and were dropped by the time filter")
    return lines


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds")


@app.command("info")
def info(dataset: Path = typer.Argument(..., exists=True, dir_okay=False)) -> None:
    """Print a dataset summary (events / sessions by profile and attack label)."""
    typer.echo(json.dumps(dataset_summary(read_dataset(dataset)), ensure_ascii=False, indent=2))
