"""``tokiwa eval`` — evaluation harness.

    tokiwa eval run --dataset eval/datasets/lab-mini.jsonl [--llm mock|live] [--out eval/runs/<ts>]
                    [--compare eval/runs/<prev>] [--fail-on-regression]
    tokiwa eval compare <run-or-metrics.json> <previous-run-or-metrics.json>
    tokiwa eval import-artex <artex traffic> --out eval/datasets/artex-<name>.jsonl [--host gate]
    tokiwa eval info <dataset.jsonl>

``--llm live`` calls the configured real LLM (cost!). It requires an explicit ``--budget-usd`` which becomes the
daily budget of the throw-away eval database, i.e. a hard cap for this run.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import typer

from tokiwa.eval.artex import DEFAULT_SOURCE_IP, ArtexImportError, import_artex
from tokiwa.eval.dataset import dataset_summary, read_dataset, write_dataset
from tokiwa.eval.harness import EvalError, ReplayOptions
from tokiwa.eval.report import compare_runs, load_metrics, run_evaluation
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
    fail_on_regression: bool = typer.Option(False, help="Exit 1 when --compare finds a regression"),
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
        d, ai = m["detection"], m["ai_attribution"]
        typer.echo(f"report: {out_dir / 'report.md'}")
        typer.echo(
            f"attack sessions detected {d['attack_sessions_detected']}/{d['attack_sessions']} "
            f"(rate {d['attack_session_rate']}), benign FPR {d['benign_session_fpr']}, "
            f"alerts {m['alerts']['total']} (precision {m['alerts']['precision']})"
        )
        typer.echo(
            f"AI attribution P={ai['precision']} R={ai['recall']} AUC={ai['auc']}; "
            f"LLM calls {m['cost']['llm_calls']} cost ${m['cost']['cost_usd']}"
        )
        for note in m["pipeline"]["notes"]:
            typer.echo(f"note: {note}")
    cmp_doc = doc.get("comparison")
    if cmp_doc:
        typer.echo("regressions: " + (", ".join(cmp_doc["regressions"]) or "none"))
        if fail_on_regression and cmp_doc["has_regression"]:
            raise typer.Exit(1)


@app.command("compare")
def compare_cmd(
    current: Path = typer.Argument(..., exists=True, help="Run dir or metrics.json"),
    previous: Path = typer.Argument(..., exists=True, help="Baseline run dir or metrics.json"),
    fail_on_regression: bool = typer.Option(False, help="Exit 1 when a regression is found"),
) -> None:
    """Diff the key metrics of two runs."""
    result = compare_runs(load_metrics(current), load_metrics(previous))
    for d in result["deltas"]:
        if d["status"] != "n/a":
            typer.echo(f"{d['status']:10s} {d['metric']:48s} {d['previous']} -> {d['current']}")
    typer.echo("regressions: " + (", ".join(result["regressions"]) or "none"))
    if fail_on_regression and result["has_regression"]:
        raise typer.Exit(1)


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
) -> None:
    """Convert ARTEX recorded traffic into a labelled dataset (actor=ai_agent) for `tokiwa eval run`."""
    try:
        events = import_artex(source, source_ip=source_ip, session=session, host=host)
    except (ArtexImportError, ValueError, OSError) as exc:
        typer.echo(f"import failed: {exc}", err=True)
        raise typer.Exit(2) from exc
    if not events:
        typer.echo("no exchanges found", err=True)
        raise typer.Exit(1)
    write_dataset(out, events, {"mode": "artex-import", "source": str(source), "host": host})
    typer.echo(f"imported {len(events)} exchange(s) -> {out}")


@app.command("info")
def info(dataset: Path = typer.Argument(..., exists=True, dir_okay=False)) -> None:
    """Print a dataset summary (events / sessions by profile and attack label)."""
    typer.echo(json.dumps(dataset_summary(read_dataset(dataset)), ensure_ascii=False, indent=2))
