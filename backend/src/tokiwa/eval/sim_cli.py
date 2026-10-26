"""``tokiwa sim`` — lab traffic simulator.

    tokiwa sim profiles                                   list traffic profiles
    tokiwa sim run --profile ai_agent --target http://gate:8080      live traffic to a LAB target
    tokiwa sim generate --out eval/datasets/mix.jsonl     offline labelled dataset (no network)
    tokiwa sim ingest --server http://tokiwa:8788 --token-file /secrets/sim.token   synthetic events -> ingest API

Targets are restricted to localhost / private addresses / names resolving to them (AGENTS.md §2.7) unless
``--i-own-this-target`` is given. Payloads are inert detection-test strings.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path

import httpx
import typer

from tokiwa.eval.dataset import generate_events, split_truth, write_dataset
from tokiwa.eval.profiles import PROFILES, parse_mix
from tokiwa.eval.safety import TargetNotAllowedError, check_target
from tokiwa.eval.sim import DEFAULT_START, build_plans, exchanges_to_events, simulate_live
from tokiwa.util import utcnow

app = typer.Typer(
    help="Lab traffic simulator (lab targets only; harmless detection-test payloads)", no_args_is_help=True
)

_PROFILE_HELP = "Profile(s): name, comma list, name=count list, or 'mixed' (default mix of all five)"


def _mix(profile: str, sessions: int | None) -> dict[str, int]:
    try:
        return parse_mix(profile, default_count=sessions)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command("profiles")
def list_profiles() -> None:
    """List available traffic profiles."""
    for p in PROFILES.values():
        typer.echo(f"{p.name:18s} actor={p.actor:18s} {p.description}")


@app.command("run")
def run(
    profile: str = typer.Option("mixed", "--profile", "-p", help=_PROFILE_HELP),
    target: str = typer.Option("http://localhost:8080", "--target", "-t", help="Lab target (Gate) base URL"),
    sessions: int | None = typer.Option(
        None, help="Sessions per named profile (default 1; 'mixed' uses the mix)"
    ),
    seed: int = typer.Option(1, help="Random seed (reproducible traffic)"),
    time_scale: float = typer.Option(
        1.0, help="Multiply all pauses (0.1 = 10x faster; changes rhythm features)"
    ),
    spread: float = typer.Option(60.0, help="Seconds over which session start times are spread"),
    max_requests: int = typer.Option(2000, help="Hard cap on requests for the whole run"),
    max_rps: float = typer.Option(50.0, help="Global request rate cap"),
    spoof_xff: bool = typer.Option(
        False, help="Send X-Forwarded-For with a per-session documentation IP (lab Gate must trust XFF)"
    ),
    record: Path | None = typer.Option(None, help="Also write what was sent as a labelled dataset (JSONL)"),
    loop: bool = typer.Option(False, help="Repeat forever with seed+1 each round (Ctrl-C to stop)"),
    i_own_this_target: bool = typer.Option(
        False,
        "--i-own-this-target",
        help="Allow a non-private target. Only for systems you own and may test.",
    ),
) -> None:
    """Send simulated traffic to a lab target (default: the Gate in front of the lab victim)."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        check_target(target, allow_any=i_own_this_target)
    except TargetNotAllowedError as exc:
        typer.echo(f"refusing target: {exc}", err=True)
        raise typer.Exit(2) from exc
    mix = _mix(profile, sessions)
    round_no = 0
    while True:
        plans = build_plans(mix, seed=seed + round_no, spread_seconds=spread)
        typer.echo(f"round {round_no + 1}: {len(plans)} session(s) -> {target} (seed {seed + round_no})")
        exchanges = asyncio.run(
            simulate_live(
                plans,
                target=target,
                allow_any_target=i_own_this_target,
                time_scale=time_scale,
                max_requests=max_requests,
                max_rps=max_rps,
                spoof_xff=spoof_xff,
            )
        )
        errors = sum(1 for e in exchanges if e.response.error)
        typer.echo(f"sent {len(exchanges)} request(s), transport errors: {errors}")
        if record is not None:
            out = record if not loop else record.with_name(f"{record.stem}-r{round_no + 1}{record.suffix}")
            events = exchanges_to_events(exchanges, seed=seed + round_no)
            write_dataset(
                out, events, {"mode": "live", "target": target, "seed": seed + round_no, "mix": mix}
            )
            typer.echo(f"recorded {len(events)} labelled event(s) -> {out}")
        round_no += 1
        if not loop:
            break


@app.command("generate")
def generate(
    out: Path = typer.Option(..., "--out", "-o", help="Output JSONL (eval/datasets/<name>.jsonl)"),
    profile: str = typer.Option("mixed", "--profile", "--profiles", "-p", help=_PROFILE_HELP),
    sessions: int | None = typer.Option(
        None, help="Sessions per named profile (default 1; 'mixed' uses the mix)"
    ),
    seed: int = typer.Option(1, help="Random seed (same seed + options -> byte-identical file)"),
    start: str = typer.Option(DEFAULT_START.isoformat(), help="Timestamp of the dataset start (ISO 8601)"),
    spread: float = typer.Option(1800.0, help="Seconds over which session start times are spread"),
    no_canary: bool = typer.Option(False, help="Model the victim without its AI canary (LAB_AI_CANARY=0)"),
) -> None:
    """Generate a labelled dataset offline (simulator + virtual victim; no network)."""
    mix = _mix(profile, sessions)
    events = asyncio.run(
        generate_events(
            mix, seed=seed, start=datetime.fromisoformat(start), spread_seconds=spread, canary=not no_canary
        )
    )
    info = write_dataset(
        out,
        events,
        {
            "mode": "offline",
            "seed": seed,
            "mix": mix,
            "start": start,
            "spread": spread,
            "canary": not no_canary,
        },
    )
    s = info["summary"]
    typer.echo(f"wrote {s['events']} events / {s['sessions']} sessions -> {out}")
    typer.echo(json.dumps(s["sessions_by_profile"], ensure_ascii=False))


@app.command("ingest")
def ingest(
    server: str = typer.Option("http://localhost:8788", help="TOKIWA server base URL (lab only)"),
    token: str | None = typer.Option(None, envvar="TOKIWA_SIM_TOKEN", help="Ingest API token (scope ingest)"),
    token_file: Path | None = typer.Option(None, help="Read the ingest token from a file"),
    profile: str = typer.Option("mixed", "--profile", "-p", help=_PROFILE_HELP),
    sessions: int | None = typer.Option(None),
    seed: int = typer.Option(1),
    batch_size: int = typer.Option(200, help="Events per ingest request (<= 5000)"),
    keep_labels: bool = typer.Option(
        False, help="Send ground-truth labels too (debug only: detectors could see them)"
    ),
    i_own_this_target: bool = typer.Option(False, "--i-own-this-target"),
) -> None:
    """Generate events offline and push them straight to the ingest API (no Gate needed). Timestamps end now."""
    try:
        base = check_target(server, allow_any=i_own_this_target)
    except TargetNotAllowedError as exc:
        typer.echo(f"refusing server: {exc}", err=True)
        raise typer.Exit(2) from exc
    secret = token or (token_file.read_text(encoding="utf-8").strip() if token_file else None)
    if not secret:
        typer.echo("an ingest token is required (--token, --token-file or TOKIWA_SIM_TOKEN)", err=True)
        raise typer.Exit(2)
    events = asyncio.run(generate_events(_mix(profile, sessions), seed=seed))
    if not keep_labels:
        events, _ = split_truth(events)
    shift = utcnow() - max(e.timestamp for e in events)
    for e in events:
        e.timestamp += shift

    async def push() -> tuple[int, int]:
        accepted = alerts = 0
        async with httpx.AsyncClient(base_url=base, timeout=30.0, trust_env=False) as client:
            for i in range(0, len(events), batch_size):
                chunk = events[i : i + batch_size]
                r = await client.post(
                    "/api/v1/ingest/events",
                    json={"events": [e.model_dump(mode="json", exclude_none=True) for e in chunk]},
                    headers={"X-Tokiwa-Token": secret},
                )
                r.raise_for_status()
                body = r.json()
                accepted += int(body.get("accepted", 0))
                alerts += int(body.get("alerts", 0))
        return accepted, alerts

    accepted, alerts = asyncio.run(push())
    typer.echo(f"ingested {accepted} events, {alerts} new alert(s)")
