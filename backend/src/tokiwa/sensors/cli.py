"""``tokiwa agent`` sub-commands (attached by ``tokiwa.cli``).

    tokiwa agent run  [--server-url URL] [--nginx PATH ...] [--zeek-dir DIR ...] ...
    tokiwa agent once --print          collect once and print the events as JSON (debugging)

Defaults come from ``AgentSettings`` (``TOKIWA_AGENT__*`` env vars / ``tokiwa.yaml``); options override them.
Keep this module import-light: ``tokiwa.cli`` imports it on every invocation of ``tokiwa``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import signal
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer

if TYPE_CHECKING:
    from tokiwa.config import AgentSettings
    from tokiwa.schemas.events import Event

app = typer.Typer(help="TOKIWA Agent: host sensor (ports/connections) and log shipper", no_args_is_help=True)

_OPT_SERVER = typer.Option(None, "--server-url", help="TOKIWA server base URL")
_OPT_TOKEN = typer.Option(
    None,
    "--token",
    help="Ingest API token. Prefer TOKIWA_AGENT__INGEST_TOKEN: command-line arguments are visible to other users.",
)
_OPT_SENSOR = typer.Option(None, "--sensor-id", help="Sensor id (default: hostname)")
_OPT_INTERVAL = typer.Option(None, "--interval", help="Host sensor interval in seconds")
_OPT_HOST = typer.Option(None, "--host-sensor/--no-host-sensor", help="Collect listening ports / connections")
_OPT_CONNS = typer.Option(None, "--connections/--no-connections", help="Report new TCP connections")
_OPT_NGINX = typer.Option(None, "--nginx", help="nginx JSON access log (repeatable)")
_OPT_CADDY = typer.Option(None, "--caddy", help="Caddy JSON access log (repeatable)")
_OPT_SURICATA = typer.Option(None, "--suricata", help="Suricata eve.json (repeatable)")
_OPT_ZEEK = typer.Option(None, "--zeek-dir", help="Zeek log directory or single log file (repeatable)")


def build_settings(
    *,
    server_url: str | None = None,
    token: str | None = None,
    sensor_id: str | None = None,
    interval: float | None = None,
    host_sensor: bool | None = None,
    connections: bool | None = None,
    nginx: list[Path] | None = None,
    caddy: list[Path] | None = None,
    suricata: list[Path] | None = None,
    zeek_dir: list[Path] | None = None,
    from_beginning: bool | None = None,
) -> AgentSettings:
    """AgentSettings from config, with CLI options (when given) taking precedence."""
    from pydantic import SecretStr

    from tokiwa.config import get_settings

    update: dict[str, Any] = {}
    for key, value in (
        ("server_url", server_url),
        ("sensor_id", sensor_id),
        ("interval_seconds", interval),
        ("host_sensor", host_sensor),
        ("connections", connections),
    ):
        if value is not None:
            update[key] = value
    if token:
        update["ingest_token"] = SecretStr(token)
    for key, paths in (
        ("nginx_json_logs", nginx),
        ("caddy_json_logs", caddy),
        ("suricata_eve_logs", suricata),
        ("zeek_log_dirs", zeek_dir),
    ):
        if paths:
            update[key] = list(paths)
    if from_beginning is not None:
        update["log_start_at"] = "beginning" if from_beginning else "end"
    return get_settings().agent.model_copy(update=update)


def _setup_logging() -> None:
    from tokiwa.config import get_settings

    logging.basicConfig(
        level=get_settings().log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


async def _run(cfg: AgentSettings) -> None:
    from tokiwa.sensors.agent import Agent

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError):  # Windows has no signal handlers
            loop.add_signal_handler(sig, stop.set)
    await Agent(cfg).run(stop)


@app.command()
def run(
    server_url: str | None = _OPT_SERVER,
    token: str | None = _OPT_TOKEN,
    sensor_id: str | None = _OPT_SENSOR,
    interval: float | None = _OPT_INTERVAL,
    host_sensor: bool | None = _OPT_HOST,
    connections: bool | None = _OPT_CONNS,
    nginx: list[Path] | None = _OPT_NGINX,
    caddy: list[Path] | None = _OPT_CADDY,
    suricata: list[Path] | None = _OPT_SURICATA,
    zeek_dir: list[Path] | None = _OPT_ZEEK,
    from_beginning: bool | None = typer.Option(
        None, "--from-beginning/--from-end", help="Where log tailing starts (default: end)"
    ),
) -> None:
    """Run the agent until interrupted (SIGINT/SIGTERM flush the buffer before exit)."""
    _setup_logging()
    cfg = build_settings(
        server_url=server_url,
        token=token,
        sensor_id=sensor_id,
        interval=interval,
        host_sensor=host_sensor,
        connections=connections,
        nginx=nginx,
        caddy=caddy,
        suricata=suricata,
        zeek_dir=zeek_dir,
        from_beginning=from_beginning,
    )
    asyncio.run(_run(cfg))


async def _collect_once(cfg: AgentSettings, max_events: int) -> list[Event]:
    from tokiwa.sensors.agent import Agent

    agent = Agent(cfg, start_at="beginning")
    try:
        events = await agent.collect()
    finally:
        for src in agent.sources:
            src.close()
    return events[:max_events]


async def _ship_once(cfg: AgentSettings, events: list[Event]) -> tuple[int, int]:
    from tokiwa.sensors.agent import Agent

    shipper = Agent(cfg, sources=[]).shipper
    try:
        shipper.submit(events)
        sent = await shipper.flush(force=True)
        return sent, shipper.pending
    finally:
        await shipper.aclose()


@app.command()
def once(
    print_json: bool = typer.Option(False, "--print", help="Print events as JSON instead of sending them"),
    max_events: int = typer.Option(1000, "--max-events", help="Cap on events collected"),
    server_url: str | None = _OPT_SERVER,
    token: str | None = _OPT_TOKEN,
    sensor_id: str | None = _OPT_SENSOR,
    host_sensor: bool | None = _OPT_HOST,
    connections: bool | None = _OPT_CONNS,
    nginx: list[Path] | None = _OPT_NGINX,
    caddy: list[Path] | None = _OPT_CADDY,
    suricata: list[Path] | None = _OPT_SURICATA,
    zeek_dir: list[Path] | None = _OPT_ZEEK,
) -> None:
    """Collect once (host sensor + logs read from the beginning) and print or send the events."""
    cfg = build_settings(
        server_url=server_url,
        token=token,
        sensor_id=sensor_id,
        host_sensor=host_sensor,
        connections=connections,
        nginx=nginx,
        caddy=caddy,
        suricata=suricata,
        zeek_dir=zeek_dir,
    )
    events = asyncio.run(_collect_once(cfg, max_events))
    if print_json:
        docs = [e.model_dump(mode="json", exclude_none=True) for e in events]
        typer.echo(json.dumps(docs, ensure_ascii=False, indent=2))
        return
    _setup_logging()
    sent, pending = asyncio.run(_ship_once(cfg, events))
    typer.echo(f"collected {len(events)} events, sent {sent}, not delivered {pending}")
    if pending:
        raise typer.Exit(code=1)
