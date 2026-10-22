"""``tokiwa gate run`` -- start the reverse-proxy sensor / enforcer as its own process.

Settings resolution: CLI flag > ``TOKIWA_GATE__*`` env / ``tokiwa.yaml`` (``GateSettings``) > defaults.
Prefer ``TOKIWA_GATE__INGEST_TOKEN`` or ``--token-file`` over ``--token``: command lines are visible to every
local user via ``ps``.
"""

from __future__ import annotations

import logging
from pathlib import Path

import typer
from pydantic import SecretStr

from tokiwa.config import GateSettings, get_settings

app = typer.Typer(help="TOKIWA Gate: reverse-proxy sensor / enforcer", no_args_is_help=True)


def parse_listen(value: str, default_host: str, default_port: int) -> tuple[str, int]:
    """``0.0.0.0:8080`` / ``[::]:8080`` / ``:8080`` / ``8080`` / ``localhost`` -> (host, port)."""
    v = value.strip()
    if not v:
        return default_host, default_port
    if v.startswith("["):
        host, _, rest = v[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port) if port else default_port
    if v.isdigit():
        return default_host, int(v)
    if v.count(":") == 1:
        host, port = v.split(":")
        return host or default_host, int(port) if port else default_port
    if ":" in v:  # bare IPv6 without port
        return v, default_port
    return v, default_port


def resolve_settings(
    base: GateSettings,
    *,
    upstream: str | None = None,
    listen: str | None = None,
    server: str | None = None,
    token: str | None = None,
    token_file: Path | None = None,
    sensor_id: str | None = None,
    capture_body_bytes: int | None = None,
    trust_forwarded_for: bool | None = None,
    policy_refresh: float | None = None,
    batch_size: int | None = None,
    flush_interval: float | None = None,
) -> GateSettings:
    update: dict[str, object] = {}
    if upstream:
        update["upstream"] = upstream
    if listen:
        host, port = parse_listen(listen, base.listen_host, base.listen_port)
        update["listen_host"], update["listen_port"] = host, port
    if server:
        update["server_url"] = server
    if token_file is not None:
        update["ingest_token"] = SecretStr(token_file.read_text(encoding="utf-8").strip())
    if token:
        update["ingest_token"] = SecretStr(token)
    if sensor_id:
        update["sensor_id"] = sensor_id
    if capture_body_bytes is not None:
        update["capture_body_bytes"] = max(0, capture_body_bytes)
    if trust_forwarded_for is not None:
        update["trust_forwarded_for"] = trust_forwarded_for
    if policy_refresh is not None:
        update["policy_refresh_seconds"] = policy_refresh
    if batch_size is not None:
        update["batch_size"] = batch_size
    if flush_interval is not None:
        update["flush_interval_seconds"] = flush_interval
    return base.model_copy(update=update)


@app.command("run")
def run(
    upstream: str | None = typer.Option(None, help="Upstream base URL, e.g. http://127.0.0.1:3000"),
    listen: str | None = typer.Option(None, help="Listen address host:port (default 0.0.0.0:8080)"),
    server: str | None = typer.Option(None, help="TOKIWA server URL, e.g. http://127.0.0.1:8788"),
    token: str | None = typer.Option(None, help="API token (scopes ingest+gate). Prefer --token-file / env"),
    token_file: Path | None = typer.Option(None, help="File containing the API token"),
    sensor_id: str | None = typer.Option(None, help="Sensor id recorded on events (default gate-1)"),
    capture_body_bytes: int | None = typer.Option(None, help="Request body prefix to capture (bytes)"),
    trust_forwarded_for: bool | None = typer.Option(
        None,
        "--trust-forwarded-for/--no-trust-forwarded-for",
        help="Use the right-most X-Forwarded-For entry as client IP (only behind a trusted proxy)",
    ),
    policy_refresh: float | None = typer.Option(None, help="Policy refresh interval (seconds)"),
    batch_size: int | None = typer.Option(None, help="Events per ingest batch"),
    flush_interval: float | None = typer.Option(None, help="Max seconds between ingest flushes"),
    upstream_timeout: float = typer.Option(30.0, help="Upstream read/write timeout (seconds)"),
    max_queue: int = typer.Option(10_000, help="Max buffered events before dropping the oldest"),
    preserve_host: bool = typer.Option(
        True,
        "--preserve-host/--rewrite-host",
        help="Forward the client Host header (default) or the upstream's",
    ),
    access_log: bool = typer.Option(False, help="Enable uvicorn access log (the gate captures anyway)"),
    log_level: str | None = typer.Option(None, help="Log level (default from TOKIWA_LOG_LEVEL)"),
) -> None:
    """Run TOKIWA Gate in front of an upstream web app."""
    import uvicorn

    from tokiwa.gate.app import GateOptions, create_gate_app

    s = get_settings()
    level = (log_level or s.log_level).upper()
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    gate_settings = resolve_settings(
        s.gate,
        upstream=upstream,
        listen=listen,
        server=server,
        token=token,
        token_file=token_file,
        sensor_id=sensor_id,
        capture_body_bytes=capture_body_bytes,
        trust_forwarded_for=trust_forwarded_for,
        policy_refresh=policy_refresh,
        batch_size=batch_size,
        flush_interval=flush_interval,
    )
    options = GateOptions(upstream_timeout=upstream_timeout, max_queue=max_queue, preserve_host=preserve_host)
    asgi_app = create_gate_app(gate_settings, options=options, redaction=s.llm.redaction)
    typer.echo(
        f"TOKIWA Gate {gate_settings.sensor_id}: http://{gate_settings.listen_host}:{gate_settings.listen_port}"
        f" -> {gate_settings.upstream} (server {gate_settings.server_url})"
    )
    uvicorn.run(
        asgi_app,
        host=gate_settings.listen_host,
        port=gate_settings.listen_port,
        log_level=level.lower(),
        access_log=access_log,
        # The gate decides itself whether to trust X-Forwarded-For (trust_forwarded_for).
        proxy_headers=False,
        # Upstream's Server/Date headers are forwarded; uvicorn's would duplicate them.
        server_header=False,
        date_header=False,
        lifespan="on",
    )
