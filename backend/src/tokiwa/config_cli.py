"""``tokiwa config show``: the effective configuration, secrets masked, with the source of every value (audit #161).

Builds :class:`~tokiwa.config.Settings` directly instead of through ``get_settings()`` so it keeps working when
``TOKIWA_STRICT_CONFIG=1`` would refuse startup - it is the tool for finding out why.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import typer
from pydantic import ValidationError

from tokiwa.config import ConfigError, Settings
from tokiwa.config_diagnostics import (
    ConfigEntry,
    config_file_status,
    config_issues,
    effective_config,
)

app = typer.Typer(help="Inspect the configuration", no_args_is_help=True)

_SOURCE_HELP = (
    "env = TOKIWA_* environment variable, file = config file (TOKIWA_CONFIG), default = built-in default, "
    "ui = saved from the web UI (only with --db)"
)


def _build_settings() -> Settings:
    try:
        return Settings()
    except ValidationError as exc:
        # Never print pydantic's message as is: it quotes the input value (a too-short secret_key, a URL with a
        # password). Location + reason is enough to find the mistake.
        typer.echo("configuration is invalid:", err=True)
        for err in exc.errors(include_input=False, include_url=False):
            loc = ".".join(str(p) for p in err["loc"])
            typer.echo(f"  {loc}: {err['msg']}", err=True)
        raise typer.Exit(2) from None


def _sqlite_file_missing(settings: Settings) -> bool:
    """Connecting to a missing SQLite file would create it: ``config show`` must not have side effects."""
    from sqlalchemy.engine import make_url

    url = make_url(settings.database.url)
    if url.get_backend_name() != "sqlite" or url.database in (None, "", ":memory:"):
        return False
    return not Path(url.database).is_file()


async def _ui_overrides(settings: Settings) -> tuple[Settings, dict[str, str], str | None]:
    """Apply the LLM overlay saved from the web UI (settings_kv "llm.config"). Read-only."""
    from tokiwa.db.session import dispose_engine, init_engine
    from tokiwa.llm.settings import LLM_CONFIG_KEY, apply_overlay, clean_overlay, load_overlay

    try:
        init_engine(settings.database.url)
        overlay = await load_overlay()
    except ConfigError:
        return (
            settings,
            {},
            "not read: TOKIWA_STRICT_CONFIG refuses this configuration (fix the problems below first)",
        )
    except Exception as exc:  # missing table, unreachable server, ...
        return settings, {}, f"could not read UI overrides ({type(exc).__name__})"
    finally:
        await dispose_engine()
    if not settings.llm.allow_ui_override:
        return settings, {}, "llm.allow_ui_override is false: UI overrides are ignored"
    applied = apply_overlay(settings, overlay)
    keys = clean_overlay(settings.llm, overlay)
    return applied, {f"llm.{k}": LLM_CONFIG_KEY for k in keys}, None


def _format_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


@app.command("show")
def show(
    section: list[str] = typer.Option(
        [],
        "--section",
        "-s",
        help="Only these sections or dotted prefixes (repeatable), e.g. -s llm -s gate.upstream",
    ),
    changed: bool = typer.Option(
        False, "--changed", help="Only values that differ from the built-in default"
    ),
    db: bool = typer.Option(
        False, "--db", help="Also read the LLM settings saved from the web UI (settings_kv) from the database"
    ),
    as_json: bool = typer.Option(False, "--json", help="JSON output"),
    check: bool = typer.Option(
        False, "--check", help="Exit with code 1 when configuration problems are found"
    ),
) -> None:
    """Print the effective configuration. Secrets are never printed (shown as <set>)."""
    settings = _build_settings()
    issues = config_issues(settings)
    overrides: dict[str, str] = {}
    db_note: str | None = None
    if db and _sqlite_file_missing(settings):
        db_note = "database file not found (no UI overrides)"
    elif db:
        settings, overrides, db_note = asyncio.run(_ui_overrides(settings))
    entries: list[ConfigEntry] = effective_config(settings, ui_overrides=overrides)
    if section:
        entries = [
            e for e in entries if any(e.path == s or e.path.startswith(s.rstrip(".") + ".") for s in section)
        ]
    if changed:
        entries = [e for e in entries if not e.default or e.source != "default"]

    if as_json:
        typer.echo(
            json.dumps(
                {
                    "config_file": config_file_status(),
                    "settings": [
                        {"path": e.path, "value": e.value, "source": e.source, "origin": e.origin}
                        for e in entries
                    ],
                    "issues": [
                        {"source": i.source, "key": i.key, "problem": i.problem, "hint": i.hint}
                        for i in issues
                    ],
                    **({"ui": db_note} if db_note else {}),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        typer.echo("# TOKIWA effective configuration (secrets shown as <set>)")
        typer.echo(f"# config file: {config_file_status()}")
        typer.echo(f"# source: {_SOURCE_HELP}")
        if db_note:
            typer.echo(f"# ui: {db_note}")
        for e in entries:
            origin = f" ({e.origin})" if e.origin and e.source in ("env", "ui") else ""
            typer.echo(f"{e.path} = {_format_value(e.value)}  [{e.source}{origin}]")
        if issues:
            typer.echo(
                f"# {len(issues)} problem(s) (logged as WARNING at startup; fatal with TOKIWA_STRICT_CONFIG=1):"
            )
            for issue in issues:
                typer.echo(f"#   {issue}")
        else:
            typer.echo("# no problems found")
    if check and issues:
        raise typer.Exit(1)
