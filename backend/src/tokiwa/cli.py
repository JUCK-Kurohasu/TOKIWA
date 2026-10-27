"""``tokiwa`` command line.

Sub-command groups are provided by modules (created by their owners) and attached when importable:

    tokiwa serve                 run the server (API + UI + background jobs)
    tokiwa user create ...       create a user
    tokiwa token create ...      create an API token for agents / gate
    tokiwa agent run ...         host sensor / log shipper          (tokiwa.sensors.cli)
    tokiwa gate run ...          reverse-proxy sensor / enforcer    (tokiwa.gate.cli)
    tokiwa intel sync ...        vulnerability intel                (tokiwa.intel.cli)
    tokiwa eval run ...          replay + metrics                   (tokiwa.eval.cli)
    tokiwa sim run ...           lab traffic simulator              (tokiwa.eval.sim_cli)
"""

from __future__ import annotations

import asyncio
import importlib
import logging
from pathlib import Path

import typer

from tokiwa import __version__
from tokiwa.config import get_settings

app = typer.Typer(help="TOKIWA - LLM-driven SIEM/XDR", no_args_is_help=True)
user_app = typer.Typer(help="User management")
token_app = typer.Typer(help="API tokens for agents / gate")
app.add_typer(user_app, name="user")
app.add_typer(token_app, name="token")

_SUBCOMMANDS = {
    "agent": "tokiwa.sensors.cli",
    "gate": "tokiwa.gate.cli",
    "intel": "tokiwa.intel.cli",
    "eval": "tokiwa.eval.cli",
    "sim": "tokiwa.eval.sim_cli",
}
for _name, _mod in _SUBCOMMANDS.items():
    try:
        _sub = getattr(importlib.import_module(_mod), "app", None)
    except ImportError:
        _sub = None
    if isinstance(_sub, typer.Typer):
        app.add_typer(_sub, name=_name)


def _setup_logging() -> None:
    logging.basicConfig(
        level=get_settings().log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


@app.command()
def version() -> None:
    """Print version."""
    typer.echo(__version__)


@app.command()
def serve(
    host: str | None = typer.Option(None, help="Bind host (default from config)"),
    port: int | None = typer.Option(None, help="Bind port (default 8788)"),
    reload: bool = typer.Option(False, help="Auto-reload (development)"),
    no_jobs: bool = typer.Option(False, help="Do not start periodic background jobs"),
) -> None:
    """Run the TOKIWA server (API, UI, pipeline, background jobs)."""
    import uvicorn

    _setup_logging()
    s = get_settings()
    if no_jobs:
        import os

        os.environ["TOKIWA_NO_JOBS"] = "1"
    # Watch only the package source: the default (the working directory, usually backend/) also covers data/,
    # where every SQLite write made watchfiles log "change detected" (uvicorn filters *.py only afterwards).
    reload_dirs = [str(Path(__file__).resolve().parent)] if reload else None
    uvicorn.run(
        "tokiwa.api.asgi:app",
        host=host or s.server.host,
        port=port or s.server.port,
        reload=reload,
        reload_dirs=reload_dirs,
        log_level=s.log_level.lower(),
    )


async def _create_user(username: str, password: str, role: str) -> None:
    from tokiwa.auth.security import hash_password
    from tokiwa.db.models.core import UserRow
    from tokiwa.db.session import create_all, init_engine, session_scope
    from tokiwa.util import new_id, utcnow

    init_engine()
    await create_all()
    async with session_scope() as session:
        session.add(
            UserRow(
                id=new_id(),
                username=username,
                password_hash=hash_password(password),
                role=role,
                created_at=utcnow(),
            )
        )


@user_app.command("create")
def user_create(
    username: str,
    password: str = typer.Option(..., prompt=True, hide_input=True, confirmation_prompt=True),
    role: str = typer.Option("analyst", help="admin | analyst | viewer"),
) -> None:
    asyncio.run(_create_user(username, password, role))
    typer.echo(f"created user {username} ({role})")


async def _create_token(name: str, scopes: list[str]) -> str:
    from tokiwa.auth.security import generate_api_token
    from tokiwa.db.models.core import ApiTokenRow
    from tokiwa.db.session import create_all, init_engine, session_scope
    from tokiwa.util import new_id, utcnow

    init_engine()
    await create_all()
    token, digest, prefix = generate_api_token()
    async with session_scope() as session:
        session.add(
            ApiTokenRow(
                id=new_id(), name=name, token_hash=digest, prefix=prefix, scopes=scopes, created_at=utcnow()
            )
        )
    return token


@token_app.command("create")
def token_create(
    name: str,
    scope: list[str] = typer.Option(["ingest", "gate"], help="ingest / gate / read"),
) -> None:
    """Create an API token (printed once)."""
    typer.echo(asyncio.run(_create_token(name, scope)))


if __name__ == "__main__":
    app()
