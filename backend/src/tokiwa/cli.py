"""``tokiwa`` command line.

Sub-command groups are provided by modules (created by their owners) and attached when importable:

    tokiwa serve                 run the server (API + UI + background jobs)
    tokiwa user create ...       create a user
    tokiwa token create ...      create an API token for agents / gate
    tokiwa token list|revoke|rotate   token lifecycle (works without an admin login)
    tokiwa agent run ...         host sensor / log shipper          (tokiwa.sensors.cli)
    tokiwa gate run ...          reverse-proxy sensor / enforcer    (tokiwa.gate.cli)
    tokiwa intel sync ...        vulnerability intel                (tokiwa.intel.cli)
    tokiwa eval run ...          replay + metrics                   (tokiwa.eval.cli)
    tokiwa sim run ...           lab traffic simulator              (tokiwa.eval.sim_cli)
    tokiwa data purge|export     subject-level delete / export      (tokiwa.data_cli)
"""

from __future__ import annotations

import asyncio
import importlib
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

import typer

from tokiwa import __version__
from tokiwa.config import get_settings

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

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
    "data": "tokiwa.data_cli",
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


CLI_ACTOR = "cli"  # audit actor for token operations done on the server host (no logged-in user)


async def _create_token(
    name: str,
    scopes: list[str],
    *,
    allowed_sensor_ids: list[str] | None = None,
    allowed_datasets: list[str] | None = None,
    expires_in_days: int | None = None,
) -> str:
    from tokiwa.auth.api_tokens import issue_token
    from tokiwa.db.session import create_all, init_engine, session_scope

    init_engine()
    await create_all()
    async with session_scope() as session:
        issued = await issue_token(
            session,
            name=name,
            scopes=scopes,
            actor=CLI_ACTOR,
            expires_in_days=expires_in_days,
            allowed_sensor_ids=allowed_sensor_ids,
            allowed_datasets=allowed_datasets,
        )
    return issued.plaintext


def _validate_token_options(
    scopes: list[str], sensor_ids: list[str], datasets: list[str], expires_in_days: int | None = None
) -> tuple[list[str], list[str] | None, list[str] | None]:
    """Same rules as the API (schemas.system.ApiTokenCreate), so the CLI cannot create what the API refuses."""
    from pydantic import ValidationError

    from tokiwa.schemas.system import ApiTokenCreate, ApiTokenScope

    valid = {s.value for s in ApiTokenScope}
    if not scopes or any(s not in valid for s in scopes):
        raise typer.BadParameter(f"--scope must be one or more of {sorted(valid)}")
    try:
        body = ApiTokenCreate(
            name="cli",
            scopes=[ApiTokenScope(s) for s in scopes],
            allowed_sensor_ids=sensor_ids or None,
            allowed_datasets=datasets or None,
            expires_in_days=expires_in_days,
        )
    except ValidationError as exc:
        raise typer.BadParameter(
            "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())
        ) from None
    return (
        list(dict.fromkeys(str(s) for s in body.scopes)),
        body.allowed_sensor_ids,
        body.allowed_datasets,
    )


@token_app.command("create")
def token_create(
    name: str,
    scope: list[str] = typer.Option(
        ["ingest"],
        help="ingest / gate / read (repeatable). Default: ingest only. A Gate needs --scope ingest --scope gate",
    ),
    sensor_id: list[str] = typer.Option(
        [], "--sensor-id", help="Bind to these sensor ids (repeatable; events are forced to one of them)"
    ),
    dataset: list[str] = typer.Option(
        [], "--dataset", help="Allowed datasets, fnmatch patterns like nginx.access or host.* (repeatable)"
    ),
    expires_in_days: int | None = typer.Option(
        None, "--expires-in-days", help="Expire after N days (1-3650). Default: never"
    ),
) -> None:
    """Create an API token (printed once)."""
    scopes, sensor_ids, datasets = _validate_token_options(scope, sensor_id, dataset, expires_in_days)
    typer.echo(
        asyncio.run(
            _create_token(
                name,
                scopes,
                allowed_sensor_ids=sensor_ids,
                allowed_datasets=datasets,
                expires_in_days=expires_in_days,
            )
        )
    )


async def _with_db[T](fn: Callable[[AsyncSession], Awaitable[T]]) -> T:
    """Run ``fn`` in one committed session on a fresh engine (the CLI owns the process)."""
    from tokiwa.db.session import create_all, dispose_engine, init_engine, session_scope

    init_engine()
    try:
        await create_all()
        async with session_scope() as session:
            return await fn(session)
    finally:
        await dispose_engine()


def _fmt_time(value: datetime | None) -> str:
    from tokiwa.util import ensure_utc

    return ensure_utc(value).strftime("%Y-%m-%d %H:%M") if value else "-"


@token_app.command("list")
def token_list(
    show_all: bool = typer.Option(False, "--all", help="Include revoked tokens"),
) -> None:
    """List API tokens (never prints secrets or hashes)."""
    from sqlalchemy import select

    from tokiwa.auth.api_tokens import status_of
    from tokiwa.db.models.core import ApiTokenRow

    async def _list(session: AsyncSession) -> list[ApiTokenRow]:
        stmt = select(ApiTokenRow).order_by(ApiTokenRow.created_at.desc(), ApiTokenRow.id.desc())
        if not show_all:
            stmt = stmt.where(ApiTokenRow.revoked.is_(False))
        return list((await session.execute(stmt)).scalars())

    rows = asyncio.run(_with_db(_list))
    header = ("ID", "NAME", "PREFIX", "SCOPES", "STATUS", "EXPIRES", "LAST_USED", "CREATED_BY")
    table = [header] + [
        (
            r.id,
            r.name,
            r.prefix,
            ",".join(r.scopes),
            status_of(r),
            _fmt_time(r.expires_at),
            _fmt_time(r.last_used),
            r.created_by or "-",
        )
        for r in rows
    ]
    widths = [max(len(str(row[i])) for row in table) for i in range(len(header))]
    for row in table:
        typer.echo("  ".join(str(v).ljust(w) for v, w in zip(row, widths, strict=True)).rstrip())


@token_app.command("revoke")
def token_revoke(
    ref: str = typer.Argument(..., help="Token id, or the name of exactly one active token"),
) -> None:
    """Revoke a token now (works without an admin login; recorded in the audit log as actor "cli")."""
    from tokiwa.auth.api_tokens import TokenLookupError, find_token, revoke_token

    async def _revoke(session: AsyncSession) -> tuple[str, str, bool]:
        row = await find_token(session, ref)
        changed = await revoke_token(session, row, actor=CLI_ACTOR)
        return row.id, row.name, changed

    try:
        token_id, name, changed = asyncio.run(_with_db(_revoke))
    except TokenLookupError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from None
    typer.echo(f"revoked {name} ({token_id})" if changed else f"{name} ({token_id}) was already revoked")


@token_app.command("rotate")
def token_rotate(
    ref: str = typer.Argument(..., help="Token id, or the name of exactly one active token"),
    grace_hours: int = typer.Option(
        24, "--grace-hours", min=0, max=720, help="Keep the old token valid this long (0 = revoke now)"
    ),
    expires_in_days: int | None = typer.Option(
        None, "--expires-in-days", min=1, max=3650, help="Expiry of the new token. Default: never"
    ),
) -> None:
    """Issue a replacement (same name, scopes, binding); prints the new token once on stdout."""
    from tokiwa.auth.api_tokens import TokenLookupError, find_token, rotate_token

    async def _rotate(session: AsyncSession) -> tuple[str, str, datetime | None]:
        row = await find_token(session, ref)
        issued = await rotate_token(
            session, row, actor=CLI_ACTOR, grace_hours=grace_hours, expires_in_days=expires_in_days
        )
        return issued.plaintext, row.id, row.expires_at

    try:
        token, old_id, old_until = asyncio.run(_with_db(_rotate))
    except (TokenLookupError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from None
    until = "now" if grace_hours == 0 else _fmt_time(old_until) + " UTC"
    typer.echo(
        f"rotated {old_id}: old token valid until {until}; write the new token to the sensor", err=True
    )
    typer.echo(token)


if __name__ == "__main__":
    app()
