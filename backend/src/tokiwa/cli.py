"""``tokiwa`` command line.

Sub-command groups are provided by modules (created by their owners) and attached when importable:

    tokiwa serve                 run the server (API + UI + background jobs)
    tokiwa user create ...       create a user
    tokiwa user reset-password   set a user's password (ends their logins)
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
from typing import Any

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


class _UserError(Exception):
    """A user-facing CLI error: printed as one line, exit code 1 (never a traceback with SQL parameters)."""


def _validated_user(username: str, password: str, role: str) -> Any:
    from pydantic import ValidationError

    from tokiwa.schemas.system import UserCreate

    try:
        return UserCreate(username=username, password=password, role=role)
    except ValidationError as exc:
        fields = ", ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        raise _UserError(f"invalid input ({fields})") from None


async def _create_user(username: str, password: str, role: str) -> None:
    """Create a user from the server's shell (also the recovery path when no admin is left)."""
    from sqlalchemy import select
    from sqlalchemy.exc import SQLAlchemyError

    from tokiwa.audit import record_audit
    from tokiwa.auth.accounts import lock_accounts, mark_setup_completed
    from tokiwa.auth.security import hash_password_async
    from tokiwa.db.models.core import UserRow
    from tokiwa.db.session import create_all, dispose_engine, init_engine, session_scope
    from tokiwa.util import new_id, utcnow

    body = _validated_user(username, password, role)
    init_engine()
    try:
        await create_all()
        password_hash = await hash_password_async(body.password)
        async with session_scope() as session:
            await lock_accounts(session)
            exists = await session.scalar(select(UserRow.id).where(UserRow.username == body.username))
            if exists is not None:
                raise _UserError(
                    f"user {body.username!r} already exists "
                    f"(change its password with: tokiwa user reset-password {body.username})"
                )
            row = UserRow(
                id=new_id(),
                username=body.username,
                password_hash=password_hash,
                role=body.role,
                created_at=utcnow(),
            )
            session.add(row)
            await mark_setup_completed(
                session, by=body.username
            )  # a CLI-created first admin closes /auth/setup
            await record_audit(
                "cli",
                "user.create",
                row.id,
                {"username": row.username, "role": str(body.role)},
                session=session,
            )
    except SQLAlchemyError as exc:
        # Only the driver's message: the full exception text carries the SQL statement (#163).
        raise _UserError(f"database error: {getattr(exc, 'orig', None) or type(exc).__name__}") from None
    finally:
        await dispose_engine()


async def _reset_password(username: str, password: str) -> None:
    """Set a new password, end the user's existing logins and record it in the audit log (#163 / #34)."""
    from sqlalchemy import select
    from sqlalchemy.exc import SQLAlchemyError

    from tokiwa.audit import record_audit
    from tokiwa.auth.accounts import revoke_sessions
    from tokiwa.auth.security import hash_password_async
    from tokiwa.db.models.core import UserRow
    from tokiwa.db.session import create_all, dispose_engine, init_engine, session_scope

    _validated_user("placeholder", password, "viewer")  # same password rules as the API
    init_engine()
    try:
        await create_all()
        password_hash = await hash_password_async(password)
        async with session_scope() as session:
            row = await session.scalar(select(UserRow).where(UserRow.username == username))
            if row is None:
                raise _UserError(
                    f"no such user: {username!r} (create one with: tokiwa user create {username})"
                )
            row.password_hash = password_hash
            await session.flush()
            await revoke_sessions(session, row.id)
            await record_audit(
                "cli",
                "user.password_reset",
                row.id,
                {"username": row.username, "sessions_revoked": True},  # never the password
                session=session,
            )
    except SQLAlchemyError as exc:
        raise _UserError(f"database error: {getattr(exc, 'orig', None) or type(exc).__name__}") from None
    finally:
        await dispose_engine()


def _run_user_command(coro: Any) -> None:
    try:
        asyncio.run(coro)
    except _UserError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None


@user_app.command("create")
def user_create(
    username: str,
    password: str = typer.Option(..., prompt=True, hide_input=True, confirmation_prompt=True),
    role: str = typer.Option("analyst", help="admin | analyst | viewer"),
) -> None:
    """Create a user (password asked interactively). Use --role admin to recover when no admin is left."""
    _run_user_command(_create_user(username, password, role))
    typer.echo(f"created user {username} ({role})")


@user_app.command("reset-password")
def user_reset_password(
    username: str,
    password: str = typer.Option(..., prompt="New password", hide_input=True, confirmation_prompt=True),
) -> None:
    """Set a new password (asked interactively). Ends the user's existing logins; recorded in the audit log."""
    _run_user_command(_reset_password(username, password))
    typer.echo(f"password reset for {username}; existing logins of this user were ended")


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
