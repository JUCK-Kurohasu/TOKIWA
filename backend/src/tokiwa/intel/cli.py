"""``tokiwa intel`` — vulnerability / threat feed operations.

tokiwa intel sync [--source kev --source nvd]   run one sync pass now (foreground)
tokiwa intel status                             per-source last sync / error / counts
tokiwa intel show CVE-2024-3400 [--json]        merged record for one vulnerability (id or alias)
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any

import typer

app = typer.Typer(
    help="Vulnerability / threat intel feeds (KEV, EPSS, NVD, OSV, JVN, GHSA, RSS)", no_args_is_help=True
)


def _run[T](fn: Callable[[], Awaitable[T]]) -> T:
    async def wrapper() -> T:
        from tokiwa.db.session import create_all, dispose_engine, init_engine

        init_engine()
        await create_all()
        try:
            return await fn()
        finally:
            await dispose_engine()

    return asyncio.run(wrapper())


def _fmt(value: Any) -> str:
    return "-" if value in (None, "") else str(value)


@app.command("sync")
def sync_cmd(
    source: list[str] = typer.Option(None, "--source", "-s", help="Source id(s); default: all enabled"),
) -> None:
    """Run one synchronisation pass in the foreground and print a summary."""
    from tokiwa.intel.sync import SyncInProgressError, run_sync

    async def go() -> dict[str, dict[str, Any]]:
        return await run_sync(source or None)

    try:
        result = _run(go)
    except KeyError as exc:
        typer.echo(str(exc.args[0]), err=True)
        raise typer.Exit(2) from exc
    except SyncInProgressError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    if not result:
        typer.echo("no enabled intel sources")
        return
    failed = False
    for sid, e in result.items():
        status = "ERROR" if e.get("last_error") else "ok"
        failed = failed or bool(e.get("last_error"))
        typer.echo(
            f"{sid:6} {status:5} records={e.get('records', 0)} vulns+{e.get('vulns_created', 0)}"
            f"/~{e.get('vulns_updated', 0)} items+{e.get('items_created', 0)} {e.get('duration_ms', 0)}ms"
        )
        if e.get("last_error"):
            typer.echo(f"       {e['last_error']}")
    if failed:
        raise typer.Exit(1)


@app.command("status")
def status_cmd() -> None:
    """Show per-source sync state."""
    from tokiwa.intel.sync import source_statuses

    statuses = _run(source_statuses)
    typer.echo(f"{'source':6} {'enabled':7} {'last_sync':32} {'records':>7}  last_error")
    for s in statuses:
        typer.echo(
            f"{s.id:6} {'yes' if s.enabled else 'no':7} {_fmt(s.last_sync and s.last_sync.isoformat()):32} "
            f"{s.records:>7}  {_fmt(s.last_error)}"
        )
    notices = [s.attribution for s in statuses if s.enabled and s.attribution]
    if notices:
        typer.echo("")
        for n in notices:
            typer.echo(f"* {n}")


@app.command("show")
def show_cmd(
    vuln_id: str = typer.Argument(..., help="CVE / GHSA / JVNDB id"),
    as_json: bool = typer.Option(False, "--json", help="Print the full merged record as JSON"),
) -> None:
    """Print the merged record for one vulnerability."""
    from tokiwa.db.session import session_scope
    from tokiwa.intel.store import get_vuln_row
    from tokiwa.schemas.intel import VulnRecord

    async def go() -> VulnRecord | None:
        async with session_scope() as session:
            row = await get_vuln_row(session, vuln_id)
            return VulnRecord.model_validate(row) if row is not None else None

    rec = _run(go)
    if rec is None:
        typer.echo(f"{vuln_id}: not found", err=True)
        raise typer.Exit(1)
    if as_json:
        typer.echo(json.dumps(rec.model_dump(mode="json"), ensure_ascii=False, indent=2))
        return
    typer.echo(f"{rec.id}  {_fmt(rec.title)}")
    if rec.aliases:
        typer.echo(f"  aliases : {', '.join(rec.aliases)}")
    typer.echo(f"  sources : {', '.join(rec.sources)}")
    kev = "yes" if rec.kev else "no"
    if rec.kev:
        kev += f" (added {_fmt(rec.kev_date_added and rec.kev_date_added.date())}, due {_fmt(rec.kev_due_date and rec.kev_due_date.date())}, ransomware {_fmt(rec.kev_ransomware)})"
    typer.echo(f"  KEV     : {kev}")
    epss = "-" if rec.epss is None else f"{rec.epss:.5f} (percentile {_fmt(rec.epss_percentile)})"
    typer.echo(f"  EPSS    : {epss}")
    typer.echo(f"  CVSS    : {_fmt(rec.cvss_score)} {_fmt(rec.cvss_vector)}  severity={_fmt(rec.severity)}")
    typer.echo(f"  CWE     : {', '.join(rec.cwe) or '-'}")
    typer.echo(f"  modified: {_fmt(rec.modified and rec.modified.isoformat())}")
    if rec.description:
        typer.echo("")
        typer.echo(rec.description)
    if rec.references:
        typer.echo("")
        for ref in rec.references[:10]:
            typer.echo(f"  - {ref}")
