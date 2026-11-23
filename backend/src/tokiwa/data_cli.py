"""``tokiwa data purge|export`` -- subject-level deletion / export of stored telemetry (audit #158).

Why a CLI and not an API: it runs on the server host with direct DB access (admin-equivalent), works without a
logged-in admin, and is the tool for "delete / disclose everything about IP x" requests or for removing customer
data ingested by mistake. Every run (including dry runs) is written to the audit log as actor ``cli``.

Selectors (combined with AND): ``--ip`` (source IP), ``--session`` (actor session id), ``--before`` (older than).
What is covered, per table:

==================  =====================================================  =========================================
table               matched by                                             purge does
==================  =====================================================  =========================================
events              source_ip / session_id / timestamp                     delete rows
actor_sessions      source_ip / id / last_seen                             delete rows
deception_trips     source_ip / event_id of matched events / timestamp     delete rows
alerts              source_ip (``--ip`` only)                              clear ``details`` (row kept: incidents
                                                                           and the audit trail refer to it)
llm_calls           related.alert_id of matched alerts, the IP / session   NULL ``request_redacted`` and
                    id in the stored prompt/response, created_at           ``response_text`` (cost/usage rows kept)
==================  =====================================================  =========================================

Not covered (see docs/handoff/2026-11-21-audit-tokens-roles.md): incidents.source_ips / summaries, alert triage
text, copilot messages, the access log and audit log, backups.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import typer
from sqlalchemy import Select, delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.db.models.deception import DeceptionTripRow
from tokiwa.db.models.detection import AlertRow
from tokiwa.db.models.llm import LLMCallRow
from tokiwa.db.models.telemetry import ActorSessionRow, EventRow
from tokiwa.util import ensure_utc

app = typer.Typer(
    help="Subject-level data purge / export (admin, runs on the server host)", no_args_is_help=True
)

CLI_ACTOR = "cli"
_CHUNK = 500


@dataclass(frozen=True)
class Selector:
    ip: str | None = None
    session_id: str | None = None
    before: datetime | None = None

    def describe(self) -> dict[str, str]:
        out: dict[str, str] = {}
        if self.ip:
            out["ip"] = self.ip
        if self.session_id:
            out["session"] = self.session_id
        if self.before:
            out["before"] = self.before.isoformat()
        return out

    def text_pattern(self) -> re.Pattern[str] | None:
        """How the IP / session id appears inside stored LLM prompts (word-bounded, so 10.0.0.1 != 10.0.0.15)."""
        terms = []
        if self.ip:
            terms.append(r"(?<![0-9A-Fa-f:.])" + re.escape(self.ip) + r"(?![0-9A-Fa-f:]|\.\d)")
        if self.session_id:
            terms.append(r"(?<![\w-])" + re.escape(self.session_id) + r"(?![\w-])")
        return re.compile("|".join(terms)) if terms else None


def parse_selector(ip: str | None, session_id: str | None, before: str | None) -> Selector:
    if not (ip or session_id or before):
        raise typer.BadParameter("give at least one of --ip, --session, --before")
    norm_ip = None
    if ip:
        try:
            norm_ip = str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            raise typer.BadParameter(f"--ip: not an IP address: {ip!r}") from None
    when = None
    if before:
        try:
            when = ensure_utc(datetime.fromisoformat(before))
        except ValueError:
            raise typer.BadParameter(
                "--before: use ISO 8601, e.g. 2026-11-01 or 2026-11-01T00:00:00Z"
            ) from None
    return Selector(ip=norm_ip, session_id=session_id.strip() if session_id else None, before=when)


def _events_stmt(sel: Selector) -> Select[EventRow]:
    stmt = select(EventRow)
    if sel.ip:
        stmt = stmt.where(EventRow.source_ip == sel.ip)
    if sel.session_id:
        stmt = stmt.where(EventRow.session_id == sel.session_id)
    if sel.before:
        stmt = stmt.where(EventRow.timestamp < sel.before)
    return stmt


def _sessions_stmt(sel: Selector) -> Select[ActorSessionRow]:
    stmt = select(ActorSessionRow)
    if sel.ip:
        stmt = stmt.where(ActorSessionRow.source_ip == sel.ip)
    if sel.session_id:
        stmt = stmt.where(ActorSessionRow.id == sel.session_id)
    if sel.before:
        stmt = stmt.where(ActorSessionRow.last_seen < sel.before)
    return stmt


def _alerts_stmt(sel: Selector) -> Select[AlertRow] | None:
    if not sel.ip:  # alerts are per source IP; a session / time selector alone leaves them to retention
        return None
    stmt = select(AlertRow).where(AlertRow.source_ip == sel.ip)
    if sel.before:
        stmt = stmt.where(AlertRow.last_seen < sel.before)
    return stmt


@dataclass
class Matches:
    event_ids: list[str]
    session_ids: list[str]
    trip_ids: list[str]
    alert_ids: list[str]
    llm_call_ids: list[str]

    def counts(self) -> dict[str, int]:
        return {
            "events": len(self.event_ids),
            "actor_sessions": len(self.session_ids),
            "deception_trips": len(self.trip_ids),
            "alerts": len(self.alert_ids),
            "llm_calls": len(self.llm_call_ids),
        }


def _chunks(ids: list[str]) -> Iterator[list[str]]:
    for i in range(0, len(ids), _CHUNK):
        yield ids[i : i + _CHUNK]


async def find_matches(session: AsyncSession, sel: Selector) -> Matches:
    event_ids = list((await session.execute(_events_stmt(sel).with_only_columns(EventRow.id))).scalars())
    session_ids = list(
        (await session.execute(_sessions_stmt(sel).with_only_columns(ActorSessionRow.id))).scalars()
    )
    trip_ids: set[str] = set()
    trips = select(DeceptionTripRow.id)
    conds = []
    if sel.ip:
        conds.append(DeceptionTripRow.source_ip == sel.ip)
    if sel.before:
        conds.append(DeceptionTripRow.timestamp < sel.before)
    if conds and not sel.session_id:
        trip_ids.update((await session.execute(trips.where(*conds))).scalars())
    for chunk in _chunks(event_ids):  # trips whose event was matched (covers --session)
        trip_ids.update((await session.execute(trips.where(DeceptionTripRow.event_id.in_(chunk)))).scalars())

    alerts = _alerts_stmt(sel)
    alert_ids = (
        list((await session.execute(alerts.with_only_columns(AlertRow.id))).scalars())
        if alerts is not None
        else []
    )

    llm_ids: set[str] = set()
    pattern = sel.text_pattern()
    if pattern is not None or sel.before:
        stmt = select(
            LLMCallRow.id, LLMCallRow.related, LLMCallRow.request_redacted, LLMCallRow.response_text
        )
        if sel.before:
            stmt = stmt.where(LLMCallRow.created_at < sel.before)
        # Full scan of llm_calls (bounded by --before when given): the related-JSON and word-bounded regex checks
        # are done in Python because JSON / LIKE semantics differ between SQLite and PostgreSQL.
        alert_set = set(alert_ids)
        async for row in await session.stream(stmt):
            cid, related, req, resp = row
            if (
                pattern is None
                or (related or {}).get("alert_id") in alert_set
                or ((related or {}).get("session_id") == sel.session_id and sel.session_id)
                or pattern.search(req or "")
                or pattern.search(resp or "")
            ):  # --before only
                llm_ids.add(cid)
    return Matches(event_ids, session_ids, sorted(trip_ids), alert_ids, sorted(llm_ids))


async def purge(session: AsyncSession, sel: Selector, m: Matches) -> None:
    for chunk in _chunks(m.event_ids):
        await session.execute(delete(EventRow).where(EventRow.id.in_(chunk)))
    for chunk in _chunks(m.session_ids):
        await session.execute(delete(ActorSessionRow).where(ActorSessionRow.id.in_(chunk)))
    for chunk in _chunks(m.trip_ids):
        await session.execute(delete(DeceptionTripRow).where(DeceptionTripRow.id.in_(chunk)))
    for chunk in _chunks(m.alert_ids):
        await session.execute(update(AlertRow).where(AlertRow.id.in_(chunk)).values(details={"purged": True}))
    for chunk in _chunks(m.llm_call_ids):
        await session.execute(
            update(LLMCallRow)
            .where(LLMCallRow.id.in_(chunk))
            .values(request_redacted=None, response_text=None)
        )


def _jsonable(row: Any, columns: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for c in columns:
        v = getattr(row, c)
        out[c] = v.isoformat() if isinstance(v, datetime) else v
    return out


async def export_records(session: AsyncSession, m: Matches) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    tables: list[tuple[str, Any, list[str], list[str]]] = [
        ("events", EventRow, m.event_ids, ["id", "timestamp", "dataset", "sensor_id", "data"]),
        ("actor_sessions", ActorSessionRow, m.session_ids,
         ["id", "source_ip", "user_agent", "first_seen", "last_seen", "request_count", "ai_score", "classification"]),
        ("deception_trips", DeceptionTripRow, m.trip_ids,
         ["id", "timestamp", "asset_id", "asset_kind", "event_id", "source_ip", "trip_type", "detail"]),
        ("alerts", AlertRow, m.alert_ids,
         ["id", "first_seen", "last_seen", "title", "severity", "category", "source_ip", "entities", "details"]),
        ("llm_calls", LLMCallRow, m.llm_call_ids,
         ["id", "created_at", "purpose", "model", "related", "request_redacted", "response_text"]),
    ]  # fmt: skip
    for name, model, ids, cols in tables:
        for chunk in _chunks(ids):
            rows = (await session.execute(select(model).where(model.id.in_(chunk)))).scalars()
            out += [{"table": name, "row": _jsonable(r, cols)} for r in rows]
    return out


async def _run(sel: Selector, *, action: str, apply: bool, out: Path | None) -> dict[str, Any]:
    from tokiwa.audit import record_audit
    from tokiwa.db.session import create_all, dispose_engine, init_engine, session_scope

    init_engine()
    try:
        await create_all()
        async with session_scope() as session:
            m = await find_matches(session, sel)
            result: dict[str, Any] = {"counts": m.counts()}
            if action == "purge" and apply:
                await purge(session, sel, m)
            if action == "export":
                records = await export_records(session, m)
                result["records"] = records
            await record_audit(
                CLI_ACTOR,
                f"data.{action}" + ("" if action == "export" or apply else ".dry_run"),
                None,
                {"selector": sel.describe(), "counts": m.counts(), "out": str(out) if out else None},
                session=session,
            )
        return result
    finally:
        await dispose_engine()


def _counts_line(counts: dict[str, int]) -> str:
    return ", ".join(f"{k}={v}" for k, v in counts.items())


@app.command("purge")
def purge_cmd(
    ip: str | None = typer.Option(None, "--ip", help="Source IP address"),
    session_id: str | None = typer.Option(None, "--session", help="Actor session id"),
    before: str | None = typer.Option(None, "--before", help="Only data older than this (ISO 8601)"),
    yes: bool = typer.Option(False, "--yes", help="Actually delete (default: dry run, counts only)"),
) -> None:
    """Delete / scrub everything stored about a source IP, an actor session or a time range."""
    sel = parse_selector(ip, session_id, before)
    result = asyncio.run(_run(sel, action="purge", apply=yes, out=None))
    verb = "purged" if yes else "would purge (dry run; add --yes)"
    typer.echo(f"{verb}: {_counts_line(result['counts'])}")


@app.command("export")
def export_cmd(
    ip: str | None = typer.Option(None, "--ip", help="Source IP address"),
    session_id: str | None = typer.Option(None, "--session", help="Actor session id"),
    before: str | None = typer.Option(None, "--before", help="Only data older than this (ISO 8601)"),
    out: Path | None = typer.Option(
        None, "--out", "-o", help="Write JSONL here (mode 600) instead of stdout"
    ),
) -> None:
    """Export everything stored about a source IP / session as JSONL ({"table": ..., "row": {...}} per line)."""
    sel = parse_selector(ip, session_id, before)
    result = asyncio.run(_run(sel, action="export", apply=False, out=out))
    lines = [json.dumps(r, ensure_ascii=False, default=str) for r in result["records"]]
    if out is None:
        for line in lines:
            typer.echo(line)
        return
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("".join(line + "\n" for line in lines))
    typer.echo(f"exported {len(lines)} records to {out}: {_counts_line(result['counts'])}", err=True)
