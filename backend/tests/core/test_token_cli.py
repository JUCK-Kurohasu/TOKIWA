"""``tokiwa token ...`` CLI (audit #33 default scope, #40 binding options)."""

from __future__ import annotations

import asyncio
import re

from sqlalchemy import select
from typer.testing import CliRunner

from tokiwa import cli
from tokiwa.config import Settings
from tokiwa.db import session as dbsession
from tokiwa.db.models.core import ApiTokenRow

TOKEN_RE = re.compile(r"^tkw_\S+$")


def _rows() -> list[ApiTokenRow]:
    async def _q() -> list[ApiTokenRow]:
        dbsession.init_engine()
        try:
            async with dbsession.session_scope() as s:
                return list((await s.execute(select(ApiTokenRow).order_by(ApiTokenRow.id))).scalars())
        finally:
            await dbsession.dispose_engine()

    return asyncio.run(_q())


def _invoke(*args: str) -> str:
    result = CliRunner().invoke(cli.app, ["token", *args])
    assert result.exit_code == 0, result.output
    return result.output.strip()


def test_create_defaults_to_ingest_only_and_gate_is_explicit(settings: Settings) -> None:
    assert TOKEN_RE.match(_invoke("create", "agent-1"))
    assert TOKEN_RE.match(_invoke("create", "gate-1", "--scope", "ingest", "--scope", "gate"))
    by_name = {r.name: r for r in _rows()}
    assert by_name["agent-1"].scopes == ["ingest"]
    assert by_name["gate-1"].scopes == ["ingest", "gate"]


def test_create_binding_options_and_validation(settings: Settings) -> None:
    _invoke("create", "web01", "--sensor-id", "web01", "--dataset", "nginx.access", "--dataset", "host.*")
    row = _rows()[0]
    assert row.allowed_sensor_ids == ["web01"] and row.allowed_datasets == ["nginx.access", "host.*"]
    for bad in (
        ["--scope", "root"],
        ["--dataset", "gate http"],
        ["--sensor-id", "a b"],
        ["--expires-in-days", "0"],
    ):
        result = CliRunner().invoke(cli.app, ["token", "create", "x", *bad])
        assert result.exit_code != 0, bad
        assert "tkw_" not in result.output


def test_list_revoke_rotate_and_expiry(settings: Settings) -> None:
    from tokiwa.util import ensure_utc, utcnow

    old = _invoke("create", "gate-1", "--scope", "ingest", "--scope", "gate")
    _invoke("create", "agent-1", "--expires-in-days", "30")
    listed = _invoke("list")
    assert "gate-1" in listed and "agent-1" in listed and "ingest,gate" in listed
    assert old not in listed and "tkw_" in listed  # prefix only, never the secret
    rows = {r.name: r for r in _rows()}
    assert rows["agent-1"].created_by == "cli" and rows["agent-1"].expires_at is not None
    assert rows["gate-1"].expires_at is None  # never expires unless asked

    # rotate: a new secret, same name/scopes; the old one stays valid for the grace period
    result = CliRunner().invoke(cli.app, ["token", "rotate", "gate-1", "--grace-hours", "2"])
    assert result.exit_code == 0, result.output
    new = result.stdout.strip().splitlines()[-1]
    assert TOKEN_RE.match(new) and new != old
    gates = [r for r in _rows() if r.name == "gate-1"]
    assert len(gates) == 2
    old_row = next(r for r in gates if r.rotated_from is None)
    new_row = next(r for r in gates if r.rotated_from == old_row.id)
    assert new_row.scopes == ["ingest", "gate"] and not old_row.revoked
    assert old_row.expires_at is not None
    left = (ensure_utc(old_row.expires_at) - utcnow()).total_seconds()
    assert 3600 < left <= 2 * 3600

    # two active "gate-1" now: a name is ambiguous, the id is not
    amb = CliRunner().invoke(cli.app, ["token", "revoke", "gate-1"])
    assert amb.exit_code == 1 and "use the id" in amb.output
    assert "revoked gate-1" in _invoke("revoke", old_row.id)
    assert "already revoked" in _invoke("revoke", old_row.id)
    assert old_row.id not in _invoke("list") and old_row.id in _invoke("list", "--all")
    missing = CliRunner().invoke(cli.app, ["token", "revoke", "nope"])
    assert missing.exit_code == 1


def test_cli_operations_are_audited(settings: Settings) -> None:
    from tokiwa.db.models.core import AuditRow

    _invoke("create", "a1")
    assert CliRunner().invoke(cli.app, ["token", "rotate", "a1", "--grace-hours", "0"]).exit_code == 0

    async def _q() -> list[tuple[str, str]]:
        dbsession.init_engine()
        try:
            async with dbsession.session_scope() as s:
                rows = (
                    await s.execute(select(AuditRow).order_by(AuditRow.created_at, AuditRow.id))
                ).scalars()
                return [(r.actor, r.action) for r in rows if r.action.startswith("token.")]
        finally:
            await dbsession.dispose_engine()

    assert asyncio.run(_q()) == [("cli", "token.create"), ("cli", "token.create"), ("cli", "token.rotate")]
    first = sorted(_rows(), key=lambda r: r.id)[0]
    assert first.revoked is True  # grace 0 = revoke now
