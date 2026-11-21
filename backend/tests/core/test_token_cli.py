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
    for bad in (["--scope", "root"], ["--dataset", "gate http"], ["--sensor-id", "a b"]):
        result = CliRunner().invoke(cli.app, ["token", "create", "x", *bad])
        assert result.exit_code != 0, bad
        assert "tkw_" not in result.output
