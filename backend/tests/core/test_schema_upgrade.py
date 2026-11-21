"""An upgraded database (schema from an older release) must work with the current models.

Every other test starts from an empty database, so a column added to an existing model would pass
CI and still break ``tokiwa serve`` on an existing ``tokiwa.db``. This test loads the schema that
``create_all`` produced at commit f993282 (before the 2026-11 audit fixes) and boots the current
models on top of it.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, inspect, text

from tokiwa.config import Settings
from tokiwa.db import session as dbsession
from tokiwa.db.base import Base
from tokiwa.db.schema_sync import SchemaSyncError, sync_additive

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "schema-f993282.sqlite.sql"


def _db_path(settings: Settings) -> Path:
    url = settings.database.url
    return Path(url.split("sqlite+aiosqlite:///", 1)[1])


async def test_current_models_boot_on_f993282_schema(settings: Settings) -> None:
    path = _db_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.executescript(FIXTURE.read_text())
    con.close()

    dbsession.init_engine()
    try:
        await dbsession.create_all()
        async with dbsession.get_engine().connect() as conn:

            def _check(sync_conn):  # type: ignore[no-untyped-def]
                insp = inspect(sync_conn)
                missing: list[str] = []
                for table in Base.metadata.sorted_tables:
                    have = {c["name"] for c in insp.get_columns(table.name)}
                    missing += [f"{table.name}.{c.name}" for c in table.columns if c.name not in have]
                    have_idx = {i["name"] for i in insp.get_indexes(table.name)}
                    missing += [f"index {i.name}" for i in table.indexes if i.name not in have_idx]
                return missing

            assert await conn.run_sync(_check) == []
            # every mapped table is queryable with every mapped column
            for table in Base.metadata.sorted_tables:
                await conn.execute(table.select().limit(1))
        # idempotent: a second boot changes nothing
        async with dbsession.get_engine().begin() as conn:
            assert await conn.run_sync(sync_additive, Base.metadata) == []
    finally:
        await dbsession.dispose_engine()


async def test_sync_adds_nullable_column_and_rejects_not_null(settings: Settings) -> None:
    dbsession.init_engine()
    try:
        async with dbsession.get_engine().begin() as conn:
            await conn.execute(text("CREATE TABLE demo (id INTEGER PRIMARY KEY)"))

        md = MetaData()
        Table("demo", md, Column("id", Integer, primary_key=True), Column("note", String(10), nullable=True))
        async with dbsession.get_engine().begin() as conn:
            executed = await conn.run_sync(sync_additive, md)
        assert len(executed) == 1 and "ADD COLUMN" in executed[0]

        bad = MetaData()
        Table(
            "demo", bad, Column("id", Integer, primary_key=True), Column("must", String(10), nullable=False)
        )
        with pytest.raises(SchemaSyncError):
            async with dbsession.get_engine().begin() as conn:
                await conn.run_sync(sync_additive, bad)

        ok = MetaData()
        Table(
            "demo",
            ok,
            Column("id", Integer, primary_key=True),
            Column("flag", Integer, nullable=False, server_default=text("0")),
        )
        async with dbsession.get_engine().begin() as conn:
            await conn.run_sync(sync_additive, ok)
            await conn.execute(text("INSERT INTO demo (id) VALUES (1)"))
            assert (await conn.execute(text("SELECT flag FROM demo"))).scalar_one() == 0
    finally:
        await dbsession.dispose_engine()
