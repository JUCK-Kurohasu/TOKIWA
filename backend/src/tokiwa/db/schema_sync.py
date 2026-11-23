"""Additive schema sync for databases created by an older TOKIWA.

Why this exists: tables are created with ``Base.metadata.create_all`` (Alembic is planned, ADR-0002 /
audit #162). ``create_all`` only creates *missing tables*; it never adds a column or index to a table
that already exists. When a release adds a column to an existing model, an upgraded ``tokiwa.db``
would then fail on the first query that touches the column — and the test suite would not notice,
because every test starts from an empty database.

This module closes that gap for the one safe case: **adding** nullable columns (or columns with a
``server_default``) and **adding** indexes. It never drops, renames or retypes anything. Anything
beyond that needs a real migration.

Rule for model authors: a column added to an existing table must be ``nullable=True`` or carry a
``server_default``; otherwise :func:`sync_additive` refuses (raises) instead of guessing a value.
``tests/core/test_schema_upgrade.py`` boots the current models against the schema shipped at
commit f993282 to keep this honest.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import Column, Index, MetaData, inspect
from sqlalchemy.engine import Connection
from sqlalchemy.schema import CreateIndex

log = logging.getLogger(__name__)


class SchemaSyncError(RuntimeError):
    """A model change cannot be applied additively to an existing table."""


def _column_ddl(conn: Connection, column: Column[Any]) -> str:
    dialect = conn.dialect
    preparer = dialect.identifier_preparer
    col_type = column.type.compile(dialect=dialect)
    ddl = f"{preparer.format_column(column)} {col_type}"
    if column.server_default is not None:
        default = column.server_default
        arg = getattr(default, "arg", None)
        if arg is None:
            raise SchemaSyncError(f"unsupported server_default on {column.table.name}.{column.name}")
        if isinstance(arg, str):
            text = "'" + arg.replace("'", "''") + "'"
        else:  # TextClause / ColumnElement, e.g. sa.text("0")
            text = str(arg.compile(dialect=dialect))
        ddl += f" DEFAULT {text}"
    if not column.nullable:
        if column.server_default is None:
            raise SchemaSyncError(
                f"cannot add NOT NULL column {column.table.name}.{column.name} without server_default"
            )
        ddl += " NOT NULL"
    return ddl


def sync_additive(conn: Connection, metadata: MetaData) -> list[str]:
    """Add missing columns and indexes to existing tables. Returns the DDL statements executed."""
    insp = inspect(conn)
    existing_tables = set(insp.get_table_names())
    preparer = conn.dialect.identifier_preparer
    executed: list[str] = []
    for table in metadata.sorted_tables:
        if table.name not in existing_tables:
            continue  # create_all already made it with every column and index
        have_cols = {c["name"] for c in insp.get_columns(table.name)}
        for column in table.columns:
            if column.name in have_cols:
                continue
            if column.primary_key:
                raise SchemaSyncError(f"cannot add primary-key column {table.name}.{column.name}")
            stmt = f"ALTER TABLE {preparer.format_table(table)} ADD COLUMN {_column_ddl(conn, column)}"
            conn.exec_driver_sql(stmt)
            executed.append(stmt)
        have_idx = {i["name"] for i in insp.get_indexes(table.name)}
        for index in table.indexes:
            if index.name in have_idx:
                continue
            assert isinstance(index, Index)
            ddl = str(CreateIndex(index, if_not_exists=True).compile(dialect=conn.dialect))
            conn.exec_driver_sql(ddl)
            executed.append(ddl)
    for stmt in executed:
        log.warning("schema upgraded in place: %s", stmt)
    return executed
