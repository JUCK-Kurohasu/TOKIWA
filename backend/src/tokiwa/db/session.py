"""Async engine / session management.

Usage in API routes: ``session: DbSession`` (see tokiwa.api.deps).
Usage in services / jobs: ``async with session_scope() as session: ...`` (commits on success).
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from tokiwa.config import get_settings
from tokiwa.db import sanitize
from tokiwa.db.base import Base

sanitize.install()  # NUL / lone surrogates / VARCHAR overflow never fail a flush (audit #25)

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _ensure_sqlite_dir(url: str) -> None:
    prefix = "sqlite+aiosqlite:///"
    if url.startswith(prefix):
        path = url[len(prefix) :]
        if path and path != ":memory:":
            Path(path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)  # new dirs only (#102)
            if "?" not in path and not path.startswith("file:"):  # SQLite gives -wal/-shm the DB file's mode
                with contextlib.suppress(FileExistsError):
                    os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))


def init_engine(url: str | None = None, echo: bool | None = None) -> AsyncEngine:
    global _engine, _sessionmaker
    settings = get_settings()
    url = url or settings.database.url
    _ensure_sqlite_dir(url)
    kwargs: dict[str, object] = {"echo": settings.database.echo if echo is None else echo}
    kwargs["hide_parameters"] = True  # DB errors must not print bound values (password hashes, tokens): #163
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"timeout": 30}
    _engine = create_async_engine(url, **kwargs)  # type: ignore[arg-type]
    if url.startswith("sqlite"):

        @event.listens_for(_engine.sync_engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):  # type: ignore[no-untyped-def]
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_engine() -> AsyncEngine:
    if _engine is None:
        return init_engine()
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    if _sessionmaker is None:
        init_engine()
    assert _sessionmaker is not None
    return _sessionmaker


async def create_all() -> None:
    """Create tables, then add any new nullable columns / indexes to tables that already exist.

    Alembic migrations are planned before v1.0 (ADR-0002, audit #162); until then
    :func:`tokiwa.db.schema_sync.sync_additive` keeps an upgraded database usable.
    """
    from tokiwa.db import models  # noqa: F401  - registers all model modules
    from tokiwa.db.schema_sync import sync_additive

    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(sync_additive, Base.metadata)


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    session = get_sessionmaker()()
    try:
        yield session
        await session.commit()
    except BaseException:
        await session.rollback()
        raise
    finally:
        await session.close()


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency; declare it as ``Depends(get_session, scope="function")`` (``tokiwa.api.deps.DbSession``).

    Why the scope matters: with FastAPI's default ``"request"`` scope the code after ``yield`` (the commit) runs
    after the response has been sent. A client then gets 204 for "revoke token" while the token still works for
    a few ms, and a commit that fails (lock, constraint) is silently lost behind a 2xx (audit #91).
    ``"function"`` scope runs the commit after the route returns and before the response starts, so a failing
    commit surfaces as an error response (IntegrityError -> 409 in ``tokiwa.api.app``). Verified against the
    installed FastAPI by ``tests/api/test_commit_timing.py``.
    """
    async with session_scope() as session:
        yield session
