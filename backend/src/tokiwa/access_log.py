"""Lightweight read-access log (audit #167): who viewed raw events / sessions / LLM call details / Copilot data.

Why separate from ``record_audit``: list pages poll every few seconds, so one row per read would explode the
table and turn every GET into a write transaction (SQLite has one writer). Instead identical reads -- same actor
id, route, target and filter -- within ``WINDOW`` share one row:

- the first read of a window INSERTs the row (in the request's session, so it is durable with the request);
- further reads in the window only bump in-memory counters (no DB write);
- the counters are written back (one UPDATE by primary key) when the window rolls over for that key, when the
  open set is trimmed, and before an admin reads the log (``GET /api/v1/audit/access``).

Trade-offs (documented, deliberate): counts of the last window can be lost on a crash (the first read always
survives), and each worker process keeps its own windows. Keys use the user *id*, never the username, so a
re-created user does not inherit another account's open row.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.db.models.access import AccessLogRow
from tokiwa.db.session import session_scope
from tokiwa.schemas.system import User
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

WINDOW = timedelta(minutes=5)
MAX_OPEN = 5000
MAX_FILTER_VALUE = 200


@dataclass(slots=True)
class _Open:
    row_id: str
    started: datetime
    hits: int
    items: int
    last_at: datetime
    dirty: bool = False


def clean_filters(filters: dict[str, Any] | None) -> dict[str, Any]:
    """Drop empty values, stringify the rest (bounded length) so the row stays small and JSON-safe."""
    out: dict[str, Any] = {}
    for k, v in (filters or {}).items():
        if v is None or v == "" or v == [] or v == {}:
            continue
        if isinstance(v, bool | int | float):
            out[k] = v
        elif isinstance(v, datetime):
            out[k] = v.isoformat()
        else:
            text = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str, sort_keys=True)
            out[k] = text[:MAX_FILTER_VALUE]
    return out


class AccessLogger:
    def __init__(self, window: timedelta = WINDOW, max_open: int = MAX_OPEN) -> None:
        self.window = window
        self.max_open = max_open
        self._open: dict[tuple[str, str, str, str], _Open] = {}

    async def record(
        self,
        session: AsyncSession,
        user: User,
        route: str,
        *,
        filters: dict[str, Any] | None = None,
        count: int | None = None,
        target: str | None = None,
        now: datetime | None = None,
    ) -> None:
        now = now or utcnow()
        clean = clean_filters(filters)
        key = (user.id, route, target or "", json.dumps(clean, sort_keys=True, default=str))
        n = max(0, count or 0)
        o = self._open.get(key)
        if o is not None and now - o.started < self.window:
            o.hits += 1
            o.items += n
            o.last_at = now
            o.dirty = True
            return
        if o is not None:
            await self._write_back(session, o)
        row = AccessLogRow(
            id=new_id(),
            created_at=now,
            last_at=now,
            actor=user.username,
            actor_id=user.id,
            role=str(user.role),
            route=route[:128],
            target=target[:256] if target else None,
            filters=clean,
            hits=1,
            items=n,
        )
        session.add(row)
        self._open[key] = _Open(row_id=row.id, started=now, hits=1, items=n, last_at=now)
        if len(self._open) > self.max_open:
            await self._trim(session, now)

    async def flush(self, session: AsyncSession, now: datetime | None = None) -> None:
        """Write pending counters; forget windows that have ended."""
        now = now or utcnow()
        for key, o in list(self._open.items()):
            if o.dirty:
                await self._write_back(session, o)
            if now - o.started >= self.window:
                del self._open[key]

    async def _trim(self, session: AsyncSession, now: datetime) -> None:
        await self.flush(session, now)
        if len(self._open) > self.max_open:  # still too many live windows: drop the oldest (counters saved)
            for key, o in sorted(self._open.items(), key=lambda kv: kv[1].started)[
                : len(self._open) - self.max_open
            ]:
                if o.dirty:
                    await self._write_back(session, o)
                del self._open[key]

    async def _write_back(self, session: AsyncSession, o: _Open) -> None:
        await session.execute(
            update(AccessLogRow)
            .where(AccessLogRow.id == o.row_id)
            .values(hits=o.hits, items=o.items, last_at=o.last_at)
            .execution_options(synchronize_session=False)
        )
        o.dirty = False

    def reset(self) -> None:
        self._open.clear()


access_logger = AccessLogger()


async def record_access(
    session: AsyncSession,
    user: User,
    route: str,
    *,
    filters: dict[str, Any] | None = None,
    count: int | None = None,
    target: str | None = None,
) -> None:
    """Never fails the read it describes: errors are logged, not raised."""
    try:
        await access_logger.record(session, user, route, filters=filters, count=count, target=target)
    except Exception:
        log.exception("access log: failed to record %s for %s", route, user.username)


async def record_access_detached(
    user: User, route: str, *, filters: dict[str, Any] | None = None, count: int | None = None
) -> None:
    """For code running outside a request session (e.g. Copilot tools inside the SSE generator)."""
    try:
        async with session_scope() as s:
            await access_logger.record(s, user, route, filters=filters, count=count)
    except Exception:
        log.exception("access log: failed to record %s for %s", route, user.username)
