"""Shared limit/offset pagination for list endpoints.

Usage in a route module::

    from tokiwa.api.pagination import PageParams, paginate

    @router.get("", response_model=Page[Alert])
    async def list_alerts(session: DbSession, user: CurrentUser, page: PageParams) -> Page[Alert]:
        stmt = select(AlertRow).order_by(AlertRow.last_seen.desc())
        return await paginate(session, stmt, page, Alert.model_validate)

Kept deliberately small and generic: every list endpoint in docs/api-contract.md shares the same
``?limit`` (default 50, max 500) / ``?offset`` (max 1,000,000) contract and the ``Page[T]`` envelope.

``offset`` is bounded because an unbounded int reaches the DB driver: ``?offset=99999999999999999999`` made SQLite
raise ``OverflowError`` -> 500 (audit #94). Routes that still declare their own ``offset`` Query are covered by
:func:`offset_guard`, which the app factory attaches to every auto-discovered router.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, Query, Request
from fastapi.exceptions import RequestValidationError
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.schemas.common import Page

DEFAULT_LIMIT = 50
MAX_LIMIT = 500
# Deep offsets are an O(offset) scan anyway; past this, narrow the query with filters instead.
MAX_OFFSET = 1_000_000


@dataclass(frozen=True, slots=True)
class PageQuery:
    """Validated pagination window. Construct directly in services/tests; routes use :data:`PageParams`."""

    limit: int = DEFAULT_LIMIT
    offset: int = 0


def page_query(
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT, description="Page size (max 500)")] = DEFAULT_LIMIT,
    offset: Annotated[
        int, Query(ge=0, le=MAX_OFFSET, description="Number of items to skip (max 1,000,000)")
    ] = 0,
) -> PageQuery:
    return PageQuery(limit=limit, offset=offset)


def _too_large(raw: str) -> bool:
    """True for a plain non-negative integer above :data:`MAX_OFFSET` (length check first: no huge ``int()``)."""
    text = raw.strip().removeprefix("+")
    if not text.isascii() or not text.isdigit():
        return False  # not a plain integer: left to the route's own validation (-> 422)
    digits = text.lstrip("0") or "0"
    return len(digits) > len(str(MAX_OFFSET)) or int(digits) > MAX_OFFSET


async def offset_guard(request: Request) -> None:
    """Router-level dependency: reject ``?offset`` above :data:`MAX_OFFSET` on every API route with a 422.

    Covers list routes that declare ``offset: int = Query(0, ge=0)`` themselves instead of :data:`PageParams`
    (no ``le``), so a huge value never reaches the database driver.
    """
    for raw in request.query_params.getlist("offset"):
        if _too_large(raw):
            raise RequestValidationError(
                [
                    {
                        "type": "less_than_equal",
                        "loc": ("query", "offset"),
                        "msg": f"Input should be less than or equal to {MAX_OFFSET}",
                        "input": raw if len(raw) <= 64 else raw[:64] + "...",
                        "ctx": {"le": MAX_OFFSET},
                    }
                ]
            )


# FastAPI dependency: ``page: PageParams`` in a route signature adds ``?limit&offset``.
PageParams = Annotated[PageQuery, Depends(page_query)]


async def paginate[T, *Ts](
    session: AsyncSession,
    stmt: Select[*Ts],
    page: PageQuery,
    convert: Callable[[Any], T],
    *,
    scalars: bool = True,
) -> Page[T]:
    """Run ``stmt`` with a total count and the requested window, converting each result with ``convert``.

    ``stmt`` should carry its own ``order_by`` (stable ordering is the caller's responsibility; add the
    primary key as a tie-breaker). With ``scalars=True`` (default) ``convert`` receives the first column of
    each row (the ORM entity for ``select(Model)``); otherwise it receives the whole ``Row``.
    """
    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = int((await session.execute(count_stmt)).scalar_one())
    items: list[T] = []
    if total > page.offset:
        result = await session.execute(stmt.limit(page.limit).offset(page.offset))
        rows = result.scalars().all() if scalars else result.all()
        items = [convert(r) for r in rows]
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)
