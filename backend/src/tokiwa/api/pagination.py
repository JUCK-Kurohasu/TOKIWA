"""Shared limit/offset pagination for list endpoints.

Usage in a route module::

    from tokiwa.api.pagination import PageParams, paginate

    @router.get("", response_model=Page[Alert])
    async def list_alerts(session: DbSession, user: CurrentUser, page: PageParams) -> Page[Alert]:
        stmt = select(AlertRow).order_by(AlertRow.last_seen.desc())
        return await paginate(session, stmt, page, Alert.model_validate)

Kept deliberately small and generic: every list endpoint in docs/api-contract.md shares the same
``?limit`` (default 50, max 500) / ``?offset`` contract and the ``Page[T]`` envelope.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, Query
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.schemas.common import Page

DEFAULT_LIMIT = 50
MAX_LIMIT = 500


@dataclass(frozen=True, slots=True)
class PageQuery:
    """Validated pagination window. Construct directly in services/tests; routes use :data:`PageParams`."""

    limit: int = DEFAULT_LIMIT
    offset: int = 0


def page_query(
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT, description="Page size (max 500)")] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0, description="Number of items to skip")] = 0,
) -> PageQuery:
    return PageQuery(limit=limit, offset=offset)


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
