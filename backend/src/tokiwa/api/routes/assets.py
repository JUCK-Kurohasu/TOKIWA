"""Asset inventory CRUD (docs/api-contract.md "ホスト・資産").

Creating/updating an asset re-runs the vulnerability matcher for it in the background (after the response is
sent) and refreshes the asset mapper's IP/hostname index. Deleting an asset removes its vulnerability matches.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import String, cast, func, or_, select

from tokiwa.api.deps import AnalystUser, CurrentUser, DbSession
from tokiwa.audit import record_audit
from tokiwa.db.models.intel import AssetRow
from tokiwa.enrich.asset_mapper import invalidate_asset_index
from tokiwa.intel.matcher import delete_matches_for_asset, run_matching
from tokiwa.schemas.common import Page, Severity
from tokiwa.schemas.intel import Asset, AssetIn, AssetKind, SoftwareItem
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


class AssetUpdate(BaseModel):
    """Partial update: only fields present in the request body are changed."""

    name: str | None = Field(default=None, max_length=255)
    kind: AssetKind | None = None
    hostname: str | None = Field(default=None, max_length=255)
    ips: list[str] | None = None
    software: list[SoftwareItem] | None = None
    criticality: Severity | None = None
    owner: str | None = Field(default=None, max_length=128)
    tags: list[str] | None = None
    notes: str | None = None


def _normalize_ips(ips: list[str]) -> list[str]:
    out: list[str] = []
    for raw in ips:
        s = (raw or "").strip()
        if not s:
            continue
        try:
            value = str(ipaddress.ip_network(s, strict=False)) if "/" in s else str(ipaddress.ip_address(s))
        except ValueError as exc:
            raise HTTPException(422, f"invalid IP address or CIDR: {raw!r}") from exc
        if value not in out:
            out.append(value)
    return out


def _clean_software(items: list[SoftwareItem]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for sw in items:
        if not sw.product or not sw.product.strip():
            raise HTTPException(422, "software.product must not be empty")
        out.append(sw.model_dump(mode="json", exclude_none=True))
    return out


def _values(data: dict[str, Any]) -> dict[str, Any]:
    """Validated request fields -> column values."""
    values: dict[str, Any] = {}
    for key, value in data.items():
        if key == "name":
            if value is None or not str(value).strip():
                raise HTTPException(422, "name must not be empty")
            values[key] = str(value).strip()
        elif key == "ips":
            values[key] = _normalize_ips(value or [])
        elif key == "software":
            values[key] = _clean_software([SoftwareItem.model_validate(s) for s in (value or [])])
        elif key in ("kind", "criticality"):
            if value is None:
                raise HTTPException(422, f"{key} must not be null")
            values[key] = str(value.value if hasattr(value, "value") else value)
        elif key == "tags":
            values[key] = [str(t).strip() for t in (value or []) if str(t).strip()]
        elif key == "hostname":
            values[key] = (value or "").strip() or None
        else:
            values[key] = value
    return values


async def _rematch(asset_id: str) -> None:
    try:
        await run_matching(asset_ids=[asset_id])
    except Exception:
        log.exception("vulnerability matching failed for asset %s", asset_id)


async def _get_or_404(session: DbSession, asset_id: str) -> AssetRow:
    row = await session.get(AssetRow, asset_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    return row


@router.get("", response_model=Page[Asset])
async def list_assets(
    session: DbSession,
    _: CurrentUser,
    q: str | None = Query(default=None, max_length=200),
    kind: AssetKind | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Page[Asset]:
    stmt = select(AssetRow)
    if kind is not None:
        stmt = stmt.where(AssetRow.kind == kind.value)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                AssetRow.name.ilike(like),
                AssetRow.hostname.ilike(like),
                cast(AssetRow.ips, String).ilike(like),
                cast(AssetRow.tags, String).ilike(like),
                cast(AssetRow.software, String).ilike(like),
            )
        )
    total = int((await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one())
    rows = (
        await session.execute(stmt.order_by(AssetRow.name, AssetRow.id).limit(limit).offset(offset))
    ).scalars()
    return Page[Asset](items=[Asset.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.post("", response_model=Asset, status_code=status.HTTP_201_CREATED)
async def create_asset(
    body: AssetIn, session: DbSession, user: AnalystUser, background: BackgroundTasks
) -> Asset:
    values = _values(body.model_dump())
    now = utcnow()
    row = AssetRow(id=new_id(), created_at=now, updated_at=now, **values)
    session.add(row)
    await session.flush()
    await record_audit(
        user.username, "asset.create", target=row.id, details={"name": row.name}, session=session
    )
    await session.commit()
    invalidate_asset_index()
    background.add_task(_rematch, row.id)
    return Asset.model_validate(row)


@router.get("/{asset_id}", response_model=Asset)
async def get_asset(asset_id: str, session: DbSession, _: CurrentUser) -> Asset:
    return Asset.model_validate(await _get_or_404(session, asset_id))


@router.patch("/{asset_id}", response_model=Asset)
async def update_asset(
    asset_id: str, body: AssetUpdate, session: DbSession, user: AnalystUser, background: BackgroundTasks
) -> Asset:
    row = await _get_or_404(session, asset_id)
    values = _values(body.model_dump(exclude_unset=True))
    for key, value in values.items():
        setattr(row, key, value)
    row.updated_at = utcnow()
    await session.flush()
    await record_audit(
        user.username, "asset.update", target=row.id, details={"fields": sorted(values)}, session=session
    )
    await session.commit()
    invalidate_asset_index()
    if "software" in values:
        background.add_task(_rematch, row.id)
    return Asset.model_validate(row)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(asset_id: str, session: DbSession, user: AnalystUser) -> Response:
    row = await _get_or_404(session, asset_id)
    name = row.name
    await delete_matches_for_asset(session, asset_id)
    await session.delete(row)
    await record_audit(
        user.username, "asset.delete", target=asset_id, details={"name": name}, session=session
    )
    await session.commit()
    invalidate_asset_index()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
