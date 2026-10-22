"""Mirage deception API (docs/api-contract.md "デセプション"). OWNER: deception module."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Response, status

from tokiwa.api.deps import AnalystUser, CurrentUser
from tokiwa.deception import service
from tokiwa.schemas.common import Page
from tokiwa.schemas.deception import DeceptionAssetUpdate, DeceptionPreview
from tokiwa.schemas.events import Event
from tokiwa.schemas.response import DeceptionAsset, DeceptionAssetIn, DeceptionKind

router = APIRouter(prefix="/api/v1/deception", tags=["deception"])


def _http_error(exc: service.DeceptionError) -> HTTPException:
    return HTTPException(exc.status_code, str(exc))


@router.get("/assets", response_model=list[DeceptionAsset])
async def list_assets(
    user: CurrentUser,
    kind: DeceptionKind | None = None,
    enabled: bool | None = None,
) -> list[DeceptionAsset]:
    return await service.list_assets(kind=kind, enabled=enabled)


@router.post("/assets", response_model=DeceptionAsset)
async def create_asset(body: DeceptionAssetIn, user: AnalystUser) -> DeceptionAsset:
    try:
        return await service.create_asset(body, actor=user.username)
    except service.DeceptionError as exc:
        raise _http_error(exc) from exc


@router.get("/assets/{asset_id}", response_model=DeceptionAsset)
async def get_asset(asset_id: str, user: CurrentUser) -> DeceptionAsset:
    asset = await service.get_asset(asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "deception asset not found")
    return asset


@router.patch("/assets/{asset_id}", response_model=DeceptionAsset)
async def update_asset(asset_id: str, body: DeceptionAssetUpdate, user: AnalystUser) -> DeceptionAsset:
    try:
        asset = await service.update_asset(asset_id, body, actor=user.username)
    except service.DeceptionError as exc:
        raise _http_error(exc) from exc
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "deception asset not found")
    return asset


@router.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(asset_id: str, user: AnalystUser) -> Response:
    if not await service.delete_asset(asset_id, actor=user.username):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "deception asset not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/trips", response_model=Page[Event])
async def list_trips(
    user: CurrentUser,
    asset_id: str | None = None,
    source_ip: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[Event]:
    return await service.list_trips(asset_id=asset_id, source_ip=source_ip, limit=limit, offset=offset)


@router.get("/preview/{asset_id}", response_model=DeceptionPreview)
async def preview_asset(
    asset_id: str,
    user: AnalystUser,
    path: Annotated[str | None, Query(max_length=512, description="labyrinth page to render")] = None,
) -> DeceptionPreview:
    preview = await service.preview_asset(asset_id, path)
    if preview is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "deception asset not found")
    return preview
