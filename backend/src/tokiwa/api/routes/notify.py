"""Notification channels (admin only). Secrets in channel configs are masked on every read."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel

from tokiwa.api.deps import AdminUser
from tokiwa.notify import service
from tokiwa.notify.channels import ChannelConfigError
from tokiwa.schemas.response import NotificationChannel, NotificationChannelIn

router = APIRouter(prefix="/api/v1/notify", tags=["notify"])


class ChannelTestResult(BaseModel):
    ok: bool
    error: str | None = None


@router.get("/channels", response_model=list[NotificationChannel])
async def list_channels(user: AdminUser) -> list[NotificationChannel]:
    return await service.list_channels()


@router.post("/channels", response_model=NotificationChannel)
async def create_channel(body: NotificationChannelIn, user: AdminUser) -> NotificationChannel:
    try:
        return await service.create_channel(body, actor=user.username)
    except ChannelConfigError as exc:
        raise HTTPException(422, f"invalid config: {exc}") from None


@router.patch("/channels/{channel_id}", response_model=NotificationChannel)
async def update_channel(channel_id: str, body: service.ChannelPatch, user: AdminUser) -> NotificationChannel:
    try:
        return await service.update_channel(channel_id, body, actor=user.username)
    except service.ChannelNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found") from None
    except ChannelConfigError as exc:
        raise HTTPException(422, f"invalid config: {exc}") from None


@router.delete("/channels/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_channel(channel_id: str, user: AdminUser) -> Response:
    try:
        await service.delete_channel(channel_id, actor=user.username)
    except service.ChannelNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found") from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/channels/{channel_id}/test", response_model=ChannelTestResult)
async def send_test(channel_id: str, user: AdminUser) -> ChannelTestResult:
    """Send a test message (``default`` = the env-configured default webhook)."""
    try:
        result = await service.send_channel_test(channel_id)
    except service.ChannelNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found") from None
    return ChannelTestResult(ok=result.ok, error=result.error)
