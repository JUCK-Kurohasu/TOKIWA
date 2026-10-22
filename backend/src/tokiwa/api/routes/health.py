from __future__ import annotations

from fastapi import APIRouter

from tokiwa import __version__

router = APIRouter(prefix="/api/v1", tags=["system"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
