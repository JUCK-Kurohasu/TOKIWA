"""Registered detectors: list and runtime enable/disable.

Overrides are kept in ``engine.overrides`` (effective immediately) and persisted in
``settings_kv["detection.overrides"]`` as ``{detector_id: bool}``; :func:`restore_detector_overrides` puts them
back on startup so a restart does not silently re-enable a detector an analyst turned off.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from tokiwa.api.deps import AnalystUser, CurrentUser, DbSession
from tokiwa.audit import record_audit
from tokiwa.db.models.core import SettingRow
from tokiwa.detect.base import Detector
from tokiwa.detect.engine import DetectionEngine, get_detection_engine
from tokiwa.runtime import on_startup
from tokiwa.schemas.system import DetectorInfo
from tokiwa.settings_store import get_setting
from tokiwa.util import utcnow

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/detectors", tags=["detectors"])

OVERRIDES_KEY = "detection.overrides"


class DetectorUpdate(BaseModel):
    enabled: bool


def _info(engine: DetectionEngine, det: Detector) -> DetectorInfo:
    return DetectorInfo(
        id=det.id,
        name=det.name,
        description=det.description,
        category=str(det.category),
        kinds=sorted(str(k) for k in det.kinds),
        enabled=engine.is_enabled(det),
        mitre=list(det.mitre),
    )


@router.get("", response_model=list[DetectorInfo])
async def list_detectors(user: CurrentUser) -> list[DetectorInfo]:
    engine = get_detection_engine()
    return [_info(engine, d) for _, d in sorted(engine.all_detectors().items())]


@router.patch("/{detector_id}", response_model=DetectorInfo)
async def update_detector(
    detector_id: str, body: DetectorUpdate, session: DbSession, user: AnalystUser
) -> DetectorInfo:
    engine = get_detection_engine()
    det = engine.all_detectors().get(detector_id)
    if det is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "detector not found")
    before = engine.is_enabled(det)
    row = await session.get(SettingRow, OVERRIDES_KEY)
    stored = {k: v for k, v in dict(row.value or {}).items() if isinstance(v, bool)} if row else {}
    stored[detector_id] = body.enabled
    if row is None:
        session.add(SettingRow(key=OVERRIDES_KEY, value=stored, updated_at=utcnow()))
    else:
        row.value = stored  # new dict object so the JSON column change is detected
        row.updated_at = utcnow()
    await record_audit(
        user.username,
        "detector.update",
        detector_id,
        {"enabled": body.enabled, "previous": before},
        session=session,
    )
    await session.commit()
    engine.overrides[detector_id] = body.enabled
    return _info(engine, det)


@on_startup
async def restore_detector_overrides() -> None:
    """Re-apply persisted enable/disable choices to the (fresh) detection engine."""
    try:
        stored = await get_setting(OVERRIDES_KEY)
    except Exception:
        log.exception("could not read %s; detector overrides not restored", OVERRIDES_KEY)
        return
    engine = get_detection_engine()
    for det_id, enabled in stored.items():
        if isinstance(enabled, bool):
            engine.overrides[det_id] = enabled
