"""Telemetry ingest for agents / gate / adapters (token auth, scope "ingest")."""

from __future__ import annotations

from fastapi import APIRouter

from tokiwa.api.deps import IngestToken
from tokiwa.pipeline.service import process_events
from tokiwa.schemas.events import IngestBatch, IngestResult

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])


@router.post("/events", response_model=IngestResult)
async def ingest_events(batch: IngestBatch, token: IngestToken) -> IngestResult:
    for e in batch.events:
        if not e.sensor_id:
            e.sensor_id = f"token:{token.name}"
    return await process_events(batch.events)
