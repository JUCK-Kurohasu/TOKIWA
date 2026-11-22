"""Telemetry ingest for agents / gate / adapters (token auth, scope "ingest").

Event content is client-controlled: a stolen sensor token could otherwise forge any source IP, ``sensor_id``
and dataset and frame an innocent address as an attacker (audit #40). This route therefore:

1. **records provenance on every event**: the server-owned labels ``ingest.token_id`` / ``ingest.token`` name
   the API token that delivered it. Client-sent labels under the ``ingest.`` prefix are dropped first, so
   they cannot be pre-seeded;
2. **enforces the token's binding** when one is configured (``allowed_datasets`` refuses the whole batch with
   403, ``allowed_sensor_ids`` forces ``sensor_id`` and keeps the claimed value in
   ``ingest.claimed_sensor_id``). Tokens without a binding behave as before (backwards compatible);
3. **marks gate-only telemetry from non-gate tokens as low trust** (``ingest.trust=low``): ``gate.*`` /
   ``deception.*`` datasets and DECEPTION events are produced by TOKIWA Gate, which holds a ``gate``-scoped
   token. Marking (not rejecting) is the default because the lab simulator and ``scripts/seed_demo.py`` replay
   ``gate.http`` traffic with ingest-only tokens; bind production tokens with ``allowed_datasets`` to refuse.
4. **clamps future timestamps** (audit #19): an event dated more than ``detection.max_future_skew_seconds``
   ahead of the server clock gets the ingest time instead, the tag ``clock_skew`` and its original timestamp in
   ``ingest.original_timestamp`` (rate-limited audit entry ``ingest.clock_skew`` per token). Past-dated events
   (late delivery, re-sent backlog) are not changed.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from fnmatch import fnmatchcase

from fastapi import APIRouter, HTTPException, status

from tokiwa.api.deps import IngestToken
from tokiwa.audit import record_audit
from tokiwa.config import get_settings
from tokiwa.pipeline.service import process_events
from tokiwa.schemas.events import Event, EventKind, IngestBatch, IngestResult
from tokiwa.schemas.system import ApiToken, ApiTokenScope
from tokiwa.util import ensure_utc, utcnow

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])

RESERVED_LABEL_PREFIX = "ingest."
LABEL_TOKEN_ID = "ingest.token_id"
LABEL_TOKEN_NAME = "ingest.token"
LABEL_TRUST = "ingest.trust"
LABEL_CLAIMED_SENSOR = "ingest.claimed_sensor_id"
TRUST_LOW = "low"
GATE_ONLY_DATASET_PREFIXES = ("gate.", "deception.")
LABEL_ORIGINAL_TS = "ingest.original_timestamp"
CLOCK_SKEW_TAG = "clock_skew"
CLOCK_SKEW_AUDIT_INTERVAL_S = 600.0
_last_skew_audit: dict[str, float] = {}  # token id -> monotonic time of the last audit entry


def dataset_allowed(dataset: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(dataset, p) for p in patterns)


def is_gate_only(event: Event) -> bool:
    """Telemetry that only TOKIWA Gate (a ``gate``-scoped token) legitimately produces."""
    return event.kind == EventKind.DECEPTION or event.dataset.startswith(GATE_ONLY_DATASET_PREFIXES)


def check_binding(events: list[Event], token: ApiToken) -> None:
    """Refuse the batch (403) when a bound token sends a dataset outside ``allowed_datasets``."""
    if not token.allowed_datasets:
        return
    for e in events:
        if not dataset_allowed(e.dataset, token.allowed_datasets):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"token is not allowed to send dataset {e.dataset[:64]!r}",
            )


def stamp_provenance(event: Event, token: ApiToken) -> None:
    labels = {k: v for k, v in event.labels.items() if not k.startswith(RESERVED_LABEL_PREFIX)}
    labels[LABEL_TOKEN_ID] = token.id
    labels[LABEL_TOKEN_NAME] = token.name
    allowed = token.allowed_sensor_ids
    if allowed:
        if event.sensor_id not in allowed:
            if event.sensor_id:
                labels[LABEL_CLAIMED_SENSOR] = event.sensor_id[:128]
            event.sensor_id = allowed[0]
    elif not event.sensor_id:
        event.sensor_id = f"token:{token.name}"
    if ApiTokenScope.GATE.value not in token.scopes and is_gate_only(event):
        labels[LABEL_TRUST] = TRUST_LOW
    event.labels = labels


def clamp_future_timestamp(event: Event, now: datetime, max_skew_s: float) -> float | None:
    """Replace a timestamp more than ``max_skew_s`` ahead of ``now`` with ``now``; return the lead if clamped.

    Why: one event dated far ahead dragged the session tracker's clock forward and expired every live session on
    each flush, which silently stopped AI attribution (audit #19); a sensor with a fast clock also mis-orders its
    events against everyone else's. Runs after :func:`stamp_provenance` (which drops client ``ingest.*`` labels),
    so the original value kept here is server-owned and cannot be pre-seeded. Past-dated events are left alone.
    """
    ts = ensure_utc(
        event.timestamp
    )  # naive timestamps are read as UTC (comparing naive vs aware would raise)
    lead = (ts - now).total_seconds()
    if lead <= max_skew_s:
        return None
    event.labels[LABEL_ORIGINAL_TS] = ts.isoformat()
    if CLOCK_SKEW_TAG not in event.tags:
        event.tags.append(CLOCK_SKEW_TAG)
    event.timestamp = now
    return lead


async def _report_clock_skew(token: ApiToken, clamped: list[tuple[Event, float]]) -> None:
    """Log every clamped batch; write an audit entry at most once per token per interval (never fails ingest)."""
    lead = max(x for _, x in clamped)
    sensors = sorted({e.sensor_id or "-" for e, _ in clamped})[:8]
    log.warning(
        "ingest: clamped %d future-dated event(s) from token %s (max lead %.0fs, sensors %s)",
        len(clamped),
        token.name,
        lead,
        sensors,
    )
    now_mono = time.monotonic()
    last = _last_skew_audit.get(token.id)
    if last is not None and now_mono - last < CLOCK_SKEW_AUDIT_INTERVAL_S:
        return
    _last_skew_audit[token.id] = now_mono
    try:
        await record_audit(
            f"token:{token.name}",
            "ingest.clock_skew",
            token.id,
            {"events": len(clamped), "max_lead_seconds": round(lead), "sensor_ids": sensors},
        )
    except Exception:
        log.exception("failed to record the clock-skew audit entry")


@router.post("/events", response_model=IngestResult)
async def ingest_events(batch: IngestBatch, token: IngestToken) -> IngestResult:
    check_binding(batch.events, token)
    now = utcnow()
    max_skew = get_settings().detection.max_future_skew_seconds
    clamped: list[tuple[Event, float]] = []
    for e in batch.events:
        stamp_provenance(e, token)
        lead = clamp_future_timestamp(e, now, max_skew)
        if lead is not None:
            clamped.append((e, lead))
    if clamped:
        await _report_clock_skew(token, clamped)
    return await process_events(batch.events)
