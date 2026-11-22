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
"""

from __future__ import annotations

from fnmatch import fnmatchcase

from fastapi import APIRouter, HTTPException, status

from tokiwa.api.deps import IngestToken
from tokiwa.pipeline.service import process_events
from tokiwa.schemas.events import Event, EventKind, IngestBatch, IngestResult
from tokiwa.schemas.system import ApiToken, ApiTokenScope

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])

RESERVED_LABEL_PREFIX = "ingest."
LABEL_TOKEN_ID = "ingest.token_id"
LABEL_TOKEN_NAME = "ingest.token"
LABEL_TRUST = "ingest.trust"
LABEL_CLAIMED_SENSOR = "ingest.claimed_sensor_id"
TRUST_LOW = "low"
GATE_ONLY_DATASET_PREFIXES = ("gate.", "deception.")


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


@router.post("/events", response_model=IngestResult)
async def ingest_events(batch: IngestBatch, token: IngestToken) -> IngestResult:
    check_binding(batch.events, token)
    for e in batch.events:
        stamp_provenance(e, token)
    return await process_events(batch.events)
