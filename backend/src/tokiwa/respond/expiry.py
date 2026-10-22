"""Periodic expiry of active response actions (TTL). Only touches ``active`` rows: never executes anything."""

from __future__ import annotations

import logging

from tokiwa.respond.service import expire_due_actions
from tokiwa.runtime import periodic

log = logging.getLogger(__name__)


@periodic("response.expiry", every_seconds=30, initial_delay=10)
async def run_expiry() -> None:
    count = await expire_due_actions()
    if count:
        log.info("expired %d response actions", count)
