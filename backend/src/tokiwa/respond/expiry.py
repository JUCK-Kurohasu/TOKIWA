"""Periodic expiry of active response actions (TTL). Only touches ``active`` rows: never executes anything.

Also reverts active network actions that the current settings now refuse (audit #64), e.g. after a CIDR was
added to ``response.protected_cidrs``.
"""

from __future__ import annotations

import logging

from tokiwa.respond.service import expire_due_actions, revoke_disallowed_actions
from tokiwa.runtime import periodic

log = logging.getLogger(__name__)


@periodic("response.expiry", every_seconds=30, initial_delay=10)
async def run_expiry() -> None:
    count = await expire_due_actions()
    if count:
        log.info("expired %d response actions", count)
    revoked = await revoke_disallowed_actions()
    if revoked:
        log.info("reverted %d response actions refused by the current settings", revoked)
