"""Gate policy pulled by TOKIWA Gate (API token with scope "gate"), and whether it is being pulled.

Supports ``If-None-Match`` with the policy ``version`` (sent back as a quoted ``ETag``) so polling Gates can
skip unchanged bodies with a 304.

Every poll (200 and 304) is recorded per Gate instance (token + source address) so ``GET /gate/status`` can
show whether an approved block is actually in a Gate's hands (audit #145). Approving an action only marks it
``active``; without a Gate polling, nothing is enforced.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Header, Request, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from tokiwa.api.deps import CurrentUser, GateToken
from tokiwa.config import get_settings
from tokiwa.db.models.gate_status import GatePollRow
from tokiwa.db.session import session_scope
from tokiwa.respond.policy import build_gate_policy, enforceable_gate_rows
from tokiwa.schemas.gate_status import GateActionReflection, GateInstance, GateStatus
from tokiwa.schemas.response import GatePolicy
from tokiwa.schemas.system import ApiToken
from tokiwa.util import sha256_hex, utcnow

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/gate", tags=["gate"])

# A Gate that has not polled for this long is reported as stale. The Gate polls every
# ``gate.policy_refresh_seconds`` (default 5 s); allow generous slack for restarts and network hiccups.
# TODO(verify): the server reads its own copy of that setting; a Gate configured differently is not known here.
_STALE_MIN_SECONDS = 120
_STALE_POLL_MULTIPLIER = 12


def stale_after_seconds() -> int:
    refresh = float(get_settings().gate.policy_refresh_seconds or 0)
    return int(max(_STALE_MIN_SECONDS, refresh * _STALE_POLL_MULTIPLIER))


def _poll_id(token_id: str, source_ip: str) -> str:
    return sha256_hex(f"{token_id}|{source_ip}")[:32]


async def record_poll(
    token: ApiToken, source_ip: str, version: str, fetched_at: datetime, status: int
) -> None:
    """Upsert this Gate's last poll. Never raises: a bookkeeping failure must not stop policy delivery."""
    key = _poll_id(token.id, source_ip)
    for attempt in range(2):
        try:
            async with session_scope() as session:
                row = await session.get(GatePollRow, key)
                if row is None:
                    session.add(
                        GatePollRow(
                            id=key,
                            token_id=token.id,
                            token_name=token.name[:128],
                            source_ip=source_ip[:64],
                            first_seen=fetched_at,
                            last_seen=fetched_at,
                            last_version=version,
                            last_status=status,
                            fetch_count=1,
                        )
                    )
                else:
                    row.token_name = token.name[:128]
                    row.last_seen = max(row.last_seen, fetched_at)
                    row.last_version = version
                    row.last_status = status
                    row.fetch_count = (row.fetch_count or 0) + 1
            return
        except IntegrityError:
            if attempt == 0:
                continue  # a concurrent first poll inserted the row: update it instead
            log.exception("could not record gate poll (token %s)", token.name)
        except Exception:
            log.exception("could not record gate poll (token %s)", token.name)
            return


@router.get("/policy", response_model=GatePolicy, responses={304: {"description": "Not modified"}})
async def gate_policy(
    token: GateToken,
    request: Request,
    response: Response,
    if_none_match: Annotated[str | None, Header()] = None,
) -> GatePolicy | Response:
    policy = await build_gate_policy()
    source_ip = request.client.host if request.client else "unknown"
    etag = f'"{policy.version}"'
    if if_none_match is not None:
        candidates = {c.strip() for c in if_none_match.split(",")}
        if etag in candidates or policy.version in candidates or f"W/{etag}" in candidates:
            await record_poll(token, source_ip, policy.version, policy.generated_at, 304)
            return Response(status_code=304, headers={"ETag": etag})
    await record_poll(token, source_ip, policy.version, policy.generated_at, 200)
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "no-cache"
    return policy


@router.get("/status", response_model=GateStatus)
async def gate_status(_: CurrentUser) -> GateStatus:
    """Gates that pulled the policy, and for each active Gate action how many Gates hold a policy containing it.

    A Gate holds an action when its last poll (200, or 304 = "my copy is current") was served a policy generated
    after the action became active. Known limits: a poll within milliseconds of the approval can be counted
    before the approving transaction commits; Gates behind one reverse proxy share a source address.
    """
    now = utcnow()
    stale = timedelta(seconds=stale_after_seconds())
    policy = await build_gate_policy(now)
    async with session_scope() as session:
        polls = list(
            (await session.execute(select(GatePollRow).order_by(GatePollRow.last_seen.desc()))).scalars()
        )
    # Same rows the policy is built from: one refused by the current settings is not served (audit #64), so it
    # must not be reported as applied either.
    actions = await enforceable_gate_rows(now)
    gates = [
        GateInstance.model_validate(p).model_copy(
            update={"current": p.last_version == policy.version, "stale": now - p.last_seen > stale}
        )
        for p in polls
    ]
    reflections: list[GateActionReflection] = []
    for a in actions:
        since = a.executed_at or a.approved_at or a.created_at
        holding = [g for g in gates if g.last_seen >= since]
        reflections.append(
            GateActionReflection(
                action_id=a.id,
                active_since=since,
                gates_applied=len(holding),
                gates_applied_fresh=sum(1 for g in holding if not g.stale),
                last_applied_at=max((g.last_seen for g in holding), default=None),
            )
        )
    return GateStatus(
        generated_at=now,
        current_version=policy.version,
        stale_after_seconds=int(stale.total_seconds()),
        gates=gates,
        actions=reflections,
    )
