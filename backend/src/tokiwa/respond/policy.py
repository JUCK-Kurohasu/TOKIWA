"""Response policy: the auto-approve decision and the Gate policy document.

Auto-approve is a two-key switch: ``response.auto_approve_enabled`` AND the action type listed in
``response.auto_approve_actions``. Both default to off/empty, so every action waits for a human.

The Gate policy aggregates ``active`` gate actions (block / rate_limit / tarpit / deceive) that have not yet
passed ``expires_at``, merges the deception module's decoys, and derives ``version`` from a hash of the
content so the Gate only swaps policy when something changed.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime
from typing import Any

from sqlalchemy import or_, select

from tokiwa.config import ResponseSettings, get_settings
from tokiwa.db.models.response import ResponseActionRow
from tokiwa.db.session import session_scope
from tokiwa.deception import policy as deception_policy
from tokiwa.respond.validate import GATE_ACTIONS, MAX_TARPIT_MS, Network, format_network
from tokiwa.schemas.response import ActionStatus, DecoyRoute, GatePolicy
from tokiwa.schemas.triage import ActionType
from tokiwa.util import sha256_hex, utcnow

log = logging.getLogger(__name__)


def auto_approve_allowed(action_type: ActionType, settings: ResponseSettings | None = None) -> bool:
    """True only when auto-approve is enabled AND this action type is explicitly allow-listed."""
    s = settings or get_settings().response
    if s.auto_approve_enabled is not True:
        return False
    allowed = {str(a).strip() for a in s.auto_approve_actions}
    return action_type.value in allowed


def _collapse(nets: list[Network]) -> list[str]:
    """Merge duplicates / contained / adjacent networks per address family; stable order."""
    v4 = [n for n in nets if isinstance(n, ipaddress.IPv4Network)]
    v6 = [n for n in nets if isinstance(n, ipaddress.IPv6Network)]
    merged: list[Network] = [*ipaddress.collapse_addresses(v4), *ipaddress.collapse_addresses(v6)]
    merged.sort(key=lambda n: (n.version, int(n.network_address), n.prefixlen))
    return [format_network(n) for n in merged]


def _int(value: Any, default: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def aggregate(
    rows: list[ResponseActionRow], settings: ResponseSettings
) -> tuple[list[str], dict[str, int], dict[str, int], list[str]]:
    """(blocked, rate_limited, tarpit, deceive) from active gate actions."""
    blocked: list[Network] = []
    deceive: list[Network] = []
    rate: dict[str, int] = {}
    tarpit: dict[str, int] = {}
    for row in rows:
        try:
            atype = ActionType(row.action_type)
            net = ipaddress.ip_network(row.target, strict=False)
        except ValueError:
            log.warning("skipping malformed active action %s (%s %r)", row.id, row.action_type, row.target)
            continue
        key = format_network(net)
        params = row.params or {}
        if atype is ActionType.BLOCK_IP:
            blocked.append(net)
        elif atype is ActionType.DECEIVE:
            deceive.append(net)
        elif atype is ActionType.RATE_LIMIT:
            rpm = max(1, _int(params.get("requests_per_minute"), settings.default_rate_limit_rpm))
            rate[key] = min(rate.get(key, rpm), rpm)  # strictest wins
        elif atype is ActionType.TARPIT:
            ms = min(MAX_TARPIT_MS, max(1, _int(params.get("delay_ms"), settings.default_tarpit_delay_ms)))
            tarpit[key] = max(tarpit.get(key, ms), ms)  # strictest wins
    return (
        _collapse(blocked),
        dict(sorted(rate.items())),
        dict(sorted(tarpit.items())),
        _collapse(deceive),
    )


def policy_version(
    blocked: list[str],
    rate_limited: dict[str, int],
    tarpit: dict[str, int],
    deceive: list[str],
    decoys: list[DecoyRoute],
    html_injection: str | None,
) -> str:
    doc = {
        "blocked": blocked,
        "rate_limited": rate_limited,
        "tarpit": tarpit,
        "deceive": deceive,
        "decoys": [d.model_dump(mode="json") for d in decoys],
        "html_injection": html_injection,
    }
    return sha256_hex(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


async def build_gate_policy(now: datetime | None = None) -> GatePolicy:
    now = now or utcnow()
    settings = get_settings().response
    async with session_scope() as session:
        rows = list(
            (
                await session.execute(
                    select(ResponseActionRow)
                    .where(
                        ResponseActionRow.status == ActionStatus.ACTIVE.value,
                        ResponseActionRow.action_type.in_([t.value for t in GATE_ACTIONS]),
                        or_(ResponseActionRow.expires_at.is_(None), ResponseActionRow.expires_at > now),
                    )
                    .order_by(ResponseActionRow.created_at)
                )
            )
            .scalars()
            .all()
        )
    blocked, rate_limited, tarpit, deceive = aggregate(rows, settings)
    try:
        decoys, html_injection = await deception_policy.build_gate_decoys()
    except Exception:
        # A deception bug must not take enforcement down: serve actions without decoys.
        log.exception("build_gate_decoys failed; serving policy without decoys")
        decoys, html_injection = [], None
    return GatePolicy(
        version=policy_version(blocked, rate_limited, tarpit, deceive, decoys, html_injection),
        generated_at=now,
        blocked=blocked,
        rate_limited=rate_limited,
        tarpit=tarpit,
        deceive=deceive,
        decoys=decoys,
        html_injection=html_injection,
    )
