"""Response policy: the auto-approve decision and the Gate policy document.

Auto-approve is a two-key switch: ``response.auto_approve_enabled`` AND the action type listed in
``response.auto_approve_actions``. Both default to off/empty, so every action waits for a human.

The Gate policy aggregates ``active`` gate actions (block / rate_limit / tarpit / deceive) that have not yet
passed ``expires_at``, merges the deception module's decoys, and derives ``version`` from a hash of the
content so the Gate only swaps policy when something changed.

Audit #64: every active row is re-checked against the *current* ``response.*`` safety settings
(``protected_cidrs``, server addresses, ``min_prefix_*``, ``block_private_targets``) before it is served, so
adding a CIDR to ``protected_cidrs`` stops enforcement on the next poll instead of when the TTL runs out. The
row itself is moved to ``reverted`` by :func:`tokiwa.respond.service.revoke_disallowed_actions` (expiry job and
startup). Each entry also carries its expiry (``entry_expires_at``) so a Gate that loses the server stops
enforcing it on time.
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
from tokiwa.respond.validate import (
    GATE_ACTIONS,
    MAX_TARPIT_MS,
    ActionValidationError,
    Network,
    format_network,
    validate_network_target,
)
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


def refused_by_settings(
    rows: list[ResponseActionRow], settings: ResponseSettings
) -> tuple[list[ResponseActionRow], list[tuple[ResponseActionRow, str]]]:
    """Split active network rows into (still allowed, refused with the reason) under the current settings."""
    allowed: list[ResponseActionRow] = []
    refused: list[tuple[ResponseActionRow, str]] = []
    for row in rows:
        try:
            validate_network_target(row.target, settings)
        except ActionValidationError as exc:
            refused.append((row, str(exc)))
            continue
        allowed.append(row)
    return allowed, refused


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


def entry_expiries(
    rows: list[ResponseActionRow],
    blocked: list[str],
    rate_limited: dict[str, int],
    tarpit: dict[str, int],
    deceive: list[str],
) -> dict[str, dict[str, datetime]]:
    """``{section: {entry: expires_at}}`` for the policy entries built by :func:`aggregate`.

    An entry merged from several rows (collapsed CIDRs, the same key twice) expires with the *last* of them,
    and never when any of them has no expiry: the Gate must not lift something the server still serves.
    Entries without an expiry are left out.
    """
    by_type: dict[ActionType, list[tuple[Network, datetime | None]]] = {}
    for row in rows:
        try:
            atype = ActionType(row.action_type)
            net = ipaddress.ip_network(row.target, strict=False)
        except ValueError:
            continue
        by_type.setdefault(atype, []).append((net, row.expires_at))
    sections: list[tuple[str, ActionType, list[str], bool]] = [
        ("blocked", ActionType.BLOCK_IP, blocked, True),
        ("rate_limited", ActionType.RATE_LIMIT, list(rate_limited), False),
        ("tarpit", ActionType.TARPIT, list(tarpit), False),
        ("deceive", ActionType.DECEIVE, deceive, True),
    ]
    out: dict[str, dict[str, datetime]] = {}
    for name, atype, keys, collapsed in sections:
        contrib = by_type.get(atype, [])
        found: dict[str, datetime] = {}
        for key in keys:
            entry = ipaddress.ip_network(key, strict=False)
            exps = [
                exp
                for net, exp in contrib
                if net.version == entry.version and (net.subnet_of(entry) if collapsed else net == entry)  # type: ignore[arg-type]
            ]
            if not exps or any(e is None for e in exps):
                continue
            found[key] = max(e for e in exps if e is not None)
        if found:
            out[name] = found
    return out


def policy_version(
    blocked: list[str],
    rate_limited: dict[str, int],
    tarpit: dict[str, int],
    deceive: list[str],
    decoys: list[DecoyRoute],
    html_injection: str | None,
    entry_expires_at: dict[str, dict[str, datetime]] | None = None,
    html_injection_positions: list[str] | None = None,
) -> str:
    doc: dict[str, Any] = {
        "blocked": blocked,
        "rate_limited": rate_limited,
        "tarpit": tarpit,
        "deceive": deceive,
        "decoys": [d.model_dump(mode="json") for d in decoys],
        "html_injection": html_injection,
    }
    if entry_expires_at:
        # Part of the content: a renewed block (same entry, later expiry) must reach the Gate.
        doc["entry_expires_at"] = {
            section: {k: v.isoformat() for k, v in entries.items()}
            for section, entries in entry_expires_at.items()
        }
    if html_injection_positions is not None:  # deception #41: a position change must reach running gates
        doc["html_injection_positions"] = html_injection_positions
    return sha256_hex(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


async def enforceable_gate_rows(
    now: datetime, settings: ResponseSettings | None = None
) -> list[ResponseActionRow]:
    """Active, unexpired gate rows that the current settings still allow (also used by ``GET /gate/status``)."""
    s = settings or get_settings().response
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
    allowed, refused = refused_by_settings(rows, s)
    if refused:
        # Not served from now on; the expiry job moves the rows to "reverted" (with an audit entry).
        log.debug("gate policy: %d active actions refused by current settings", len(refused))
    return allowed


async def build_gate_policy(now: datetime | None = None) -> GatePolicy:
    now = now or utcnow()
    settings = get_settings().response
    rows = await enforceable_gate_rows(now, settings)
    blocked, rate_limited, tarpit, deceive = aggregate(rows, settings)
    expires = entry_expiries(rows, blocked, rate_limited, tarpit, deceive)
    try:
        decoys, html_injection = await deception_policy.build_gate_decoys()
    except Exception:
        # A deception bug must not take enforcement down: serve actions without decoys.
        log.exception("build_gate_decoys failed; serving policy without decoys")
        decoys, html_injection = [], None
    positions = deception_policy.html_injection_positions() if html_injection else None
    return GatePolicy(
        version=policy_version(
            blocked,
            rate_limited,
            tarpit,
            deceive,
            decoys,
            html_injection,
            entry_expires_at=expires,
            html_injection_positions=positions,
        ),
        generated_at=now,
        blocked=blocked,
        rate_limited=rate_limited,
        tarpit=tarpit,
        deceive=deceive,
        decoys=decoys,
        html_injection=html_injection,
        entry_expires_at=expires,
        html_injection_positions=positions,
    )
