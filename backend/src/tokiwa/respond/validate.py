"""Proposal validation: turn an untrusted proposal (user / rule / LLM) into typed, executor-safe values.

Everything an executor ever sees comes out of :func:`validate_action`:
- ``target``: normalized IP / CIDR for network actions (never a hostname, never free text), a safe path for
  ``deploy_canary``, or a restricted identifier for ``notify`` / ``webhook``.
- ``params``: only allow-listed keys per action type, type-checked and range-checked; defaults filled in.
- ``ttl_minutes``: required for reversible actions, capped at ``response.max_ttl_minutes``.

Self-lockout protection: network targets must not overlap ``response.protected_cidrs`` (loopback by default)
or this server's own interface addresses, must not be broader than ``min_prefix_v4/v6``, and are never
unspecified / multicast / broadcast addresses. Private targets can be refused with
``response.block_private_targets`` (management networks).
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from tokiwa.config import ResponseSettings, get_settings
from tokiwa.schemas.triage import ActionType

log = logging.getLogger(__name__)

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

# Actions enforced by the Gate from DB state (GET /api/v1/gate/policy).
GATE_ACTIONS: frozenset[ActionType] = frozenset(
    {ActionType.BLOCK_IP, ActionType.RATE_LIMIT, ActionType.TARPIT, ActionType.DECEIVE}
)
# Actions whose target must be an IP / CIDR.
NETWORK_ACTIONS: frozenset[ActionType] = GATE_ACTIONS | {ActionType.NFTABLES_BLOCK}
# Fire-and-forget actions: no TTL, nothing to revert.
ONE_SHOT_ACTIONS: frozenset[ActionType] = frozenset({ActionType.NOTIFY, ActionType.WEBHOOK})
# Actions that stay in effect until expires_at (then reverted by the expiry job).
TTL_ACTIONS: frozenset[ActionType] = NETWORK_ACTIONS | {ActionType.DEPLOY_CANARY}

MAX_TARPIT_MS = 30_000
MAX_RATE_LIMIT_RPM = 100_000
CANARY_KINDS = frozenset({"decoy_path", "honeytoken", "ai_canary"})

_ALLOWED_PARAMS: dict[ActionType, frozenset[str]] = {
    ActionType.BLOCK_IP: frozenset(),
    ActionType.RATE_LIMIT: frozenset({"requests_per_minute"}),
    ActionType.TARPIT: frozenset({"delay_ms"}),
    ActionType.DECEIVE: frozenset(),
    ActionType.DEPLOY_CANARY: frozenset({"kind"}),
    ActionType.NOTIFY: frozenset({"channel_id"}),
    ActionType.WEBHOOK: frozenset({"endpoint"}),
    ActionType.NFTABLES_BLOCK: frozenset(),
}

_SAFE_IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$")
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~/-]{0,255}$")
_REF_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_CHANNEL_ID = re.compile(r"^(default|[0-9a-f]{32})$")
_ENDPOINT_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class ActionValidationError(ValueError):
    """The proposal is not acceptable. The message is safe to show to users."""


@dataclass(frozen=True)
class ValidatedAction:
    action_type: ActionType
    target: str
    params: Mapping[str, str | int] = field(default_factory=dict)
    ttl_minutes: int | None = None
    reversible: bool = True
    incident_id: str | None = None
    alert_id: str | None = None
    notes: tuple[str, ...] = ()


# ---------------------------------------------------------------- network targets


@lru_cache(maxsize=1)
def _server_addresses() -> tuple[str, ...]:
    """Addresses bound to this host's interfaces (best effort, cached)."""
    try:
        import psutil

        out: list[str] = []
        for entries in psutil.net_if_addrs().values():
            for e in entries:
                if e.family in (socket.AF_INET, socket.AF_INET6):
                    out.append(str(e.address).split("%", 1)[0])
        return tuple(out)
    except Exception:
        log.exception("could not enumerate server interface addresses")
        return ()


def reset_server_address_cache() -> None:
    _server_addresses.cache_clear()


def protected_networks(settings: ResponseSettings) -> list[Network]:
    nets: list[Network] = []
    for cidr in settings.protected_cidrs:
        try:
            nets.append(ipaddress.ip_network(cidr.strip(), strict=False))
        except ValueError:
            log.error("ignoring invalid response.protected_cidrs entry %r", cidr)
    if settings.protect_server_addresses:
        for addr in _server_addresses():
            try:
                nets.append(ipaddress.ip_network(addr))
            except ValueError:
                continue
    return nets


def format_network(net: Network) -> str:
    """Single hosts are rendered as a bare address, everything else as CIDR."""
    return str(net.network_address) if net.num_addresses == 1 else str(net)


def parse_network(target: str) -> Network:
    """Parse an IP or CIDR (host bits are cleared). IPv4-mapped IPv6 hosts become IPv4."""
    t = target.strip()
    if not t or len(t) > 64 or "%" in t:
        raise ActionValidationError("target must be an IP address or CIDR")
    try:
        net: Network = ipaddress.ip_network(t, strict=False)
    except ValueError as exc:
        raise ActionValidationError("target must be an IP address or CIDR") from exc
    if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped is not None:
        if net.num_addresses != 1:
            raise ActionValidationError("use IPv4 notation for IPv4-mapped networks")
        net = ipaddress.ip_network(net.network_address.ipv4_mapped)
    return net


def validate_network_target(target: str, settings: ResponseSettings) -> str:
    net = parse_network(target)
    min_prefix = settings.min_prefix_v4 if net.version == 4 else settings.min_prefix_v6
    if net.prefixlen < min_prefix:
        raise ActionValidationError(f"target {net} is broader than the allowed minimum prefix /{min_prefix}")
    addr = net.network_address
    if addr.is_unspecified or net.is_multicast:
        raise ActionValidationError(f"target {net} is not a unicast address")
    if net.version == 4 and net.broadcast_address == ipaddress.IPv4Address("255.255.255.255"):
        raise ActionValidationError(f"target {net} is not a unicast address")
    for p in protected_networks(settings):
        if p.version == net.version and net.overlaps(p):
            raise ActionValidationError(f"target {format_network(net)} overlaps protected network {p}")
    if settings.block_private_targets and (net.is_private or net.is_link_local):
        raise ActionValidationError(
            f"target {format_network(net)} is a private address (response.block_private_targets)"
        )
    return format_network(net)


# ---------------------------------------------------------------- params


def _int_param(params: Mapping[str, Any], key: str, default: int, lo: int, hi: int) -> int:
    value = params.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ActionValidationError(f"params.{key} must be an integer")
    if not lo <= value <= hi:
        raise ActionValidationError(f"params.{key} must be between {lo} and {hi}")
    return value


def _validate_params(
    action_type: ActionType, params: Mapping[str, Any], settings: ResponseSettings
) -> dict[str, str | int]:
    if not isinstance(params, Mapping):
        raise ActionValidationError("params must be an object")
    unknown = sorted(set(params) - _ALLOWED_PARAMS[action_type])
    if unknown:
        raise ActionValidationError(f"params not allowed for {action_type.value}: {', '.join(unknown)}")
    out: dict[str, str | int] = {}
    if action_type is ActionType.RATE_LIMIT:
        out["requests_per_minute"] = _int_param(
            params, "requests_per_minute", settings.default_rate_limit_rpm, 1, MAX_RATE_LIMIT_RPM
        )
    elif action_type is ActionType.TARPIT:
        out["delay_ms"] = _int_param(
            params, "delay_ms", min(settings.default_tarpit_delay_ms, MAX_TARPIT_MS), 1, MAX_TARPIT_MS
        )
    elif action_type is ActionType.DEPLOY_CANARY:
        kind = params.get("kind", "decoy_path")
        if kind not in CANARY_KINDS:
            raise ActionValidationError(f"params.kind must be one of {', '.join(sorted(CANARY_KINDS))}")
        out["kind"] = str(kind)
    elif action_type is ActionType.NOTIFY:
        if "channel_id" in params:
            cid = params["channel_id"]
            if not isinstance(cid, str) or not _CHANNEL_ID.match(cid):
                raise ActionValidationError("params.channel_id must be a channel id")
            out["channel_id"] = cid
    elif action_type is ActionType.WEBHOOK:
        endpoint = params.get("endpoint", "default")
        if not isinstance(endpoint, str) or not _ENDPOINT_NAME.match(endpoint):
            raise ActionValidationError("params.endpoint must be an endpoint name")
        if endpoint not in settings.webhook_urls:
            raise ActionValidationError(
                f"webhook endpoint {endpoint!r} is not configured (response.webhook_urls)"
            )
        out["endpoint"] = endpoint
    return out


# ---------------------------------------------------------------- entry point


def _ref_id(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    if not _REF_ID.match(value):
        raise ActionValidationError(f"{name} is not a valid id")
    return value


def validate_action(
    action_type: ActionType | str,
    target: str,
    params: Mapping[str, Any] | None = None,
    ttl_minutes: int | None = None,
    *,
    incident_id: str | None = None,
    alert_id: str | None = None,
    settings: ResponseSettings | None = None,
) -> ValidatedAction:
    """Validate a proposal (or re-validate a stored action right before execution)."""
    s = settings or get_settings().response
    try:
        atype = ActionType(action_type)
    except ValueError as exc:
        raise ActionValidationError(f"unknown action type {action_type!r}") from exc
    if not isinstance(target, str):
        raise ActionValidationError("target must be a string")
    notes: list[str] = []

    if atype in NETWORK_ACTIONS:
        norm_target = validate_network_target(target, s)
        if atype is ActionType.NFTABLES_BLOCK and "/" in norm_target:
            raise ActionValidationError("nftables_block accepts a single IP address only")
    elif atype is ActionType.DEPLOY_CANARY:
        norm_target = target.strip()
        if not _SAFE_PATH.match(norm_target) or ".." in norm_target or "//" in norm_target:
            raise ActionValidationError("deploy_canary target must be an absolute URL path like /backup.zip")
    else:  # notify / webhook: an IP/CIDR or a restricted identifier
        stripped = target.strip()
        try:
            net: Network | None = parse_network(stripped)
        except ActionValidationError:
            net = None
        if net is not None:
            # A webhook usually hands the target to an external firewall/SOAR: same lockout guard as
            # network actions. A notify only mentions it.
            norm_target = (
                validate_network_target(stripped, s) if atype is ActionType.WEBHOOK else format_network(net)
            )
        elif _SAFE_IDENT.match(stripped):
            norm_target = stripped
        else:
            raise ActionValidationError("target must be an IP/CIDR or a simple identifier")

    norm_params = _validate_params(atype, params or {}, s)

    ttl: int | None
    if atype in TTL_ACTIONS:
        ttl = s.default_ttl_minutes if ttl_minutes is None else ttl_minutes
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 1:
            raise ActionValidationError("ttl_minutes must be a positive integer")
        if ttl > s.max_ttl_minutes:
            notes.append(f"ttl capped from {ttl} to {s.max_ttl_minutes} minutes")
            ttl = s.max_ttl_minutes
    else:
        if ttl_minutes is not None:
            notes.append(f"ttl ignored for one-shot action {atype.value}")
        ttl = None

    return ValidatedAction(
        action_type=atype,
        target=norm_target,
        params=norm_params,
        ttl_minutes=ttl,
        reversible=atype not in ONE_SHOT_ACTIONS,
        incident_id=_ref_id(incident_id, "incident_id"),
        alert_id=_ref_id(alert_id, "alert_id"),
        notes=tuple(notes),
    )
