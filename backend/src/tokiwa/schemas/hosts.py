"""Host port state and port baselines (FR-01/02). API contract: docs/api-contract.md「ホスト・資産」.

Field names match ``tokiwa.db.models.telemetry.HostPortRow`` / ``PortBaselineRow`` so ``model_validate(row)``
works. ``HostPort.allowed`` is not a column: the hosts API computes it against the baselines.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Protocol

from pydantic import BaseModel, Field, field_validator

from tokiwa.schemas.common import ORMModel

_PROTOCOLS = {"tcp", "udp"}
WILDCARD_BINDS = frozenset({"0.0.0.0", "::", "*", ""})  # noqa: S104 - these are values we look for


def base_protocol(protocol: str | None) -> str:
    """``tcp6`` -> ``tcp``. Baselines are per transport, not per address family."""
    p = (protocol or "tcp").strip().lower()
    return p[:-1] if p.endswith("6") else p


def is_wildcard_bind(bind_ip: str | None) -> bool:
    """Bound to every interface (reachable from outside unless a firewall says otherwise)."""
    return (bind_ip or "").strip().strip("[]") in WILDCARD_BINDS


def is_loopback_bind(bind_ip: str | None) -> bool:
    ip = (bind_ip or "").strip().strip("[]")
    return ip.startswith("127.") or ip == "::1" or ip == "localhost"


class BaselineLike(Protocol):
    """Anything shaped like a baseline (ORM row or :class:`PortBaseline`)."""

    @property
    def host(self) -> str: ...
    @property
    def protocol(self) -> str: ...
    @property
    def port(self) -> int: ...
    @property
    def process_name(self) -> str | None: ...
    @property
    def allow_public(self) -> bool: ...


def match_baseline[B: BaselineLike](
    baselines: Iterable[B], *, host: str, protocol: str, port: int, process_name: str | None
) -> B | None:
    """Most specific baseline that allows this listener, or None.

    A baseline with ``process_name`` only matches that process. When the sensor could not read the owning
    process (agent without root), the process constraint cannot be verified and is treated as satisfied —
    otherwise every unprivileged agent would flood the console with false deviations.
    """
    proto = base_protocol(protocol)
    best: B | None = None
    best_rank = -1
    for b in baselines:
        if b.host not in ("*", host) or b.port != port or base_protocol(b.protocol) != proto:
            continue
        if b.process_name and process_name and b.process_name != process_name:
            continue
        rank = (2 if b.host == host else 0) + (1 if b.process_name else 0)
        if rank > best_rank:
            best, best_rank = b, rank
    return best


class HostPort(ORMModel):
    id: str
    host: str
    protocol: str
    bind_ip: str
    port: int
    pid: int | None = None
    process_name: str | None = None
    first_seen: datetime
    last_seen: datetime
    open: bool
    # Covered by a port baseline (computed by the API, not stored).
    allowed: bool = False


class PortBaseline(ORMModel):
    id: str
    host: str  # "*" = every host
    protocol: str
    port: int
    process_name: str | None = None  # None = any process
    allow_public: bool = False
    note: str | None = None
    created_at: datetime


class PortBaselineIn(BaseModel):
    host: str | None = Field(default=None, max_length=255)  # None / "" -> "*"
    protocol: str = "tcp"
    port: int = Field(ge=0, le=65535)
    process_name: str | None = Field(default=None, max_length=255)
    allow_public: bool = False
    note: str | None = Field(default=None, max_length=2000)

    @field_validator("protocol")
    @classmethod
    def _protocol(cls, v: str) -> str:
        p = base_protocol(v)
        if p not in _PROTOCOLS:
            raise ValueError("protocol must be tcp, udp, tcp6 or udp6")
        return p

    @field_validator("host", "process_name")
    @classmethod
    def _blank_to_none(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        return v or None


class BaselineLearnRequest(BaseModel):
    host: str = Field(min_length=1, max_length=255)


class HostSummary(BaseModel):
    host: str
    ports_open: int
    last_seen: datetime | None = None
    # Open listeners that no baseline allows.
    deviations: int = 0
