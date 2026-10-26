"""Gate policy: compile the server's :class:`GatePolicy` into fast lookup structures and keep it fresh.

Fail-open / fail-static semantics (deliberate):

- Before the first successful fetch the gate enforces nothing (pure sensor + proxy).
- When the server is unreachable or returns garbage, the *last known* policy stays in force. Blocks are TTL'd
  server-side, so a stale policy can only be as old as the outage; dropping it would silently unblock an
  active attacker the moment they DoS the TOKIWA server.
- A policy is swapped only when ``version`` changes, so an unchanged policy keeps its compiled tables (and the
  rate-limiter state keyed by client IP is never reset by a refresh).
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime

import httpx
from pydantic import ValidationError

from tokiwa.gate.netmatch import IpTable
from tokiwa.schemas.response import DecoyRoute, GatePolicy
from tokiwa.util import utcnow

log = logging.getLogger(__name__)

POLICY_PATH = "/api/v1/gate/policy"
TARPIT_MAX_MS = 30_000


def normalize_path(path: str) -> str:
    """Collapse duplicate slashes and resolve dot segments (RFC 3986 §5.2.4) for decoy matching.

    The request is still forwarded with its *raw* target; normalization only ensures ``//.env`` or
    ``/static/../.env`` cannot side-step a ``/.env`` decoy.
    """
    if not path:
        return "/"
    segments: list[str] = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if segments:
                segments.pop()
            continue
        segments.append(seg)
    out = "/" + "/".join(segments)
    if segments and (path.endswith("/") or path.endswith("/.") or path.endswith("/..")):
        out += "/"
    return out


@dataclass(frozen=True, slots=True)
class DecoyMatcher:
    exact: dict[str, DecoyRoute] = field(default_factory=dict)
    prefixes: tuple[tuple[str, DecoyRoute], ...] = ()  # longest prefix first

    @classmethod
    def build(cls, routes: list[DecoyRoute]) -> tuple[DecoyMatcher, list[str]]:
        exact: dict[str, DecoyRoute] = {}
        prefixes: dict[str, DecoyRoute] = {}
        rejected: list[str] = []
        for route in routes:
            raw = route.path.strip()
            if raw.endswith("*"):
                prefix = raw[:-1]
                norm = normalize_path(prefix)
                if prefix.endswith("/") and norm != "/":
                    norm = norm.rstrip("/") + "/"
                # Guard: a catch-all decoy ("*", "/*") would replace the protected site for every visitor.
                if norm in ("", "/"):
                    rejected.append(route.path)
                    continue
                prefixes.setdefault(norm, route)
            else:
                exact.setdefault(normalize_path(raw), route)
        ordered = tuple(sorted(prefixes.items(), key=lambda kv: len(kv[0]), reverse=True))
        return cls(exact=exact, prefixes=ordered), rejected

    def match(self, path: str) -> DecoyRoute | None:
        if not self.exact and not self.prefixes:
            return None
        norm = normalize_path(path)
        hit = self.exact.get(norm)
        if hit is not None:
            return hit
        for prefix, route in self.prefixes:
            if norm.startswith(prefix):
                return route
        return None

    def __len__(self) -> int:
        return len(self.exact) + len(self.prefixes)


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    version: str | None
    generated_at: datetime | None
    blocked: IpTable[bool]
    rate_limited: IpTable[int]
    tarpit: IpTable[int]
    deceive: IpTable[bool]
    decoys: DecoyMatcher
    html_injection: str | None
    invalid_entries: tuple[str, ...] = ()

    @classmethod
    def empty(cls) -> CompiledPolicy:
        return cls(
            version=None,
            generated_at=None,
            blocked=IpTable(),
            rate_limited=IpTable(),
            tarpit=IpTable(),
            deceive=IpTable(),
            decoys=DecoyMatcher(),
            html_injection=None,
        )

    @classmethod
    def compile(cls, policy: GatePolicy) -> CompiledPolicy:
        blocked, bad1 = IpTable[bool].build((x, True) for x in policy.blocked)
        # Same network listed twice: the stricter limit / the longer delay wins.
        rate, bad2 = IpTable[int].build(policy.rate_limited.items(), merge=min)
        tarpit, bad3 = IpTable[int].build(
            ((k, max(0, min(int(v), TARPIT_MAX_MS))) for k, v in policy.tarpit.items()), merge=max
        )
        deceive, bad4 = IpTable[bool].build((x, True) for x in policy.deceive)
        decoys, bad5 = DecoyMatcher.build(policy.decoys)
        invalid = tuple(bad1 + bad2 + bad3 + bad4 + [f"decoy:{p}" for p in bad5])
        if invalid:
            log.warning(
                "gate policy %s: ignoring %d invalid entries (e.g. %s)",
                policy.version,
                len(invalid),
                ", ".join(invalid[:5]),
            )
        return cls(
            version=policy.version,
            generated_at=policy.generated_at,
            blocked=blocked,
            rate_limited=rate,
            tarpit=tarpit,
            deceive=deceive,
            decoys=decoys,
            html_injection=policy.html_injection or None,
            invalid_entries=invalid,
        )

    def summary(self) -> dict[str, object]:
        return {
            "version": self.version,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None,
            "blocked": len(self.blocked),
            "rate_limited": len(self.rate_limited),
            "tarpit": len(self.tarpit),
            "deceive": len(self.deceive),
            "decoys": len(self.decoys),
            "html_injection": self.html_injection is not None,
            "invalid_entries": len(self.invalid_entries),
        }


class PolicyManager:
    """Pulls ``GET /api/v1/gate/policy`` every ``refresh_seconds`` and swaps the compiled policy on change."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        server_url: str,
        token: str | None,
        *,
        refresh_seconds: float = 5.0,
        timeout: float = 5.0,
    ) -> None:
        self._client = client
        self._url = server_url.rstrip("/") + POLICY_PATH
        self._token = token
        self.refresh_seconds = max(0.5, refresh_seconds)
        self._timeout = timeout
        self._current = CompiledPolicy.empty()
        self.fetches = 0
        self.errors = 0
        self.swaps = 0
        self.last_error: str | None = None
        self.last_success: datetime | None = None
        self._consecutive_failures = 0

    @property
    def current(self) -> CompiledPolicy:
        return self._current

    def apply(self, policy: GatePolicy) -> bool:
        """Install ``policy`` if its version differs from the current one. Returns True when swapped."""
        if policy.version == self._current.version:
            return False
        compiled = CompiledPolicy.compile(policy)
        self._current = compiled  # single reference assignment: requests see either old or new, never a mix
        self.swaps += 1
        log.info("gate policy updated: %s", compiled.summary())
        return True

    async def refresh(self) -> bool:
        """Fetch once. Never raises (fail-open); returns True when a new policy was installed."""
        self.fetches += 1
        headers = {"Accept": "application/json"}
        if self._token:
            headers["X-Tokiwa-Token"] = self._token
        try:
            resp = await self._client.get(self._url, headers=headers, timeout=self._timeout)
        except httpx.HTTPError as exc:
            self._failed(f"{type(exc).__name__}: {exc}")
            return False
        if resp.status_code != 200:
            self._failed(f"HTTP {resp.status_code}")
            return False
        try:
            policy = GatePolicy.model_validate_json(resp.content)
        except ValidationError as exc:
            self._failed(f"invalid policy payload ({exc.error_count()} errors)")
            return False
        if self._consecutive_failures:
            log.info("gate policy fetch recovered after %d failures", self._consecutive_failures)
        self._consecutive_failures = 0
        self.last_error = None
        self.last_success = utcnow()
        return self.apply(policy)

    def _failed(self, reason: str) -> None:
        self.errors += 1
        self.last_error = reason
        # Log the first failure loudly, then quietly until recovery (avoid flooding during an outage).
        level = logging.WARNING if self._consecutive_failures == 0 else logging.DEBUG
        log.log(level, "gate policy fetch failed (%s); keeping policy %s", reason, self._current.version)
        self._consecutive_failures += 1

    async def run(self, *, initial_delay: bool = True) -> None:
        """Refresh forever. ``initial_delay``: the caller already did the first fetch at startup."""
        if not initial_delay:
            await self.refresh()
        while True:
            jitter = self.refresh_seconds * 0.1 * (2 * random.random() - 1)
            await asyncio.sleep(self.refresh_seconds + jitter)
            await self.refresh()

    def stats(self) -> dict[str, object]:
        return {
            **self._current.summary(),
            "fetches": self.fetches,
            "errors": self.errors,
            "swaps": self.swaps,
            "last_error": self.last_error,
            "last_success": self.last_success.isoformat() if self.last_success else None,
        }
