"""Gate policy: compile the server's :class:`GatePolicy` into fast lookup structures and keep it fresh.

Fail-open / fail-static semantics (deliberate):

- Before the first successful fetch the gate enforces the policy it last saved (``gate.policy_cache_file``,
  audit #32), trimmed of entries whose expiry has passed and refused when older than
  ``gate.policy_cache_max_age_hours``; with no usable copy it enforces nothing (pure sensor + proxy). Without the
  copy, restarting the Gate while the server was unreachable silently unblocked every blocked attacker.
- When the server is unreachable or returns garbage, the *last known* policy stays in force. Blocks are TTL'd
  server-side, so a stale policy can only be as old as the outage; dropping it would silently unblock an
  active attacker the moment they DoS the TOKIWA server.
- ...but never past each entry's own expiry (``GatePolicy.entry_expires_at``, audit #64): an entry is lifted
  locally at ``receive time + (expires_at - generated_at)`` on the monotonic clock, so neither an outage nor a
  skewed Gate clock keeps a block alive longer than the server would.
- A policy is swapped only when ``version`` changes, so an unchanged policy keeps its compiled tables (and the
  rate-limiter state keyed by client IP is never reset by a refresh).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import random
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import unquote

import httpx
from pydantic import ValidationError

from tokiwa.gate.netmatch import IpTable
from tokiwa.gate.proxy import LEGACY_POSITIONS
from tokiwa.gate.tokens import TokenSource
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


_NTFS_STREAM = re.compile(r"::\$[a-z_]*$")


def _segment_head(seg: str) -> str:
    """What a lenient server keeps of one segment: before a NUL (C string APIs) and before ``;`` (Tomcat/Jetty/
    Spring path parameters, so ``..;`` is ``..`` there too)."""
    return seg.split("\x00", 1)[0].split(";", 1)[0]


def match_key(path: str) -> str:
    """Decoy-matching key: :func:`normalize_path` plus the variants other servers treat as the same file (#54).

    ``path`` is ``scope['path']`` (percent-decoded once by the ASGI server). The upstream receives the raw target,
    so whatever *some* upstream would resolve to a decoy must match it here too, else the variant reaches the
    real application -- and the 200-decoy vs 404-variant difference tells an agent which paths are traps:

    - a second percent-decoding (``%252e`` -> ``.``), ``\\`` as ``/`` (``%5c``, IIS / Windows);
    - per segment, everything from a NUL or ``;`` on is dropped (``/.env;x``, ``/x/..;/.env``, ``.php%3b.css``);
    - dot segments resolved (RFC 3986), then trailing dots / spaces and NTFS ``::$DATA`` streams dropped
      (``/.env.``, ``/.env%20``; after resolution so ``..`` is not turned into an empty segment);
    - lower-cased (case-insensitive file systems) and without a trailing ``/``.

    The request is still forwarded unchanged; only the decision "is this a decoy?" uses the key.
    """
    s = unquote(path) if "%" in path else path
    s = s.replace("\\", "/")
    s = normalize_path("/".join(_segment_head(seg) for seg in s.split("/")))
    segments = []
    for seg in s.lower().split("/"):
        seg = _NTFS_STREAM.sub("", seg).rstrip(". ")
        if seg:
            segments.append(seg)
    return "/" + "/".join(segments)


def path_anomalies(path: str) -> list[str]:
    """Reasons ``path`` (``scope['path']``) only makes sense to a lenient server (event tag ``gate:path_anomaly``)."""
    found = []
    if "\x00" in path:
        found.append("nul")
    if ";" in path:
        found.append("semicolon")
    if "\\" in path:
        found.append("backslash")
    if "%" in path and unquote(path) != path:
        found.append("double_encoding")
    if "�" in path:
        found.append("invalid_utf8")  # e.g. overlong %c0%ae (not decoded as "." here)
    if any(seg != seg.rstrip(". ") and seg not in (".", "..") for seg in path.split("/")):
        found.append("trailing_dot_or_space")
    if "::$" in path:
        found.append("ntfs_stream")
    return found


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
                key = match_key(prefix)
                if prefix.endswith("/") and key != "/":
                    key += "/"
                # Guard: a catch-all decoy ("*", "/*") would replace the protected site for every visitor.
                if key in ("", "/"):
                    rejected.append(route.path)
                    continue
                prefixes.setdefault(key, route)
            else:
                key = match_key(raw)
                if key == "/":  # e.g. "/;x" or "/%2e": would answer the home page with a decoy
                    rejected.append(route.path)
                    continue
                exact.setdefault(key, route)
        ordered = tuple(sorted(prefixes.items(), key=lambda kv: len(kv[0]), reverse=True))
        return cls(exact=exact, prefixes=ordered), rejected

    def match(self, path: str) -> DecoyRoute | None:
        if not self.exact and not self.prefixes:
            return None
        key = match_key(path)
        hit = self.exact.get(key)
        if hit is not None:
            return hit
        slashed = key + "/"  # "/admin" and "/admin/" are both under an "/admin/*" decoy
        for prefix, route in self.prefixes:
            if slashed.startswith(prefix):
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
    # where html_injection goes (gate.proxy.inject_html); servers before audit #41 send none -> before </body>
    html_injection_positions: tuple[str, ...] = LEGACY_POSITIONS

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
            html_injection_positions=tuple(policy.html_injection_positions or LEGACY_POSITIONS),
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


def _without(policy: GatePolicy, expired: dict[str, set[str]]) -> GatePolicy:
    """``policy`` minus the expired entries (same version: it is still the server's policy, trimmed)."""
    return policy.model_copy(
        update={
            "blocked": [x for x in policy.blocked if x not in expired.get("blocked", set())],
            "deceive": [x for x in policy.deceive if x not in expired.get("deceive", set())],
            "rate_limited": {
                k: v for k, v in policy.rate_limited.items() if k not in expired.get("rate_limited", set())
            },
            "tarpit": {k: v for k, v in policy.tarpit.items() if k not in expired.get("tarpit", set())},
        }
    )


class PolicyManager:
    """Pulls ``GET /api/v1/gate/policy`` every ``refresh_seconds`` and swaps the compiled policy on change."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        server_url: str,
        token: str | TokenSource | None,
        *,
        refresh_seconds: float = 5.0,
        timeout: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
        cache_file: Path | None = None,
        cache_max_age_hours: float = 168.0,
    ) -> None:
        self._client = client
        self.cache_file = cache_file
        self.cache_max_age = timedelta(hours=max(0.0, cache_max_age_hours))
        self.source: str | None = None  # "cache" until the first successful fetch, then "server"
        self._url = server_url.rstrip("/") + POLICY_PATH
        self._tokens = TokenSource.of(token)
        self.refresh_seconds = max(0.5, refresh_seconds)
        self._timeout = timeout
        self._current = CompiledPolicy.empty()
        self._clock = clock
        # The installed policy (already trimmed of expired entries) and the pending local deadlines, soonest
        # first: (monotonic deadline, section, entry).
        self._source: GatePolicy | None = None
        self._deadlines: list[tuple[float, str, str]] = []
        self.expired_locally = 0
        self.fetches = 0
        self.errors = 0
        self.swaps = 0
        self.last_error: str | None = None
        self.last_success: datetime | None = None
        self._consecutive_failures = 0

    @property
    def current(self) -> CompiledPolicy:
        if self._deadlines and self._clock() >= self._deadlines[0][0]:
            self._expire_entries()
        return self._current

    def apply(self, policy: GatePolicy, *, now: datetime | None = None) -> bool:
        """Install ``policy`` if its version differs from the current one. Returns True when swapped.

        ``now`` (wall clock) is given for a policy read back from the cache: its entries then run until their
        absolute ``expires_at``. A freshly fetched policy measures from its ``generated_at`` instead, so a skewed
        Gate clock cannot stretch a block; a cached one was generated before the restart, and measuring from
        ``generated_at`` again would give every entry its full TTL back.
        """
        if policy.version == self._current.version:
            return False
        received = self._clock()
        base = now or policy.generated_at
        deadlines: list[tuple[float, str, str]] = []
        for section, entries in policy.entry_expires_at.items():
            for key, expires_at in entries.items():
                remaining = (expires_at - base).total_seconds()
                deadlines.append((received + remaining, section, key))
        deadlines.sort()
        self._source = policy
        self._deadlines = deadlines
        compiled = CompiledPolicy.compile(policy)
        self._current = compiled  # single reference assignment: requests see either old or new, never a mix
        self.swaps += 1
        log.info("gate policy updated: %s", compiled.summary())
        if deadlines and received >= deadlines[0][0]:
            self._expire_entries()  # already past (a policy generated long ago)
        return True

    def _expire_entries(self) -> None:
        """Drop entries whose deadline passed and recompile (normally the server's next policy does this)."""
        now = self._clock()
        expired: dict[str, set[str]] = {}
        while self._deadlines and self._deadlines[0][0] <= now:
            _, section, key = self._deadlines.pop(0)
            expired.setdefault(section, set()).add(key)
        if self._source is None or not expired:
            return
        self._source = _without(self._source, expired)
        self._current = CompiledPolicy.compile(self._source)
        count = sum(len(v) for v in expired.values())
        self.expired_locally += count
        log.info("gate policy %s: %d entries reached their expiry locally", self._source.version, count)

    async def refresh(self) -> bool:
        """Fetch once. Never raises (fail-open); returns True when a new policy was installed."""
        self.fetches += 1
        try:
            resp = await self._get()
            if resp.status_code == 401 and self._tokens.reload():
                resp = await self._get()  # the token file was replaced (rotation): retry once right away
        except httpx.HTTPError as exc:
            self._failed(f"{type(exc).__name__}: {exc}")
            return False
        if resp.status_code != 200:
            reason = f"HTTP {resp.status_code}"
            if resp.status_code == 403:
                # `tokiwa token create` defaults to scope ingest only (audit #33): the gate scope is opt-in.
                reason += " (token lacks the 'gate' scope? create it with --scope ingest --scope gate)"
            self._failed(reason)
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
        self.source = "server"
        swapped = self.apply(policy)
        if swapped:
            await asyncio.to_thread(self._save_cache, resp.content)
        return swapped

    # ------------------------------------------------------------------ local copy (audit #32)
    def load_cache(self) -> bool:
        """Install the saved policy (startup, before the first fetch). Never raises; True when installed."""
        path = self.cache_file
        if path is None or not path.is_file():
            return False
        try:
            policy = GatePolicy.model_validate_json(path.read_bytes())
        except (OSError, ValidationError, ValueError) as exc:
            log.warning(
                "gate policy cache %s unusable (%s); starting without a policy", path, type(exc).__name__
            )
            return False
        now = utcnow()
        age = now - policy.generated_at
        if self.cache_max_age and age > self.cache_max_age:
            log.warning(
                "gate policy cache %s is %s old (> gate.policy_cache_max_age_hours); not enforcing it",
                path,
                str(age).split(".")[0],
            )
            return False
        expired = {
            section: {k for k, at in entries.items() if at <= now}
            for section, entries in policy.entry_expires_at.items()
        }
        if any(expired.values()):
            policy = _without(policy, expired)
        installed = self.apply(policy, now=now)
        if installed:
            self.source = "cache"
            log.warning(
                "gate: enforcing the saved policy %s (generated %s) until the server answers",
                policy.version,
                policy.generated_at.isoformat(),
            )
        return installed

    def _save_cache(self, payload: bytes) -> None:
        """Write the fetched policy atomically, mode 600 (it carries decoy routes and canary snippets)."""
        path = self.cache_file
        if path is None:
            return
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
            os.replace(tmp, path)
        except OSError as exc:
            # A read-only filesystem must not affect the proxy: the Gate just loses the restart protection.
            log.warning("gate: could not save the policy to %s (%s)", path, exc)
            with contextlib.suppress(OSError):
                tmp.unlink()

    async def _get(self) -> httpx.Response:
        headers = {"Accept": "application/json"}
        token = self._tokens.get()
        if token:
            headers["X-Tokiwa-Token"] = token
        return await self._client.get(self._url, headers=headers, timeout=self._timeout)

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
            "expired_locally": self.expired_locally,
            "last_error": self.last_error,
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "source": self.source,
        }
