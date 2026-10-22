"""Lab traffic simulator core.

Profiles (``tokiwa.eval.profiles``) are small async scripts written against :class:`SessionContext`. The same
script runs in two modes:

* **offline** (``tokiwa sim generate``): a :class:`VirtualClock` and :class:`VirtualTransport` (in-process mirror
  of the lab victim) — no network, deterministic for a given seed, used to build labelled datasets;
* **live** (``tokiwa sim run``): real time and :class:`HttpTransport` against a lab target that passed
  :func:`tokiwa.eval.safety.check_target`. Redirects are never followed and a global request cap / rate cap apply.

Every request is recorded as an :class:`~tokiwa.eval.exchange.Exchange` (what a Gate would capture + ground truth
labels) and can be turned into a TOKIWA :class:`~tokiwa.schemas.events.Event` with :func:`exchange_to_event`.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import math
import random
import time
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from tokiwa.eval.exchange import ClientIdentity, Exchange, SimRequest, SimResponse
from tokiwa.eval.safety import check_target
from tokiwa.eval.virtual import VirtualLab
from tokiwa.llm.redact import redact_headers, redact_text
from tokiwa.schemas.events import Endpoint, Event, EventKind, HttpInfo

log = logging.getLogger(__name__)

DEFAULT_START = datetime(2026, 10, 1, 9, 0, 0, tzinfo=UTC)
LAB_HOST = "gate:8080"
LAB_DEST_IP = "172.28.0.10"
CAPTURE_BODY_CHARS = 4096
MAX_RESPONSE_CHARS = 256 * 1024


class SessionBudgetExceededError(RuntimeError):
    """Raised inside a profile when its request budget is used up; the runner ends the session cleanly."""


# --------------------------------------------------------------------------------------------- clocks


class VirtualClock:
    def __init__(self, start: datetime) -> None:
        self._t = start

    def now(self) -> datetime:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += timedelta(seconds=max(0.0, seconds))

    def set(self, t: datetime) -> None:
        self._t = max(self._t, t)

    async def sleep(self, seconds: float) -> None:
        self.advance(seconds)


class RealClock:
    def __init__(self, time_scale: float = 1.0) -> None:
        self.time_scale = time_scale

    def now(self) -> datetime:
        return datetime.now(UTC)

    def advance(self, seconds: float) -> None:  # real time advances by itself
        return None

    def set(self, t: datetime) -> None:
        return None

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(max(0.0, seconds) * self.time_scale)


Clock = VirtualClock | RealClock

# ------------------------------------------------------------------------------------------ transports


class Transport(Protocol):
    virtual: bool

    async def send(
        self, req: SimRequest, headers: list[tuple[str, str]], rng: random.Random
    ) -> tuple[SimResponse, float, list[tuple[str, str]]]:
        """Return (response, duration_ms, headers actually sent)."""
        ...


class VirtualTransport:
    virtual = True

    def __init__(self, lab: VirtualLab | None = None) -> None:
        self.lab = lab or VirtualLab()

    async def send(
        self, req: SimRequest, headers: list[tuple[str, str]], rng: random.Random
    ) -> tuple[SimResponse, float, list[tuple[str, str]]]:
        sent = SimRequest(method=req.method, path=req.path, query=req.query, headers=headers, body=req.body)
        resp = self.lab.handle(sent)
        base = 4.0 if resp.content_type.startswith(("text/css", "application/javascript", "image/")) else 9.0
        duration = base * math.exp(rng.gauss(0.0, 0.45)) + (25.0 if resp.status >= 500 else 0.0)
        return resp, round(duration, 2), headers


class _RateLimiter:
    def __init__(self, max_rps: float) -> None:
        self.interval = 1.0 / max_rps if max_rps > 0 else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        if self.interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            delay = self._next - now
            self._next = max(now, self._next) + self.interval
        if delay > 0:
            await asyncio.sleep(delay)


class HttpTransport:
    """Real HTTP to a validated lab target. Never follows redirects; ignores proxy env vars."""

    virtual = False

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        max_requests: int = 5000,
        max_rps: float = 50.0,
    ) -> None:
        self.client = client
        self.max_requests = max_requests
        self.sent = 0
        self._limiter = _RateLimiter(max_rps)

    async def send(
        self, req: SimRequest, headers: list[tuple[str, str]], rng: random.Random
    ) -> tuple[SimResponse, float, list[tuple[str, str]]]:
        if self.sent >= self.max_requests:
            raise SessionBudgetExceededError("global request cap reached")
        self.sent += 1
        await self._limiter.wait()
        wire_headers = [(k, v) for k, v in headers if k not in ("host", "content-length")]
        url = req.target
        started = time.perf_counter()
        try:
            r = await self.client.request(
                req.method,
                url,
                headers=wire_headers,
                content=req.body.encode() if req.body is not None else None,
            )
        except httpx.HTTPError as exc:
            duration = (time.perf_counter() - started) * 1000
            return SimResponse(status=0, error=f"{type(exc).__name__}: {exc}"), duration, headers
        duration = (time.perf_counter() - started) * 1000
        text = r.text[:MAX_RESPONSE_CHARS] if _is_text(r.headers.get("content-type", "")) else ""
        sent_headers = [(k.lower(), v) for k, v in r.request.headers.multi_items()]
        resp = SimResponse(
            status=r.status_code,
            content_type=r.headers.get("content-type", ""),
            body=text,
            size=len(r.content),
            headers={k.lower(): v for k, v in r.headers.items()},
        )
        return resp, round(duration, 2), sent_headers


def _is_text(ctype: str) -> bool:
    ctype = ctype.lower()
    return ctype.startswith("text/") or "json" in ctype or "javascript" in ctype or "xml" in ctype


# ------------------------------------------------------------------------------------- client headers

_ACCEPT_DOC = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
_ACCEPT = {
    "document": _ACCEPT_DOC,
    "script": "*/*",
    "style": "text/css,*/*;q=0.1",
    "image": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
    "xhr": "application/json, text/plain, */*",
}
_BROWSER_FAMILIES = {"chrome", "firefox", "safari"}


def build_headers(
    ident: ClientIdentity,
    *,
    host: str,
    kind: str,
    method: str,
    referer: str | None,
    content_type: str | None,
    body: str | None,
    cookie: str | None,
    extra: Sequence[tuple[str, str]] = (),
) -> list[tuple[str, str]]:
    """Header list in the order the given client family would send it (header order is a fingerprint)."""
    fam = ident.family
    h: list[tuple[str, str]] = []
    clen = [("content-length", str(len(body.encode())))] if body is not None else []
    ctype = [("content-type", content_type)] if content_type else []
    if fam == "chrome":
        dest = {"document": "document", "script": "script", "style": "style", "image": "image"}.get(
            kind, "empty"
        )
        mode = "navigate" if kind == "document" else ("cors" if kind == "xhr" else "no-cors")
        h = [("host", host), ("connection", "keep-alive"), *clen]
        h += [
            ("sec-ch-ua", '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"'),
            ("sec-ch-ua-mobile", "?0"),
            ("sec-ch-ua-platform", '"Windows"'),
        ]
        if kind == "document":
            h.append(("upgrade-insecure-requests", "1"))
        h += [("user-agent", ident.user_agent), ("accept", _ACCEPT.get(kind, "*/*")), *ctype]
        if method == "POST":
            h.append(("origin", f"http://{host}"))
        h += [("sec-fetch-site", "same-origin"), ("sec-fetch-mode", mode)]
        if kind == "document":
            h.append(("sec-fetch-user", "?1"))
        h.append(("sec-fetch-dest", dest))
        if referer:
            h.append(("referer", referer))
        h += [
            ("accept-encoding", "gzip, deflate, br, zstd"),
            ("accept-language", ident.accept_language or "ja"),
        ]
        if cookie:
            h.append(("cookie", cookie))
    elif fam == "firefox":
        h = [("host", host), ("user-agent", ident.user_agent), ("accept", _ACCEPT.get(kind, "*/*"))]
        h += [
            ("accept-language", ident.accept_language or "ja"),
            ("accept-encoding", "gzip, deflate, br, zstd"),
        ]
        h += [*ctype, *clen]
        if method == "POST":
            h.append(("origin", f"http://{host}"))
        h.append(("connection", "keep-alive"))
        if referer:
            h.append(("referer", referer))
        if cookie:
            h.append(("cookie", cookie))
        if kind == "document":
            h.append(("upgrade-insecure-requests", "1"))
        h += [("sec-fetch-dest", "document" if kind == "document" else "empty")]
        h += [
            ("sec-fetch-mode", "navigate" if kind == "document" else "cors"),
            ("sec-fetch-site", "same-origin"),
        ]
    elif fam == "safari":
        h = [("host", host), ("accept", _ACCEPT.get(kind, "*/*")), ("sec-fetch-site", "same-origin")]
        if cookie:
            h.append(("cookie", cookie))
        h += [("sec-fetch-dest", "document" if kind == "document" else "empty")]
        h += [("accept-language", ident.accept_language or "ja-JP,ja;q=0.9")]
        h += [
            ("sec-fetch-mode", "navigate" if kind == "document" else "cors"),
            ("user-agent", ident.user_agent),
        ]
        if referer:
            h.append(("referer", referer))
        h += [*ctype, *clen, ("accept-encoding", "gzip, deflate"), ("connection", "keep-alive")]
    elif fam == "curl":
        h = [("host", host), ("user-agent", ident.user_agent), ("accept", "*/*"), *ctype, *clen]
    elif fam == "httpx":
        h = [("host", host), ("accept", "*/*"), ("accept-encoding", "gzip, deflate")]
        h += [("connection", "keep-alive"), ("user-agent", ident.user_agent), *clen, *ctype]
    elif fam == "requests":
        h = [("host", host), ("user-agent", ident.user_agent), ("accept-encoding", "gzip, deflate")]
        h += [("accept", "*/*"), ("connection", "keep-alive"), *clen, *ctype]
    elif fam == "aiohttp":
        h = [("host", host), ("user-agent", ident.user_agent), ("accept", "*/*")]
        h += [("accept-encoding", "gzip, deflate"), *clen, *ctype]
    elif fam == "go":
        h = [("host", host), ("user-agent", ident.user_agent), *clen, *ctype, ("accept-encoding", "gzip")]
    elif fam == "nuclei":
        h = [("host", host), ("user-agent", ident.user_agent), ("connection", "close"), ("accept", "*/*")]
        h += [("accept-language", "en"), *ctype, *clen, ("accept-encoding", "gzip")]
    elif fam == "sqlmap":
        h = [("host", host), ("cache-control", "no-cache"), ("user-agent", ident.user_agent)]
        h += [("accept", "*/*"), ("accept-encoding", "gzip,deflate"), *ctype, *clen, ("connection", "close")]
    else:  # gobuster / nikto / generic tools
        h = [("host", host), ("user-agent", ident.user_agent), *ctype, *clen, ("accept-encoding", "gzip")]
    overrides = {k.lower() for k, _ in extra}
    h = [(k, v) for k, v in h if k not in overrides]
    h.extend((k.lower(), v) for k, v in extra)
    return h


# ---------------------------------------------------------------------------------------- session ctx


@dataclass
class RequestSpec:
    method: str
    path: str
    query: str | None = None
    body: str | None = None
    content_type: str | None = None
    kind: str = "xhr"
    attack: str = "none"
    phase: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    referer: str | None = None


class SessionContext:
    """API that profile scripts use. Holds the actor identity, the clock, the transport and the recordings."""

    def __init__(
        self,
        *,
        transport: Transport,
        identity: ClientIdentity,
        rng: random.Random,
        clock: Clock,
        labels: dict[str, str],
        host: str = LAB_HOST,
        scheme: str = "http",
        max_requests: int = 400,
        spoof_xff: bool = False,
    ) -> None:
        self.transport = transport
        self.identity = identity
        self.rng = rng
        self.clock = clock
        self.labels = labels
        self.host = host
        self.scheme = scheme
        self.max_requests = max_requests
        self.spoof_xff = spoof_xff
        self.cookie: str | None = None
        self.auth: str | None = None
        self.exchanges: list[Exchange] = []
        self._port = rng.randint(32768, 60999)
        self._last_url: str | None = None

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}"

    @property
    def is_browser(self) -> bool:
        return self.identity.family in _BROWSER_FAMILIES

    async def sleep(self, seconds: float) -> None:
        await self.clock.sleep(seconds)

    def _headers_for(self, spec: RequestSpec) -> list[tuple[str, str]]:
        extra = list(spec.headers)
        if self.auth and not any(k.lower() == "authorization" for k, _ in extra):
            extra.append(("authorization", self.auth))
        if self.spoof_xff:
            extra.append(("x-forwarded-for", self.identity.source_ip))
        referer = spec.referer if spec.referer is not None else (self._last_url if self.is_browser else None)
        return build_headers(
            self.identity,
            host=self.host,
            kind=spec.kind,
            method=spec.method,
            referer=referer,
            content_type=spec.content_type,
            body=spec.body,
            cookie=self.cookie if self.is_browser else None,
            extra=extra,
        )

    async def _send(self, spec: RequestSpec, started: datetime) -> tuple[SimResponse, float]:
        if len(self.exchanges) >= self.max_requests:
            raise SessionBudgetExceededError("session request budget reached")
        headers = self._headers_for(spec)
        req = SimRequest(
            method=spec.method,
            path=spec.path,
            query=spec.query,
            headers=headers,
            body=spec.body,
            content_type=spec.content_type,
            attack=spec.attack,
            phase=spec.phase,
        )
        resp, duration, sent = await self.transport.send(req, headers, self.rng)
        if self.rng.random() < 0.15:
            self._port = self.rng.randint(32768, 60999)  # new TCP connection now and then
        labels = dict(self.labels)
        labels["attack"] = spec.attack
        if spec.phase:
            labels["phase"] = spec.phase
        self.exchanges.append(
            Exchange(
                request=req,
                response=resp,
                timestamp=started,
                duration_ms=duration,
                source_ip=self.identity.source_ip,
                source_port=self._port,
                headers=sent,
                host=self.host,
                scheme=self.scheme,
                labels=labels,
            )
        )
        if spec.kind == "document" and resp.status < 400:
            self._last_url = f"{self.base_url}{req.target}"
        return resp, duration

    async def send(self, spec: RequestSpec) -> SimResponse:
        started = self.clock.now()
        resp, duration = await self._send(spec, started)
        self.clock.advance(duration / 1000.0)
        return resp

    async def request(
        self,
        method: str,
        path: str,
        *,
        query: str | None = None,
        json_body: dict[str, Any] | None = None,
        body: str | None = None,
        content_type: str | None = None,
        kind: str = "xhr",
        attack: str = "none",
        phase: str = "",
        headers: list[tuple[str, str]] | None = None,
        referer: str | None = None,
    ) -> SimResponse:
        if json_body is not None:
            body = json.dumps(json_body, ensure_ascii=False)
            content_type = content_type or "application/json"
        return await self.send(
            RequestSpec(
                method=method,
                path=path,
                query=query,
                body=body,
                content_type=content_type,
                kind=kind,
                attack=attack,
                phase=phase,
                headers=list(headers or []),
                referer=referer,
            )
        )

    async def burst(
        self, specs: Sequence[RequestSpec], *, spacing_ms: tuple[float, float] = (2.0, 25.0)
    ) -> list[SimResponse]:
        """Send several requests nearly in parallel (tool-call fan-out). Returns responses in input order."""
        if not specs:
            return []
        offsets: list[float] = []
        acc = 0.0
        for _ in specs:
            offsets.append(acc)
            acc += self.rng.uniform(*spacing_ms) / 1000.0
        start = self.clock.now()
        if self.transport.virtual:
            results: list[SimResponse] = []
            end = start
            for spec, off in zip(specs, offsets, strict=True):
                t0 = start + timedelta(seconds=off)
                resp, duration = await self._send(spec, t0)
                results.append(resp)
                end = max(end, t0 + timedelta(milliseconds=duration))
            self.clock.set(end)
            return results

        async def one(spec: RequestSpec, off: float) -> SimResponse:
            await asyncio.sleep(off)
            resp, _ = await self._send(spec, datetime.now(UTC))
            return resp

        return list(await asyncio.gather(*(one(s, o) for s, o in zip(specs, offsets, strict=True))))

    async def page(self, path: str, *, assets: Sequence[str] = (), phase: str = "browse") -> SimResponse:
        """Browser navigation: the document, then its sub-resources fetched in parallel."""
        resp = await self.request("GET", path, kind="document", phase=phase)
        if assets and resp.status < 400:
            referer = f"{self.base_url}{path}"
            specs = [
                RequestSpec(
                    "GET",
                    a,
                    kind="script" if a.endswith(".js") else ("style" if a.endswith(".css") else "image"),
                    phase=phase,
                    referer=referer,
                )
                for a in assets
            ]
            await self.clock.sleep(self.rng.uniform(0.02, 0.12))  # parse HTML
            await self.burst(specs, spacing_ms=(1.0, 15.0))
        return resp


# ------------------------------------------------------------------------------------------ planning


@dataclass
class SessionPlan:
    profile: str
    session: str
    seed: int
    start_offset: float
    identity: ClientIdentity


_IP_POOLS = [
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
]


def build_plans(mix: dict[str, int], *, seed: int, spread_seconds: float = 1800.0) -> list[SessionPlan]:
    """Deterministic list of sessions for a profile mix. Source IPs are unique documentation addresses."""
    from tokiwa.eval.profiles import get_profile

    rng = random.Random(seed)
    used: set[str] = set()
    plans: list[SessionPlan] = []
    for name in sorted(mix):
        profile = get_profile(name)
        for i in range(mix[name]):
            while True:
                net = rng.choice(_IP_POOLS)
                ip = str(net.network_address + rng.randint(2, 253))
                if ip not in used:
                    used.add(ip)
                    break
            sess_seed = rng.randrange(1 << 30)
            ident = profile.identity(random.Random(sess_seed ^ 0x5EED), ip)
            plans.append(
                SessionPlan(
                    profile=name,
                    session=f"{name}-{i + 1:02d}",
                    seed=sess_seed,
                    start_offset=rng.uniform(0.0, spread_seconds),
                    identity=ident,
                )
            )
    return plans


def _labels_for(plan: SessionPlan) -> dict[str, str]:
    from tokiwa.eval.profiles import get_profile

    return {"actor": get_profile(plan.profile).actor, "profile": plan.profile, "session": plan.session}


async def _run_profile(ctx: SessionContext, runner: Callable[[SessionContext], Awaitable[None]]) -> None:
    try:
        await runner(ctx)
    except SessionBudgetExceededError:
        log.info("session %s stopped: request budget reached", ctx.labels.get("session"))


async def simulate_offline(
    plans: Sequence[SessionPlan],
    *,
    start: datetime = DEFAULT_START,
    lab: VirtualLab | None = None,
    max_requests_per_session: int = 400,
) -> list[Exchange]:
    from tokiwa.eval.profiles import get_profile

    transport = VirtualTransport(lab)
    out: list[Exchange] = []
    for plan in plans:
        ctx = SessionContext(
            transport=transport,
            identity=plan.identity,
            rng=random.Random(plan.seed),
            clock=VirtualClock(start + timedelta(seconds=plan.start_offset)),
            labels=_labels_for(plan),
            max_requests=max_requests_per_session,
        )
        await _run_profile(ctx, get_profile(plan.profile).run)
        out.extend(ctx.exchanges)
    out.sort(key=lambda e: e.timestamp)
    return out


async def simulate_live(
    plans: Sequence[SessionPlan],
    *,
    target: str,
    allow_any_target: bool = False,
    time_scale: float = 1.0,
    max_requests: int = 2000,
    max_requests_per_session: int = 400,
    max_rps: float = 50.0,
    spoof_xff: bool = False,
    client: httpx.AsyncClient | None = None,
) -> list[Exchange]:
    """Send the plans' traffic to a lab target (validated by :func:`check_target`)."""
    from tokiwa.eval.profiles import get_profile

    base = check_target(target, allow_any=allow_any_target)
    parts = urlsplit(base)
    own_client = client is None
    http = client or httpx.AsyncClient(
        base_url=base, follow_redirects=False, timeout=httpx.Timeout(10.0), trust_env=False
    )
    transport = HttpTransport(http, max_requests=max_requests, max_rps=max_rps)

    async def run_one(plan: SessionPlan) -> list[Exchange]:
        await asyncio.sleep(plan.start_offset * time_scale)
        ctx = SessionContext(
            transport=transport,
            identity=plan.identity,
            rng=random.Random(plan.seed),
            clock=RealClock(time_scale),
            labels=_labels_for(plan),
            host=parts.netloc,
            scheme=parts.scheme,
            max_requests=max_requests_per_session,
            spoof_xff=spoof_xff,
        )
        await _run_profile(ctx, get_profile(plan.profile).run)
        return ctx.exchanges

    try:
        results = await asyncio.gather(*(run_one(p) for p in plans))
    finally:
        if own_client:
            await http.aclose()
    out = [e for r in results for e in r]
    out.sort(key=lambda e: e.timestamp)
    return out


# ------------------------------------------------------------------------------------ to TOKIWA event


def deterministic_id(ts: datetime, rng: random.Random) -> str:
    """UUIDv7-shaped id from the event time + a seeded RNG (datasets are byte-identical for a given seed)."""
    ms = int(ts.timestamp() * 1000)
    rand = rng.getrandbits(74)
    value = (ms & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76
    value |= ((rand >> 62) & 0xFFF) << 64
    value |= 0b10 << 62
    value |= rand & ((1 << 62) - 1)
    return uuid.UUID(int=value).hex


def exchange_to_event(
    ex: Exchange,
    *,
    rng: random.Random | None = None,
    sensor_id: str = "sim",
    dataset: str = "gate.http",
    dest_ip: str = LAB_DEST_IP,
) -> Event:
    """Gate-equivalent capture of one exchange (headers/query/body redacted like the Gate does)."""
    req, resp = ex.request, ex.response
    header_dict: dict[str, str] = {}
    for k, v in ex.headers:
        header_dict[k] = f"{header_dict[k]}, {v}" if k in header_dict else v
    redacted = redact_headers(header_dict)
    body = req.body
    host_only, _, port = ex.host.partition(":")
    event_kwargs: dict[str, Any] = {}
    if rng is not None:
        event_kwargs["id"] = deterministic_id(ex.timestamp, rng)
    return Event(
        timestamp=ex.timestamp,
        kind=EventKind.HTTP,
        dataset=dataset,
        sensor_id=sensor_id,
        source=Endpoint(ip=ex.source_ip, port=ex.source_port),
        destination=Endpoint(ip=dest_ip, port=int(port) if port.isdigit() else 80),
        http=HttpInfo(
            method=req.method,
            scheme=ex.scheme,
            host=host_only or ex.host,
            path=req.path,
            query=redact_text(req.query) if req.query else None,
            headers=redacted,
            header_order=[k for k, _ in ex.headers],
            user_agent=header_dict.get("user-agent"),
            referrer=header_dict.get("referer"),
            content_type=header_dict.get("content-type"),
            request_body_size=len(body.encode()) if body is not None else 0,
            request_body=redact_text(body[:CAPTURE_BODY_CHARS]) if body else None,
            status=resp.status or None,
            response_size=resp.size,
            response_content_type=resp.content_type or None,
            duration_ms=ex.duration_ms,
            http_version="1.1",
        ),
        labels=dict(ex.labels),
        **event_kwargs,
    )


def exchanges_to_events(exchanges: Sequence[Exchange], *, seed: int = 0, **kwargs: Any) -> list[Event]:
    rng = random.Random(seed ^ 0xE7E7)
    return [exchange_to_event(ex, rng=rng, **kwargs) for ex in exchanges]
