"""TOKIWA Gate ASGI application: reverse proxy + full-request sensor + policy enforcer.

Request flow (first match wins)::

    /__tokiwa/health            -> gate health (never proxied, never captured)
    websocket / Upgrade         -> 501 (v1 does not tunnel WebSockets)
    client IP in blocked        -> 403
    client IP in rate_limited   -> token bucket per client IP, 429 + Retry-After when empty
    client IP in tarpit         -> sleep(ms, capped at 30 s), then continue
    path matches a DecoyRoute   -> decoy response (NEVER forwarded upstream) + DECEPTION event
    client IP in deceive        -> decoy for every request (generic 404 decoy when no route matches)
    otherwise                   -> stream to upstream; HTML canary injected when the policy carries one

Every exchange (except health) yields a redacted ``gate.http`` event queued to the shipper after the response
has been sent, so capture never adds latency in front of the response.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from email.utils import formatdate
from http.cookiejar import CookieJar, DefaultCookiePolicy
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from tokiwa.config import ConfigError, GateSettings, RedactionSettings, get_settings, strict_config_enabled
from tokiwa.gate.capture import BodyCapture, EventBuilder, Exchange, mime_type
from tokiwa.gate.netmatch import IpTable, parse_ip, resolve_forwarded_client
from tokiwa.gate.policy import TARPIT_MAX_MS, CompiledPolicy, PolicyManager, path_anomalies
from tokiwa.gate.proxy import (
    HOP_BY_HOP,
    HTTPX_FRAMING,
    LEGACY_POSITIONS,
    ROUTE_OVERRIDE_HEADERS,
    Headers,
    UpstreamTarget,
    decode_content,
    encode_snippet,
    forwarded_request_headers,
    inject_html,
    raw_path_of,
    strip_hop_by_hop,
    stripped_client_headers,
)
from tokiwa.gate.ratelimit import TokenBucketLimiter
from tokiwa.gate.shipper import EventShipper
from tokiwa.gate.tokens import TokenSource
from tokiwa.schemas.response import DecoyRoute

log = logging.getLogger(__name__)

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

HEALTH_PATH = "/__tokiwa/health"
BLOCKED_BODY = b"Forbidden\n"
RATE_LIMITED_BODY = b"Too Many Requests\n"
WEBSOCKET_BODY = b"Not Implemented: WebSocket is not supported by this gateway\n"
TOO_MANY_HEADERS_BODY = b"Request Header Fields Too Large\n"
BAD_GATEWAY_BODY = b"Bad Gateway\n"
REQUEST_TIMEOUT_BODY = b"Request Timeout\n"
GATEWAY_TIMEOUT_BODY = b"Gateway Timeout\n"
GENERIC_404 = (
    b"<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head>\n"
    b"<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>\n"
)
_NO_INJECT_STATUS = frozenset({204, 206, 304})
# Request body held in memory while a tarpitted request waits (watching for a disconnect reads the body too).
TARPIT_BUFFER_BYTES = 64 * 1024
_DECOY_HEADER_DENY = HOP_BY_HOP | {b"content-length", b"content-encoding", b"content-type", b"date"}


@dataclass
class GateOptions:
    """Operational knobs that are not (yet) part of ``GateSettings`` -- set via ``tokiwa gate run`` flags."""

    upstream_timeout: float = 30.0
    upstream_connect_timeout: float = 5.0
    max_upstream_connections: int = 512
    max_queue: int = 10_000
    # Caddy-style: forward the client's Host header (apps build absolute URLs from it). False = upstream host.
    preserve_host: bool = True
    # HTML responses larger than this (decompressed) are streamed through without canary injection.
    max_inject_bytes: int = 2 * 1024 * 1024
    # How long to wait for the body prefix of a request answered locally (decoys), slowloris guard.
    local_body_timeout: float = 5.0
    initial_policy_fetch: bool = True


class _ClientGone(Exception):
    """The client disconnected while its request body was being streamed upstream."""


class _SlowBody(Exception):
    """The request body stalled or took too long (audit #39); the reason is ``idle`` or ``total``."""


class Gate:
    """All gate state (clients, policy, limiter, shipper) + the raw ASGI request handler."""

    def __init__(
        self,
        settings: GateSettings,
        *,
        options: GateOptions | None = None,
        redaction: RedactionSettings | None = None,
        upstream_transport: httpx.AsyncBaseTransport | None = None,
        server_transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.options = options or GateOptions()
        self.tokens = TokenSource(
            settings.ingest_token.get_secret_value() if settings.ingest_token else None, settings.token_file
        )
        self.target = UpstreamTarget(settings.upstream)
        opts = self.options
        # trust_env=False: never route upstream/server traffic through HTTP(S)_PROXY from the environment.
        # cookies=_no_cookie_jar(): one client serves every visitor, and httpx would otherwise store each upstream
        # Set-Cookie and add it to the next request that carries no Cookie header -- someone else's session.
        self.upstream_client = httpx.AsyncClient(
            transport=upstream_transport,
            timeout=httpx.Timeout(opts.upstream_timeout, connect=opts.upstream_connect_timeout),
            limits=httpx.Limits(
                max_connections=opts.max_upstream_connections,
                max_keepalive_connections=min(128, opts.max_upstream_connections),
            ),
            follow_redirects=False,
            trust_env=False,
            cookies=_no_cookie_jar(),
        )
        self.server_client = httpx.AsyncClient(
            transport=server_transport, timeout=10.0, trust_env=False, cookies=_no_cookie_jar()
        )
        self.policy = PolicyManager(
            self.server_client,
            settings.server_url,
            self.tokens,
            refresh_seconds=settings.policy_refresh_seconds,
            cache_file=_policy_cache_file(settings),
            cache_max_age_hours=settings.policy_cache_max_age_hours,
        )
        self.shipper = EventShipper(
            self.server_client,
            settings.server_url,
            self.tokens,
            batch_size=settings.batch_size,
            flush_interval=settings.flush_interval_seconds,
            max_queue=opts.max_queue,
            sensor_id=settings.sensor_id,
        )
        self.limiter = TokenBucketLimiter(clock=clock)
        self.builder = EventBuilder(
            sensor_id=settings.sensor_id,
            capture_body_bytes=settings.capture_body_bytes,
            redaction=redaction or get_settings().llm.redaction,
            # The server's deception settings, when this process shares its config (else the default name).
            priority_headers=(get_settings().deception.canary_header,),
        )
        self._pass_through = frozenset(
            h.strip().lower().encode("latin-1") for h in settings.forward_client_headers if h.strip()
        )
        self._trusted_proxies = _trusted_proxy_table(settings)
        self._sleep = sleep
        self._tarpit_active = 0  # requests currently held by the tarpit (#99)
        self._tarpit_per_client: Counter[str] = Counter()
        self._inflight: Counter[str] = Counter()  # requests being handled per client IP (#39)
        self.counters: Counter[str] = Counter()
        self._tasks: list[asyncio.Task[None]] = []
        self._upstream_server: bytes | None = None  # mimicked on gate-generated responses

    @property
    def token(self) -> str | None:
        """Current API token (re-read from ``settings.token_file`` when it changes)."""
        return self.tokens.get()

    # ------------------------------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        if not self.token:
            log.warning("gate: no ingest token configured; the server will reject events and policy fetches")
        # The saved copy first (audit #32): if the server is unreachable, the restart does not lift blocks.
        await asyncio.to_thread(self.policy.load_cache)
        if self.options.initial_policy_fetch:
            await self.policy.refresh()
        self._tasks = [
            asyncio.create_task(self._supervise("policy", self.policy.run), name="tokiwa-gate-policy"),
            asyncio.create_task(self._supervise("shipper", self.shipper.run), name="tokiwa-gate-shipper"),
        ]
        log.info(
            "gate %s: upstream=%s server=%s policy=%s",
            self.settings.sensor_id,
            self.settings.upstream,
            self.settings.server_url,
            self.policy.current.version,
        )

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
        await self.shipper.aclose()
        await self.upstream_client.aclose()
        await self.server_client.aclose()

    @asynccontextmanager
    async def running(self) -> AsyncIterator[Gate]:
        await self.start()
        try:
            yield self
        finally:
            await self.stop()

    @staticmethod
    async def _supervise(name: str, loop_fn: Callable[[], Awaitable[None]]) -> None:
        """Background loops must survive bugs: a dead shipper would silently blind the SOC."""
        while True:
            try:
                await loop_fn()
                return
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("gate %s loop crashed; restarting in 1s", name)
                await asyncio.sleep(1.0)

    # -------------------------------------------------------------------------------------------- health
    async def health(self, request: Request) -> JSONResponse:
        body: dict[str, Any] = {"status": "ok"}
        peer = parse_ip(request.client.host if request.client else None)
        # Details only for operators (loopback / private networks); the internet just sees "ok".
        if peer is not None and (peer.is_loopback or peer.is_private):
            body.update(
                sensor_id=self.settings.sensor_id,
                upstream=self.settings.upstream,
                policy=self.policy.stats(),
                shipper=self.shipper.snapshot(),
                requests=dict(self.counters),
            )
        return JSONResponse(body, headers={"cache-control": "no-store"})

    # ------------------------------------------------------------------------------------------- handler
    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            await self._reject_websocket(scope, receive, send)
            return
        if scope["type"] != "http":
            return
        ex = self._exchange(scope)
        key = ex.client_ip or "unknown"
        cap = self.settings.max_requests_per_client
        try:
            if cap and self._inflight[key] >= cap:
                # Audit #39: one client holding many slow requests would otherwise take every upstream
                # connection. Answered at once, so the event reaches the server while the attack goes on.
                ex.tag("gate:conn_limit")
                ex.labels["gate.action"] = "conn_limit"
                await self._respond(
                    send, ex, 429, RATE_LIMITED_BODY, b"text/plain; charset=utf-8", [(b"retry-after", b"5")]
                )
                return
            self._inflight[key] += 1
            try:
                await self._dispatch(scope, receive, send, ex, self.policy.current)
            finally:
                # Also on cancellation / disconnect: a leaked count would lock the client out for good.
                self._inflight[key] -= 1
                if self._inflight[key] <= 0:
                    del self._inflight[key]
        finally:
            self._capture(ex)

    def _capture(self, ex: Exchange) -> None:
        self.counters[ex.labels.get("gate.action", "proxy")] += 1
        try:
            self.shipper.submit_many(self.builder.build(ex))
        except Exception:  # capture must never break proxying
            log.exception("gate: failed to build capture event")

    def _exchange(self, scope: Scope) -> Exchange:
        client = scope.get("client") or (None, None)
        server = scope.get("server") or (None, None)
        headers: Headers = [(bytes(k), bytes(v)) for k, v in scope.get("headers", [])]
        ex = Exchange(
            method=scope.get("method", "GET"),
            scheme=scope.get("scheme", "http"),
            path=scope.get("path", "/"),
            query=scope.get("query_string", b"").decode("latin-1"),
            raw_headers=headers,
            client_ip=client[0],
            client_port=client[1],
            peer_ip=client[0],
            server_ip=server[0],
            server_port=server[1],
            http_version=scope.get("http_version"),
            body=BodyCapture(self.settings.capture_body_bytes),
        )
        if self.settings.trust_forwarded_for:
            xff = ", ".join(v.decode("latin-1") for k, v in headers if k.lower() == b"x-forwarded-for")
            client_ip, ex.forwarded_trusted = resolve_forwarded_client(ex.peer_ip, xff, self._trusted_proxies)
            if not ex.forwarded_trusted:
                if xff:
                    # Trust is configured, yet this peer is not one of the proxies: someone reached the Gate
                    # directly (bypassing the LB) and claimed an address. Their own address is kept (#22).
                    ex.tag("gate:untrusted_forwarded_for")
            elif client_ip and client_ip != ex.client_ip:
                if ex.client_ip:
                    ex.labels["gate.peer_ip"] = ex.client_ip
                ex.client_ip = client_ip
        return ex

    async def _dispatch(
        self, scope: Scope, receive: Receive, send: Send, ex: Exchange, policy: CompiledPolicy
    ) -> None:
        ip = parse_ip(ex.client_ip)
        if policy.version is not None:
            ex.labels["gate.policy"] = policy.version
        anomalies = path_anomalies(ex.path)
        if (
            anomalies
        ):  # ;params, NUL, backslash, double encoding ...: only a lenient upstream resolves these (#54)
            ex.tag("gate:path_anomaly")
            ex.labels["gate.path_anomaly"] = ",".join(anomalies)

        blocked = policy.blocked.lookup(ip)
        if blocked is not None:
            ex.tag("gate:blocked")
            ex.labels["gate.action"] = "blocked"
            ex.labels["gate.rule"] = blocked[0]
            await self._respond(send, ex, 403, BLOCKED_BODY, b"text/plain; charset=utf-8")
            return

        limited = policy.rate_limited.lookup(ip)
        if limited is not None:
            allowed, retry_after = self.limiter.allow(ex.client_ip or "unknown", limited[1])
            if not allowed:
                ex.tag("gate:rate_limited")
                ex.labels["gate.action"] = "rate_limited"
                ex.labels["gate.rule"] = limited[0]
                await self._respond(
                    send,
                    ex,
                    429,
                    RATE_LIMITED_BODY,
                    b"text/plain; charset=utf-8",
                    [(b"retry-after", str(int(retry_after)).encode())],
                )
                return

        if _is_websocket_upgrade(ex):
            log.info(
                "gate: rejecting WebSocket upgrade from %s for %s (unsupported in v1)", ex.client_ip, ex.path
            )
            ex.tag("gate:websocket_unsupported")
            ex.labels["gate.action"] = "websocket"
            await self._respond(send, ex, 501, WEBSOCKET_BODY, b"text/plain; charset=utf-8")
            return

        tarpit = policy.tarpit.lookup(ip)
        if tarpit is not None and tarpit[1] > 0:
            delay_ms = min(tarpit[1], TARPIT_MAX_MS)
            ex.tag("gate:tarpit")
            ex.labels["gate.tarpit_ms"] = str(delay_ms)
            key = ex.client_ip or "unknown"
            if not self._tarpit_acquire(key):
                # Holding more of this client's requests would cost the Gate more than the client (#99).
                ex.tag("gate:tarpit_overflow")
                ex.labels["gate.action"] = "tarpit_overflow"
                retry = str(max(1, delay_ms // 1000)).encode()
                await self._respond(
                    send, ex, 429, RATE_LIMITED_BODY, b"text/plain; charset=utf-8", [(b"retry-after", retry)]
                )
                return
            try:
                waited = await self._tarpit_wait(receive, delay_ms / 1000.0)
            finally:
                self._tarpit_release(key)
            if waited is None:  # the client hung up while held: nothing left to answer or forward
                ex.tag("gate:client_disconnect")
                ex.labels["gate.action"] = "client_disconnect"
                ex.status = 499
                return
            receive = waited

        decoy = policy.decoys.match(ex.path)
        override = _route_override_path(ex)
        if override is not None:
            # X-Original-URL & co. never reach the upstream (gate.proxy strips them), but asking for a decoy
            # through them is the same probe as asking for it directly: answer with the decoy (audit #147).
            ex.tag("gate:route_override")
            if decoy is None:
                decoy = policy.decoys.match(override)
        deceived = policy.deceive.lookup(ip) is not None
        if decoy is not None or deceived:
            await self._serve_decoy(receive, send, ex, decoy, deceived)
            return

        max_headers = self.settings.max_request_headers
        if max_headers > 0 and len(ex.raw_headers) > max_headers:
            # The event keeps at most MAX_CAPTURED_HEADERS names: never forward more than the SOC can see (#140).
            ex.tag("gate:too_many_headers")
            ex.labels["gate.action"] = "too_many_headers"
            await self._respond(send, ex, 431, TOO_MANY_HEADERS_BODY, b"text/plain; charset=utf-8")
            return

        ex.labels["gate.action"] = "proxy"
        await self._proxy(scope, receive, send, ex, policy)

    # -------------------------------------------------------------------------------------------- tarpit
    def _tarpit_acquire(self, key: str) -> bool:
        s = self.settings
        if s.tarpit_max_concurrent and self._tarpit_active >= s.tarpit_max_concurrent:
            return False
        if s.tarpit_max_per_client and self._tarpit_per_client[key] >= s.tarpit_max_per_client:
            return False
        self._tarpit_active += 1
        self._tarpit_per_client[key] += 1
        return True

    def _tarpit_release(self, key: str) -> None:
        self._tarpit_active -= 1
        self._tarpit_per_client[key] -= 1
        if self._tarpit_per_client[key] <= 0:
            del self._tarpit_per_client[key]

    async def _tarpit_wait(self, receive: Receive, seconds: float) -> Receive | None:
        """Hold the request for ``seconds`` unless the client disconnects first (then None).

        Watching for ``http.disconnect`` means calling ``receive()``, which also yields request-body chunks; those
        are kept (up to TARPIT_BUFFER_BYTES) and replayed by the returned ``receive`` so the body still reaches
        the capture and the upstream. Past that bound the wait finishes without disconnect detection.
        """
        buffered: list[Message] = []
        size = 0
        sleeper = asyncio.ensure_future(self._sleep(seconds))
        pending: asyncio.Future[Message] | None = None
        try:
            while not sleeper.done():
                if size > TARPIT_BUFFER_BYTES:
                    await sleeper
                    break
                pending = asyncio.ensure_future(receive())
                await asyncio.wait({sleeper, pending}, return_when=asyncio.FIRST_COMPLETED)
                if not pending.done():
                    break  # slept the full delay; the receive() in flight is cancelled below
                message = pending.result()
                pending = None
                if message.get("type") == "http.disconnect":
                    return None
                buffered.append(message)
                size += len(message.get("body", b""))
        finally:
            for fut in (pending, sleeper):
                if fut is not None and not fut.done():
                    fut.cancel()
        if not buffered:
            return receive

        async def replay() -> Message:
            if buffered:
                return buffered.pop(0)
            return await receive()

        return replay

    # -------------------------------------------------------------------------------------------- decoys
    async def _serve_decoy(
        self, receive: Receive, send: Send, ex: Exchange, decoy: DecoyRoute | None, deceived: bool
    ) -> None:
        """Answer locally. The request (and its body) never reaches the upstream application."""
        await self._read_local_body(receive, ex)
        if deceived:
            ex.tag("gate:deceive")
        if decoy is not None:
            ex.decoy = decoy
            ex.tag("gate:decoy")
            ex.labels["gate.action"] = "decoy"
            ex.labels["gate.decoy_asset"] = decoy.asset_id
            extra = _sanitize_decoy_headers(decoy.headers)
            await self._respond(
                send,
                ex,
                decoy.status_code,
                decoy.body.encode("utf-8"),
                decoy.content_type.encode("latin-1", errors="replace"),
                extra,
            )
            return
        ex.tag("gate:decoy_generic")
        ex.labels["gate.action"] = "deceive"
        await self._respond(send, ex, 404, GENERIC_404, b"text/html; charset=utf-8")

    async def _read_local_body(self, receive: Receive, ex: Exchange) -> None:
        """Read only the capture prefix of a locally answered request (bounded in size and time)."""
        if ex.body.limit <= 0:
            return

        async def _read() -> None:
            while True:
                message = await receive()
                if message["type"] != "http.request":
                    return  # http.disconnect
                ex.body.feed(message.get("body", b""))
                if not message.get("more_body", False):
                    ex.body.complete = True
                    return
                if ex.body.size >= ex.body.limit:
                    return

        try:
            await asyncio.wait_for(_read(), timeout=self.options.local_body_timeout)
        except TimeoutError:
            ex.tag("gate:body_timeout")

    # --------------------------------------------------------------------------------------------- proxy
    async def _proxy(
        self, scope: Scope, receive: Receive, send: Send, ex: Exchange, policy: CompiledPolicy
    ) -> None:
        url, target = self.target.resolve(raw_path_of(scope), scope.get("query_string", b""))
        headers = forwarded_request_headers(
            ex.raw_headers,
            peer_ip=ex.peer_ip,
            scheme=ex.scheme,
            trust_forwarded_for=ex.forwarded_trusted,
            preserve_host=self.options.preserve_host,
            upstream_host=self.target.host_header,
            restrict_encoding=policy.html_injection is not None,
            client_ip=ex.client_ip,
            pass_through=self._pass_through,
        )
        stripped = stripped_client_headers(ex.raw_headers, self._pass_through)
        if stripped:
            ex.tag(
                "gate:client_ip_header"
            )  # the client claimed an address / scheme / route itself (#138/#147)
            ex.labels["gate.stripped_headers"] = ",".join(stripped)
        content = self._body_stream(receive, ex) if _has_body(ex) else None
        if content is None:
            ex.body.complete = True
        request = self.upstream_client.build_request(
            ex.method, url, headers=headers, content=content, extensions={"target": target}
        )
        # httpx merges its client defaults (User-Agent: python-httpx, Accept, Accept-Encoding) into every request:
        # a client that sent none would reach the upstream as the Gate's own library (#149).
        sent = {k.decode("latin-1") for k, _ in headers}
        for name in [n for n in request.headers if n not in sent and n not in HTTPX_FRAMING]:
            del request.headers[name]
        t_upstream = time.perf_counter()
        try:
            response = await self.upstream_client.send(request, stream=True)
        except _ClientGone:
            ex.tag("gate:client_disconnect")
            ex.status = 499  # nginx convention: client closed request
            return
        except _SlowBody as exc:
            ex.tag("gate:slow_body")
            ex.labels["gate.action"] = "slow_body"
            ex.labels["gate.slow_body"] = str(exc)
            await self._respond(
                send, ex, 408, REQUEST_TIMEOUT_BODY, b"text/plain; charset=utf-8", [(b"connection", b"close")]
            )
            return
        except httpx.TimeoutException as exc:
            await self._upstream_failed(send, ex, 504, GATEWAY_TIMEOUT_BODY, exc)
            return
        except httpx.HTTPError as exc:
            await self._upstream_failed(send, ex, 502, BAD_GATEWAY_BODY, exc)
            return

        try:
            ex.labels["gate.upstream_ms"] = f"{(time.perf_counter() - t_upstream) * 1000.0:.1f}"
            resp_headers = strip_hop_by_hop(response.headers.raw)
            server_hdr = response.headers.get("server")
            if server_hdr:
                self._upstream_server = server_hdr.encode("latin-1", errors="replace")
            if not any(k == b"date" for k, _ in resp_headers):
                resp_headers.append((b"date", formatdate(usegmt=True).encode()))
            if response.is_stream_consumed:
                # Transport handed over a pre-buffered response (e.g. httpx.MockTransport): only the *decoded*
                # content survives, so frame it accordingly.
                resp_headers = [
                    (k, v) for k, v in resp_headers if k not in (b"content-length", b"content-encoding")
                ]
                resp_headers.append((b"content-length", str(len(response.content)).encode()))
            content_type = response.headers.get("content-type")
            ex.response_content_type = content_type
            verdict = self._injection_verdict(ex, response, content_type) if policy.html_injection else "no"
            if verdict == "yes" and policy.html_injection:
                await self._send_injected(
                    send, ex, response, resp_headers, policy.html_injection, policy.html_injection_positions
                )
            else:
                if verdict == "too_large":
                    ex.tag("gate:inject_skipped")
                await self._send_streamed(send, ex, response, resp_headers)
        except httpx.HTTPError as exc:
            if ex.status is None:
                await self._upstream_failed(send, ex, 502, BAD_GATEWAY_BODY, exc)
            else:  # headers already sent: the only honest signal left is an aborted response
                ex.tag("gate:upstream_error")
                log.warning("gate: upstream body error for %s %s: %s", ex.method, ex.path, exc)
        finally:
            await response.aclose()

    def _body_stream(self, receive: Receive, ex: Exchange) -> AsyncIterator[bytes]:
        """Stream the request body upstream while teeing the first ``capture_body_bytes`` into the capture."""

        idle = self.settings.body_idle_timeout_seconds
        total = self.settings.body_total_timeout_seconds
        loop = asyncio.get_running_loop()
        deadline = loop.time() + total if total else None

        async def next_message() -> Message:
            # Audit #39: without a limit, a client trickling one byte every few seconds held an upstream
            # connection for as long as it liked. Both an idle gap and the whole body are bounded.
            wait = idle or None
            if deadline is not None:
                left = deadline - loop.time()
                if left <= 0:
                    raise _SlowBody("total")
                wait = left if wait is None else min(wait, left)
            if wait is None:
                return await receive()
            try:
                return await asyncio.wait_for(receive(), wait)
            except TimeoutError:
                raise _SlowBody(
                    "total" if deadline is not None and loop.time() >= deadline else "idle"
                ) from None

        async def gen() -> AsyncIterator[bytes]:
            while True:
                message = await next_message()
                if message["type"] == "http.request":
                    chunk = message.get("body", b"")
                    if chunk:
                        ex.body.feed(chunk)
                        yield chunk
                    if not message.get("more_body", False):
                        ex.body.complete = True
                        return
                elif message["type"] == "http.disconnect":
                    raise _ClientGone

        return gen()

    async def _upstream_failed(
        self, send: Send, ex: Exchange, status: int, body: bytes, exc: Exception
    ) -> None:
        ex.tag("gate:upstream_error")
        ex.labels["gate.action"] = "upstream_error"
        ex.labels["gate.error"] = type(exc).__name__
        log.warning(
            "gate: upstream %s for %s %s: %s", status, ex.method, ex.path, str(exc) or type(exc).__name__
        )
        await self._respond(send, ex, status, body, b"text/plain; charset=utf-8", mimic_server=False)

    def _injection_verdict(self, ex: Exchange, response: httpx.Response, content_type: str | None) -> str:
        """``yes`` / ``no`` (not an HTML document response) / ``too_large`` (declared size over the limit)."""
        if ex.method == "HEAD" or response.status_code < 200 or response.status_code in _NO_INJECT_STATUS:
            return "no"
        if mime_type(content_type) != "text/html":
            return "no"
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self.options.max_inject_bytes:
            return "too_large"
        return "yes"

    async def _send_streamed(
        self, send: Send, ex: Exchange, response: httpx.Response, headers: Headers
    ) -> None:
        await send({"type": "http.response.start", "status": response.status_code, "headers": headers})
        ex.status = response.status_code
        async for chunk in _raw_chunks(response):
            if chunk:
                ex.response_size += len(chunk)
                await send({"type": "http.response.body", "body": chunk, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    async def _send_injected(
        self,
        send: Send,
        ex: Exchange,
        response: httpx.Response,
        headers: Headers,
        snippet: str,
        positions: tuple[str, ...] = LEGACY_POSITIONS,
    ) -> None:
        limit = self.options.max_inject_bytes
        raw = bytearray()
        chunks = _raw_chunks(response)
        async for chunk in chunks:
            raw += chunk
            if len(raw) > limit:
                # Too large to rewrite: stream what we have plus the rest, untouched.
                ex.tag("gate:inject_skipped")
                await send(
                    {"type": "http.response.start", "status": response.status_code, "headers": headers}
                )
                ex.status = response.status_code
                ex.response_size += len(raw)
                await send({"type": "http.response.body", "body": bytes(raw), "more_body": True})
                async for rest in chunks:
                    if rest:
                        ex.response_size += len(rest)
                        await send({"type": "http.response.body", "body": rest, "more_body": True})
                await send({"type": "http.response.body", "body": b"", "more_body": False})
                return

        body = bytes(raw)
        content_type = response.headers.get("content-type")
        encoding = b", ".join(v for k, v in headers if k == b"content-encoding").decode("latin-1")
        decoded = decode_content(body, encoding, limit)
        injected = (
            inject_html(decoded, encode_snippet(snippet, content_type, decoded), positions)
            if decoded is not None
            else None
        )
        if injected is None:
            ex.tag("gate:inject_skipped")
        else:
            ex.tag("gate:html_injected")
            # Body changed: recompute length, drop encoding (we serve it decoded) and validators of the old body.
            stale = {b"content-length", b"content-encoding", b"etag", b"content-md5", b"digest"}
            headers = [(k, v) for k, v in headers if k not in stale]
            headers.append((b"content-length", str(len(injected)).encode()))
            body = injected
        await send({"type": "http.response.start", "status": response.status_code, "headers": headers})
        ex.status = response.status_code
        ex.response_size = len(body)
        await send({"type": "http.response.body", "body": body, "more_body": False})

    # ------------------------------------------------------------------------------------------- helpers
    async def _respond(
        self,
        send: Send,
        ex: Exchange,
        status: int,
        body: bytes,
        content_type: bytes,
        extra_headers: Headers | None = None,
        *,
        mimic_server: bool = True,
    ) -> None:
        """Gate-generated response. Looks like the upstream (same Server header) so decoys don't stand out."""
        headers: Headers = [
            (b"content-type", content_type),
            (b"content-length", str(len(body)).encode()),
            (b"date", formatdate(usegmt=True).encode()),
        ]
        if mimic_server and self._upstream_server:
            headers.append((b"server", self._upstream_server))
        # Never let a shared cache / CDN keep an answer meant for one client (a deceive-mode 404, a 502 during an
        # upstream hiccup) and serve it to everyone else (#148). A decoy's own Cache-Control wins.
        if not any(k == b"cache-control" for k, _ in extra_headers or ()):
            headers.append((b"cache-control", b"no-store"))
        if extra_headers:
            headers.extend(extra_headers)
        send_body = b"" if ex.method == "HEAD" else body
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": send_body, "more_body": False})
        ex.status = status
        ex.response_size = len(send_body)
        ex.response_content_type = content_type.decode("latin-1")

    async def _reject_websocket(self, scope: Scope, receive: Receive, send: Send) -> None:
        ex = self._exchange({**scope, "method": "GET"})
        ex.tag("gate:websocket_unsupported")
        ex.labels["gate.action"] = "websocket"
        ex.body.complete = True
        log.info("gate: rejecting WebSocket from %s for %s (unsupported in v1)", ex.client_ip, ex.path)
        try:
            message = await receive()
            if message.get("type") != "websocket.connect":
                return
            if "websocket.http.response" in (scope.get("extensions") or {}):
                headers = [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", str(len(WEBSOCKET_BODY)).encode()),
                ]
                await send({"type": "websocket.http.response.start", "status": 501, "headers": headers})
                await send({"type": "websocket.http.response.body", "body": WEBSOCKET_BODY})
                ex.status = 501
                ex.response_size = len(WEBSOCKET_BODY)
            else:  # server without the denial-response extension: closing before accept yields HTTP 403
                await send({"type": "websocket.close", "code": 1003})
                ex.status = 403
        finally:
            self._capture(ex)


def _policy_cache_file(settings: GateSettings) -> Path | None:
    """Where the last fetched policy is kept (audit #32); None when ``gate.persist_policy`` is off."""
    if not settings.persist_policy:
        return None
    if settings.policy_cache_file is not None:
        return settings.policy_cache_file
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", settings.sensor_id)[:64] or "gate"
    return get_settings().server.data_dir / f"gate-policy-{safe_id}.json"


def _trusted_proxy_table(settings: GateSettings) -> IpTable[bool] | None:
    """``gate.trusted_proxies`` as a lookup table; None = legacy "trust any peer" mode (audit #22).

    Only meaningful with ``trust_forwarded_for``. An unparsable entry or the legacy mode is a configuration
    problem: warned about, and refused under ``TOKIWA_STRICT_CONFIG=1`` like other config issues.
    """
    if not settings.trust_forwarded_for:
        return None
    table, invalid = IpTable.build((p, True) for p in settings.trusted_proxies)
    problems: list[str] = []
    if invalid:
        problems.append(f"gate.trusted_proxies has entries that are not IPs/CIDRs: {', '.join(invalid)}")
    if not settings.trusted_proxies:
        problems.append(
            "gate.trust_forwarded_for is on but gate.trusted_proxies is empty: X-Forwarded-For is accepted from "
            "any client that reaches the Gate, which can then claim any source address. List the proxy/LB "
            "addresses in gate.trusted_proxies"
        )
    for problem in problems:
        log.warning("gate config: %s", problem)
    if problems and strict_config_enabled():
        raise ConfigError("; ".join(problems) + " (TOKIWA_STRICT_CONFIG is set)")
    # A list whose entries all failed to parse trusts no peer (not "any peer"): a typo must not widen trust.
    return table if settings.trusted_proxies else None


def _no_cookie_jar() -> CookieJar:
    """A cookie jar that never stores nor sends anything (the Gate is a shared, transparent proxy).

    Passed to httpx as a raw ``CookieJar`` so httpx keeps it (a ``dict`` / ``httpx.Cookies`` would be copied into a
    default jar without this policy).
    """
    return CookieJar(policy=DefaultCookiePolicy(allowed_domains=[]))


async def _raw_chunks(response: httpx.Response) -> AsyncIterator[bytes]:
    """Raw (still content-encoded) body bytes; falls back to the buffered content of a pre-read response."""
    if response.is_stream_consumed:
        if response.content:
            yield response.content
        return
    async for chunk in response.aiter_raw():
        yield chunk


def _is_websocket_upgrade(ex: Exchange) -> bool:
    upgrade = (ex.header("upgrade") or "").lower()
    return "websocket" in upgrade


def _route_override_path(ex: Exchange) -> str | None:
    """The path an ``X-Original-URL`` / ``X-Rewrite-URL`` / ``X-Override-URL`` header asks for (decoded once, like
    ``scope['path']``), or None when the request has none."""
    for k, v in ex.raw_headers:
        if k.lower() not in ROUTE_OVERRIDE_HEADERS:
            continue
        value = v.decode("latin-1").strip()
        if "://" in value:
            try:
                value = urlsplit(value).path
            except ValueError:
                value = ""
        return unquote(value.split("?", 1)[0].split("#", 1)[0]) or "/"
    return None


def _has_body(ex: Exchange) -> bool:
    if ex.header("transfer-encoding"):
        return True
    declared = (ex.header("content-length") or "").strip()
    return declared.isdigit() and int(declared) > 0


def _sanitize_decoy_headers(headers: dict[str, str]) -> Headers:
    """Server-provided decoy headers, minus anything that would corrupt framing or allow header injection."""
    out: Headers = []
    for name, value in headers.items():
        key = name.strip().lower()
        if not key or key.encode("latin-1", errors="replace") in _DECOY_HEADER_DENY:
            continue
        if any(c in name + value for c in "\r\n\x00"):
            continue
        try:
            out.append((key.encode("latin-1"), value.encode("latin-1")))
        except UnicodeEncodeError:
            continue
    return out


def create_gate_app(settings: GateSettings | None = None, **kwargs: Any) -> Starlette:
    """Build the Starlette app; ``kwargs`` go to :class:`Gate` (options, transports, sleep/clock for tests)."""
    gate = Gate(settings or get_settings().gate, **kwargs)

    @asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        async with gate.running():
            yield

    app = Starlette(
        routes=[
            Route(HEALTH_PATH, gate.health, methods=["GET"]),
            Mount("", app=gate.handle),
        ],
        lifespan=lifespan,
    )
    app.state.gate = gate
    return app


def gate_of(app: Starlette) -> Gate:
    gate = app.state.gate
    assert isinstance(gate, Gate)
    return gate
