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
import time
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from email.utils import formatdate
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from tokiwa.config import GateSettings, RedactionSettings, get_settings
from tokiwa.gate.capture import BodyCapture, EventBuilder, Exchange, mime_type
from tokiwa.gate.netmatch import parse_ip
from tokiwa.gate.policy import TARPIT_MAX_MS, CompiledPolicy, PolicyManager
from tokiwa.gate.proxy import (
    HOP_BY_HOP,
    Headers,
    UpstreamTarget,
    decode_content,
    encode_snippet,
    forwarded_request_headers,
    inject_before_body_close,
    raw_path_of,
    strip_hop_by_hop,
)
from tokiwa.gate.ratelimit import TokenBucketLimiter
from tokiwa.gate.shipper import EventShipper
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
BAD_GATEWAY_BODY = b"Bad Gateway\n"
GATEWAY_TIMEOUT_BODY = b"Gateway Timeout\n"
GENERIC_404 = (
    b"<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head>\n"
    b"<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>\n"
)
_NO_INJECT_STATUS = frozenset({204, 206, 304})
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
        self.token = settings.ingest_token.get_secret_value() if settings.ingest_token else None
        self.target = UpstreamTarget(settings.upstream)
        opts = self.options
        # trust_env=False: never route upstream/server traffic through HTTP(S)_PROXY from the environment.
        self.upstream_client = httpx.AsyncClient(
            transport=upstream_transport,
            timeout=httpx.Timeout(opts.upstream_timeout, connect=opts.upstream_connect_timeout),
            limits=httpx.Limits(
                max_connections=opts.max_upstream_connections,
                max_keepalive_connections=min(128, opts.max_upstream_connections),
            ),
            follow_redirects=False,
            trust_env=False,
        )
        self.server_client = httpx.AsyncClient(transport=server_transport, timeout=10.0, trust_env=False)
        self.policy = PolicyManager(
            self.server_client,
            settings.server_url,
            self.token,
            refresh_seconds=settings.policy_refresh_seconds,
        )
        self.shipper = EventShipper(
            self.server_client,
            settings.server_url,
            self.token,
            batch_size=settings.batch_size,
            flush_interval=settings.flush_interval_seconds,
            max_queue=opts.max_queue,
        )
        self.limiter = TokenBucketLimiter(clock=clock)
        self.builder = EventBuilder(
            sensor_id=settings.sensor_id,
            capture_body_bytes=settings.capture_body_bytes,
            redaction=redaction or get_settings().llm.redaction,
        )
        self._sleep = sleep
        self.counters: Counter[str] = Counter()
        self._tasks: list[asyncio.Task[None]] = []
        self._upstream_server: bytes | None = None  # mimicked on gate-generated responses

    # ------------------------------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        if not self.token:
            log.warning("gate: no ingest token configured; the server will reject events and policy fetches")
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
        try:
            await self._dispatch(scope, receive, send, ex, self.policy.current)
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
            # Right-most entry = the address the trusted proxy in front of us saw (left-most is client-supplied).
            for candidate in reversed([p.strip() for p in xff.split(",") if p.strip()]):
                ip = parse_ip(candidate)
                if ip is not None:
                    if ex.client_ip:
                        ex.labels["gate.peer_ip"] = ex.client_ip
                    ex.client_ip = str(ip)
                    break
        return ex

    async def _dispatch(
        self, scope: Scope, receive: Receive, send: Send, ex: Exchange, policy: CompiledPolicy
    ) -> None:
        ip = parse_ip(ex.client_ip)
        if policy.version is not None:
            ex.labels["gate.policy"] = policy.version

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
            await self._sleep(delay_ms / 1000.0)

        decoy = policy.decoys.match(ex.path)
        deceived = policy.deceive.lookup(ip) is not None
        if decoy is not None or deceived:
            await self._serve_decoy(receive, send, ex, decoy, deceived)
            return

        ex.labels["gate.action"] = "proxy"
        await self._proxy(scope, receive, send, ex, policy)

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
            trust_forwarded_for=self.settings.trust_forwarded_for,
            preserve_host=self.options.preserve_host,
            upstream_host=self.target.host_header,
            restrict_encoding=policy.html_injection is not None,
        )
        content = self._body_stream(receive, ex) if _has_body(ex) else None
        if content is None:
            ex.body.complete = True
        request = self.upstream_client.build_request(
            ex.method, url, headers=headers, content=content, extensions={"target": target}
        )
        t_upstream = time.perf_counter()
        try:
            response = await self.upstream_client.send(request, stream=True)
        except _ClientGone:
            ex.tag("gate:client_disconnect")
            ex.status = 499  # nginx convention: client closed request
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
                await self._send_injected(send, ex, response, resp_headers, policy.html_injection)
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

        async def gen() -> AsyncIterator[bytes]:
            while True:
                message = await receive()
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
        self, send: Send, ex: Exchange, response: httpx.Response, headers: Headers, snippet: str
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
            inject_before_body_close(decoded, encode_snippet(snippet, content_type))
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
        if status in (403, 429, 501):
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
