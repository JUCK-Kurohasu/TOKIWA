"""Pure-ASGI middlewares for the API server (no BaseHTTPMiddleware: it buffers/wraps streaming responses).

- :class:`BodySizeLimitMiddleware`  413 for request bodies over the configured size (audit #57)
- :class:`SecurityHeadersMiddleware`  CSP / frame / nosniff / referrer headers on every response (audit #66)
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# --- security headers (audit #66) ------------------------------------------------------------------------
# The UI renders attacker-supplied telemetry all day and keeps its JWT in localStorage, so a CSP is the
# backstop if an XSS ever slips into a view. The Vite build has no inline scripts (checked on the build
# output); 'unsafe-inline' for styles is needed because a bundled library injects a <style> element.
SPA_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'; object-src 'none'"
)
# FastAPI's Swagger UI loads its JS/CSS from cdn.jsdelivr.net, its favicon from fastapi.tiangolo.com, and
# boots with an inline <script>; only the docs pages get these allowances.
DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'; object-src 'none'"
)
# JSON / SSE responses are never rendered as documents by the UI: nothing may load from them.
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
DOCS_PREFIX = "/api/docs"
API_PREFIX = "/api/"
ASSETS_PREFIX = "/assets/"
# Vite puts a content hash in every file name under /assets/, so they can be cached forever.
ASSETS_CACHE_CONTROL = "public, max-age=31536000, immutable"
_COMMON_HEADERS = (
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
)


class RequestBodyTooLarge(HTTPException):
    """Raised from ``receive`` once a streamed (chunked) body passes the limit.

    It is an ``HTTPException`` on purpose: FastAPI re-raises those unchanged while reading the body (anything else
    becomes "400 There was an error parsing the body"), so the app's normal handler renders the 413.
    """

    def __init__(self, limit: int) -> None:
        super().__init__(status_code=413, detail=f"request body too large (limit {limit} bytes)")


class BodySizeLimitMiddleware:
    """Reject request bodies larger than a per-path-prefix limit, before the app parses them.

    The limit is applied twice: a declared ``Content-Length`` above it is answered with 413 without reading the
    body, and the bytes actually received are counted (chunked uploads, lying headers). The application is
    reverse-proxy independent this way; a proxy limit in front of it is still recommended (docs/deploy.md).
    """

    def __init__(
        self, app: ASGIApp, *, default_limit: int, prefix_limits: Sequence[tuple[str, int]] = ()
    ) -> None:
        self.app = app
        self.default_limit = default_limit
        # Longest prefix first so "/api/v1/ingest/" wins over a hypothetical "/api/v1/".
        self.prefix_limits = sorted(prefix_limits, key=lambda item: len(item[0]), reverse=True)

    def limit_for(self, path: str) -> int:
        for prefix, limit in self.prefix_limits:
            if path.startswith(prefix):
                return limit
        return self.default_limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.limit_for(scope.get("path", ""))
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                declared = value.strip()
                # Length check first: no int() of a 10,000-digit header.
                if declared.isdigit() and (len(declared) > 18 or int(declared) > limit):
                    await _reject(send, limit)
                    return
                break

        received = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise RequestBodyTooLarge(limit)
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except RequestBodyTooLarge:
            # Normally rendered by the app's HTTPException handler; this covers code that reads the body outside
            # FastAPI's request handling.
            if started:
                raise
            await _reject(send, limit)


async def _reject(send: Send, limit: int) -> None:
    body = json.dumps({"detail": f"request body too large (limit {limit} bytes)"}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def security_headers_for(path: str) -> list[tuple[str, str]]:
    """Headers for a response to ``path``: common ones + the CSP of its tier (docs / API / UI)."""
    if path == DOCS_PREFIX or path.startswith(DOCS_PREFIX + "/"):
        csp = DOCS_CSP
    elif path.startswith(API_PREFIX):
        csp = API_CSP
    else:
        csp = SPA_CSP
    headers = [*_COMMON_HEADERS, ("content-security-policy", csp)]
    if path.startswith(ASSETS_PREFIX):
        headers.append(("cache-control", ASSETS_CACHE_CONTROL))
    return headers


class SecurityHeadersMiddleware:
    """Add security headers to every HTTP response; a header the route already set is left alone.

    (``/api/v1/stream`` sets its own ``Cache-Control``; ``index.html`` is served with ``no-store`` by the SPA
    route.) Pure ASGI so streaming responses (SSE) pass through untouched.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        extra = security_headers_for(scope.get("path", ""))

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", []))
                headers = MutableHeaders(scope=message)
                for name, value in extra:
                    if name not in headers:
                        headers.append(name, value)
            await send(message)

        await self.app(scope, receive, send_with_headers)
