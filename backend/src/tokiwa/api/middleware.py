"""Pure-ASGI middlewares for the API server (no BaseHTTPMiddleware: it buffers/wraps streaming responses).

- :class:`BodySizeLimitMiddleware`  413 for request bodies over the configured size (audit #57)
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send


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
