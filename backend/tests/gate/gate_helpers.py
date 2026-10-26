"""Gate test helpers: in-process upstream (ASGI), fake TOKIWA server (httpx.MockTransport), fake time.

Nothing here opens a socket: upstream and server are reached through httpx transports, and the gate itself is
driven through ``httpx.ASGITransport`` (or raw ASGI calls for scopes httpx cannot express).
"""

from __future__ import annotations

import gzip
import json
import zlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from tokiwa.gate.app import Gate
from tokiwa.schemas.response import GatePolicy
from tokiwa.util import utcnow

HTML = "<!DOCTYPE html><html><head><title>shop</title></head><body><h1>Welcome</h1></body></html>"
CLIENT_IP = "203.0.113.7"

GateFactory = Callable[..., Awaitable[tuple[Starlette, Gate]]]


class FakeServer:
    """Stands in for the TOKIWA server: serves ``GatePolicy`` and records ingest batches."""

    def __init__(self) -> None:
        self.policy: GatePolicy | None = None
        self.raw_policy: Any = None  # when set, served verbatim (malformed payload tests)
        self.policy_status = 200
        self.ingest_status = 200
        self.down = False
        self.batches: list[dict[str, Any]] = []
        self.policy_requests = 0
        self.tokens: list[str | None] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("connection refused", request=request)
        self.tokens.append(request.headers.get("x-tokiwa-token"))
        if request.url.path == "/api/v1/gate/policy":
            self.policy_requests += 1
            if self.raw_policy is not None:
                return httpx.Response(200, json=self.raw_policy)
            if self.policy is None or self.policy_status != 200:
                return httpx.Response(self.policy_status if self.policy_status != 200 else 404)
            return httpx.Response(200, json=self.policy.model_dump(mode="json"))
        if request.url.path == "/api/v1/ingest/events":
            if self.ingest_status != 200:
                return httpx.Response(self.ingest_status, json={"detail": "nope"})
            body = json.loads(request.content)
            self.batches.append(body)
            return httpx.Response(200, json={"accepted": len(body["events"]), "alerts": 0, "alert_ids": []})
        return httpx.Response(404)

    @property
    def events(self) -> list[dict[str, Any]]:
        return [e for b in self.batches for e in b["events"]]

    def set_policy(self, version: str = "v1", **kwargs: Any) -> GatePolicy:
        self.policy = GatePolicy(version=version, generated_at=utcnow(), **kwargs)
        return self.policy


class Upstream:
    """The protected web app. Records every request it receives (to prove decoys/blocks never reach it)."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.app = Starlette(
            routes=[
                Route("/html", self.html),
                Route("/html-sjis", self.html_sjis),
                Route("/gzip-html", self.gzip_html),
                Route("/deflate-html", self.deflate_html),
                Route("/br-html", self.br_html),
                Route("/fragment", self.fragment),
                Route("/cookies", self.cookies),
                Route("/hop", self.hop),
                Route("/binary", self.binary),
                Route("/status/{code:int}", self.status),
                Route(
                    "/{path:path}",
                    self.echo,
                    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                ),
            ]
        )

    async def _record(self, request: Request) -> dict[str, Any]:
        body = await request.body()
        rec = {
            "method": request.method,
            "path": request.url.path,
            "query": request.url.query,
            "headers": [(k, v) for k, v in request.headers.items()],
            "body": body,
        }
        self.requests.append(rec)
        return rec

    def header(self, index: int, name: str) -> list[str]:
        return [v for k, v in self.requests[index]["headers"] if k == name]

    async def echo(self, request: Request) -> Response:
        rec = await self._record(request)
        return JSONResponse(
            {
                "method": rec["method"],
                "path": rec["path"],
                "query": rec["query"],
                "body": rec["body"].decode("utf-8", "replace"),
            }
        )

    async def html(self, request: Request) -> Response:
        await self._record(request)
        return Response(HTML, media_type="text/html", headers={"etag": '"abc"'})

    async def html_sjis(self, request: Request) -> Response:
        await self._record(request)
        body = "<html><body>こんにちは</body></html>".encode("shift_jis")
        return Response(body, headers={"content-type": "text/html; charset=Shift_JIS"})

    async def gzip_html(self, request: Request) -> Response:
        await self._record(request)
        return Response(
            gzip.compress(HTML.encode()), headers={"content-type": "text/html", "content-encoding": "gzip"}
        )

    async def deflate_html(self, request: Request) -> Response:
        await self._record(request)
        return Response(
            zlib.compress(HTML.encode()),
            headers={"content-type": "text/html; charset=utf-8", "content-encoding": "deflate"},
        )

    async def br_html(self, request: Request) -> Response:
        await self._record(request)
        return Response(
            b"\x1b\x00opaque-brotli", headers={"content-type": "text/html", "content-encoding": "br"}
        )

    async def fragment(self, request: Request) -> Response:
        await self._record(request)
        return Response("<div>partial</div>", media_type="text/html")

    async def cookies(self, request: Request) -> Response:
        await self._record(request)
        resp = Response("ok", media_type="text/plain")
        resp.raw_headers.append((b"set-cookie", b"a=1; Path=/"))
        resp.raw_headers.append((b"set-cookie", b"b=2; Path=/"))
        return resp

    async def hop(self, request: Request) -> Response:
        await self._record(request)
        resp = Response("hop", media_type="text/plain")
        resp.raw_headers.extend(
            [
                (b"connection", b"x-internal-hop"),
                (b"x-internal-hop", b"secret"),
                (b"keep-alive", b"timeout=5"),
                (b"x-app", b"kept"),
            ]
        )
        return resp

    async def binary(self, request: Request) -> Response:
        await self._record(request)
        return Response(b"\x89PNG\r\n\x1a\n" + bytes(range(256)), media_type="image/png")

    async def status(self, request: Request) -> Response:
        await self._record(request)
        return Response("status", status_code=int(request.path_params["code"]), media_type="text/plain")


@dataclass
class FakeTime:
    """Monotonic clock + sleep that advances it instantly (tarpit / rate-limit tests without waiting)."""

    now: float = 1000.0
    sleeps: list[float] = field(default_factory=list)

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def advance(self, seconds: float) -> None:
        self.now += seconds


def client_for(app: Starlette, ip: str = CLIENT_IP, port: int = 40000) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=(ip, port)), base_url="http://shop.example"
    )


async def events_of(gate: Gate, fake_server: FakeServer) -> list[dict[str, Any]]:
    await gate.shipper.flush()
    return fake_server.events


async def asgi_call(
    app: Any, scope: dict[str, Any], messages: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """Invoke an ASGI app with a hand-built scope (raw paths, websocket scopes) and collect sent messages."""
    inbox = list(messages or [{"type": "http.request", "body": b"", "more_body": False}])
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        if inbox:
            return inbox.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(scope, receive, send)
    return sent


def http_scope(path: str, raw_path: bytes, *, ip: str = CLIENT_IP, **extra: Any) -> dict[str, Any]:
    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": raw_path,
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"shop.example"), (b"user-agent", b"raw-test")],
        "client": (ip, 40000),
        "server": ("10.0.0.5", 8080),
    }
    scope.update(extra)
    return scope
