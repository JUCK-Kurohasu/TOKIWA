"""L05 engine-level harness: build HTTP events (direct or via the Gate's capture+redaction) and run all detectors."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from urllib.parse import unquote

MYDIR = Path(__file__).resolve().parent
os.environ.update(
    {
        "TOKIWA_ENV": "test",
        "TOKIWA_CONFIG": str(MYDIR / "none.yaml"),
        "TOKIWA_SERVER__DATA_DIR": str(MYDIR / "data"),
        "TOKIWA_DATABASE__URL": f"sqlite+aiosqlite:///{MYDIR / 'data' / 'h.db'}",
        "TOKIWA_LLM__PROVIDER": "mock",
        "TOKIWA_DETECTION__SIGMA_RULE_DIRS": '["/home/user/TOKIWA/rules/sigma"]',
    }
)
(MYDIR / "data").mkdir(exist_ok=True)

import logging  # noqa: E402

logging.disable(logging.WARNING)

from tokiwa.config import get_settings  # noqa: E402
from tokiwa.detect.context import DetectionContext  # noqa: E402
from tokiwa.detect.engine import DetectionEngine  # noqa: E402
from tokiwa.gate.capture import BodyCapture, EventBuilder, Exchange  # noqa: E402
from tokiwa.schemas.events import Endpoint, Event, EventKind, HttpInfo  # noqa: E402

S = get_settings()
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
ENGINE = DetectionEngine(S)
ENGINE.load()
BUILDER = EventBuilder(sensor_id="gate-1", capture_body_bytes=S.gate.capture_body_bytes, redaction=S.llm.redaction)


def _hdrs(headers: dict[str, str] | None, ct: str | None) -> dict[str, str]:
    h = {"host": "app.lab", "user-agent": UA}
    if ct:
        h["content-type"] = ct
    for k, v in (headers or {}).items():
        h[k.lower()] = v
    return h


def direct_event(target: str, *, method: str = "GET", body: str | bytes | None = None, ct: str | None = None,
                 headers: dict[str, str] | None = None, status: int = 200, ip: str = "203.0.113.10", ts=None) -> Event:
    """Event as a log shipper / WAF integration would send it (raw request target, body as text)."""
    path, _, q = target.partition("?")
    h = _hdrs(headers, ct)
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    kw = {}
    if ts is not None:
        kw["timestamp"] = ts
    return Event(kind=EventKind.HTTP, dataset="test.http", source=Endpoint(ip=ip, port=50000),
                 destination=Endpoint(ip="10.0.0.5", port=8080),
                 http=HttpInfo(method=method, scheme="http", host="app.lab", path=path, query=q or None,
                               user_agent=h.get("user-agent"), referrer=h.get("referer"), content_type=h.get("content-type"),
                               status=status, request_body=body, request_body_size=len(body or ""), headers=h), **kw)


def gate_event(target: str, *, method: str = "GET", body: str | bytes | None = None, ct: str | None = None,
               headers: dict[str, str] | None = None, status: int = 200, ip: str = "203.0.113.10",
               extra_headers: list[tuple[str, str]] | None = None) -> Event:
    """Event as the TOKIWA Gate would ship it: uvicorn-decoded scope['path'], raw query, 4 KiB body capture,
    redaction (gate/capture.py EventBuilder)."""
    raw_path, _, q = target.partition("?")
    h = _hdrs(headers, ct)
    raw_headers = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in h.items()]
    for k, v in extra_headers or []:
        raw_headers.append((k.encode("latin-1"), v.encode("latin-1")))
    ex = Exchange(method=method, scheme="http", path=unquote(raw_path), query=q, raw_headers=raw_headers,
                  client_ip=ip, client_port=50000, peer_ip=ip, server_ip="10.0.0.5", server_port=8080,
                  http_version="1.1", body=BodyCapture(S.gate.capture_body_bytes))
    if body is not None:
        b = body.encode("utf-8") if isinstance(body, str) else body
        for i in range(0, len(b), 1024):
            ex.body.feed(b[i : i + 1024])
    ex.body.complete = True
    ex.status = status
    ex.response_content_type = "text/html"
    return BUILDER.build(ex)[0]


async def _run(events: list[Event], ctx: DetectionContext | None = None) -> list[list[str]]:
    eng = ENGINE
    eng.ctx = ctx or DetectionContext(S)
    out = []
    for ev in events:
        drafts = await eng.run([ev])
        out.append(sorted({d.rule_id for d in drafts}))
    return out


def run(events: list[Event], ctx: DetectionContext | None = None) -> list[list[str]]:
    return asyncio.run(_run(events, ctx))


def run_drafts(events: list[Event], ctx: DetectionContext | None = None):
    async def go():
        ENGINE.ctx = ctx or DetectionContext(S)
        res = []
        for ev in events:
            res.append(await ENGINE.run([ev]))
        return res

    return asyncio.run(go())


def web(ids: list[str]) -> list[str]:
    return [i for i in ids if i.startswith("web.") or i.startswith("sigma:")]
