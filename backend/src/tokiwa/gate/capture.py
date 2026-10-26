"""Turn one proxied request/response exchange into normalized, redacted :class:`Event` objects.

The gate is the only sensor that sees request *bodies* (access logs do not), which is what makes payload-level
detection (SQLi in JSON, prompt injection in chat APIs, credential stuffing) possible. Because bodies and
headers are attacker-controlled *and* may contain real user secrets, everything goes through
:mod:`tokiwa.llm.redact` here, before the event ever leaves the gate process.
"""

from __future__ import annotations

import codecs
import time
from dataclasses import dataclass, field
from datetime import datetime

from tokiwa.config import RedactionSettings
from tokiwa.gate.netmatch import parse_ip
from tokiwa.llm.redact import redact_headers, redact_text
from tokiwa.schemas.events import DeceptionInfo, Endpoint, Event, EventKind, HttpInfo
from tokiwa.schemas.response import DecoyRoute
from tokiwa.util import utcnow

DATASET_HTTP = "gate.http"
DATASET_DECEPTION = "gate.deception"
MAX_CAPTURED_HEADERS = 64

_TEXT_MIME_EXACT = frozenset(
    {
        "application/json",
        "application/x-www-form-urlencoded",
        "application/xml",
        "application/javascript",
        "application/ecmascript",
        "application/graphql",
        "application/x-ndjson",
        "application/jsonl",
        "application/soap+xml",
        "application/x-yaml",
        "application/yaml",
        "application/csp-report",
    }
)
_BINARY_MIME_PREFIXES = ("image/", "audio/", "video/", "font/")
_BINARY_MIME_EXACT = frozenset(
    {
        "application/octet-stream",
        "application/pdf",
        "application/zip",
        "application/gzip",
        "application/x-protobuf",
        "application/protobuf",
        "application/grpc",
        "application/wasm",
        "application/msgpack",
        "application/x-msgpack",
        "application/cbor",
    }
)


def mime_type(content_type: str | None) -> str:
    if not content_type:
        return ""
    return content_type.split(";", 1)[0].strip().lower()


def classify_content_type(content_type: str | None) -> bool | None:
    """True = text, False = binary, None = unknown (sniff the bytes)."""
    mime = mime_type(content_type)
    if not mime:
        return None
    if mime.startswith("text/") or mime in _TEXT_MIME_EXACT:
        return True
    if mime.endswith("+json") or mime.endswith("+xml"):
        return True
    if mime.startswith(_BINARY_MIME_PREFIXES) or mime in _BINARY_MIME_EXACT:
        return False
    return None  # multipart/form-data, vendor types, ...: decide by content


def looks_textual(sample: bytes) -> bool:
    """Heuristic for unknown / multipart bodies: valid-ish UTF-8, no NULs, mostly printable."""
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    text = codecs.getincrementaldecoder("utf-8")(errors="replace").decode(sample, final=False)
    if not text:
        return False
    bad = sum(1 for ch in text if ch == "�" or (ord(ch) < 32 and ch not in "\t\r\n\f"))
    return bad / len(text) <= 0.05


def decode_prefix(prefix: bytes, truncated: bool) -> str:
    """UTF-8 with replacement; a multibyte char cut by the capture limit is dropped instead of becoming U+FFFD."""
    return codecs.getincrementaldecoder("utf-8")(errors="replace").decode(prefix, final=not truncated)


class BodyCapture:
    """Keeps the first ``limit`` bytes of a streamed body and counts the total size."""

    __slots__ = ("_buf", "complete", "limit", "size")

    def __init__(self, limit: int) -> None:
        self.limit = max(0, limit)
        self._buf = bytearray()
        self.size = 0
        self.complete = False  # True once the whole body went through feed()

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.size += len(chunk)
        room = self.limit - len(self._buf)
        if room > 0:
            self._buf += chunk[:room]

    @property
    def prefix(self) -> bytes:
        return bytes(self._buf)

    @property
    def truncated(self) -> bool:
        return self.size > len(self._buf) or not self.complete

    def text(self, content_type: str | None) -> str | None:
        """Decoded prefix for textual bodies; None for binary or empty bodies (size is still recorded)."""
        if not self._buf:
            return None
        kind = classify_content_type(content_type)
        if kind is False or (kind is None and not looks_textual(bytes(self._buf[:512]))):
            return None
        return decode_prefix(bytes(self._buf), self.truncated)


def capture_headers(raw: list[tuple[bytes, bytes]]) -> tuple[dict[str, str], list[str]]:
    """Lower-cased header map (duplicates joined with ", ") + arrival order (incl. repeats) for fingerprinting."""
    headers: dict[str, str] = {}
    order: list[str] = []
    for name_b, value_b in raw[:MAX_CAPTURED_HEADERS]:
        name = name_b.decode("latin-1").lower()
        value = value_b.decode("latin-1")
        order.append(name)
        if name in headers:
            sep = "; " if name == "cookie" else ", "
            headers[name] = headers[name] + sep + value
        else:
            headers[name] = value
    return headers, order


@dataclass(slots=True)
class Exchange:
    """Mutable record of one request as it flows through the gate (raw values; redacted at build time)."""

    method: str
    scheme: str
    path: str
    query: str
    raw_headers: list[tuple[bytes, bytes]]
    client_ip: str | None  # effective client (right-most trusted X-Forwarded-For entry, else the TCP peer)
    client_port: int | None
    peer_ip: str | None = None  # TCP peer as seen by the gate
    server_ip: str | None = None
    server_port: int | None = None
    http_version: str | None = None
    body: BodyCapture = field(default_factory=lambda: BodyCapture(0))
    started_at: datetime = field(default_factory=utcnow)
    t0: float = field(default_factory=time.perf_counter)
    status: int | None = None
    response_size: int = 0
    response_content_type: str | None = None
    duration_ms: float | None = None
    tags: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    decoy: DecoyRoute | None = None

    def header(self, name: str) -> str | None:
        key = name.lower().encode("latin-1")
        for k, v in self.raw_headers:
            if k.lower() == key:
                return v.decode("latin-1")
        return None

    def tag(self, value: str) -> None:
        if value not in self.tags:
            self.tags.append(value)

    def finish(self) -> None:
        if self.duration_ms is None:
            self.duration_ms = round((time.perf_counter() - self.t0) * 1000.0, 3)


def _endpoint(host: str | None, port: int | None) -> Endpoint:
    """ASGI ``client``/``server`` hosts are usually IPs, but may be names (unix sockets, test transports)."""
    if host is None:
        return Endpoint(port=port)
    ip = parse_ip(host)
    if ip is None:
        return Endpoint(hostname=host, port=port)
    return Endpoint(ip=str(ip), port=port)


class EventBuilder:
    """Builds redacted events. Holds the redaction config so the hot path does no settings lookups."""

    def __init__(self, *, sensor_id: str, capture_body_bytes: int, redaction: RedactionSettings) -> None:
        self.sensor_id = sensor_id
        self.capture_body_bytes = capture_body_bytes
        self.redaction = redaction
        # Bodies may legitimately be longer than the generic per-field cap; let the capture limit govern.
        self.body_redaction = redaction.model_copy(
            update={"max_field_chars": max(redaction.max_field_chars or 0, capture_body_bytes)}
        )

    def http_info(self, ex: Exchange) -> HttpInfo:
        cfg = self.redaction
        headers, order = capture_headers(ex.raw_headers)
        content_type = headers.get("content-type")
        body_size = ex.body.size
        if not ex.body.complete:
            declared = headers.get("content-length", "")
            if declared.isdigit():
                body_size = max(body_size, int(declared))
        body_text = ex.body.text(content_type)
        return HttpInfo(
            method=ex.method,
            scheme=ex.scheme,
            host=redact_text(headers.get("host"), cfg),
            path=redact_text(ex.path, cfg),
            query=redact_text(ex.query, cfg) if ex.query else None,
            headers=redact_headers(headers, cfg),
            header_order=order,
            user_agent=redact_text(headers.get("user-agent"), cfg),
            referrer=redact_text(headers.get("referer"), cfg),
            content_type=content_type,
            request_body_size=body_size,
            request_body=redact_text(body_text, self.body_redaction) if body_text else None,
            status=ex.status,
            response_size=ex.response_size,
            response_content_type=ex.response_content_type,
            duration_ms=ex.duration_ms,
            http_version=ex.http_version,
        )

    def build(self, ex: Exchange) -> list[Event]:
        """One HTTP event per exchange, plus a DECEPTION event when a Mirage decoy was served."""
        ex.finish()
        http = self.http_info(ex)
        source = _endpoint(ex.client_ip, ex.client_port)
        destination = _endpoint(ex.server_ip, ex.server_port)
        message = f"{ex.method} {http.path} -> {ex.status}"
        events = [
            Event(
                timestamp=ex.started_at,
                kind=EventKind.HTTP,
                dataset=DATASET_HTTP,
                sensor_id=self.sensor_id,
                message=message,
                source=source,
                destination=destination,
                http=http,
                tags=list(ex.tags),
                labels=dict(ex.labels),
            )
        ]
        if ex.decoy is not None:
            events.append(
                Event(
                    timestamp=ex.started_at,
                    kind=EventKind.DECEPTION,
                    dataset=DATASET_DECEPTION,
                    sensor_id=self.sensor_id,
                    message=f"decoy served: {ex.decoy.kind} {ex.decoy.path}",
                    source=source,
                    destination=destination,
                    http=http,
                    deception=DeceptionInfo(
                        asset_id=ex.decoy.asset_id,
                        asset_kind=ex.decoy.kind,
                        detail=f"gate served decoy route {ex.decoy.path!r} (status {ex.decoy.status_code})",
                    ),
                    tags=list(ex.tags),
                    labels=dict(ex.labels),
                )
            )
        return events
