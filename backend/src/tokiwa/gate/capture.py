"""Turn one proxied request/response exchange into normalized, redacted :class:`Event` objects.

The gate is the only sensor that sees request *bodies* (access logs do not), which is what makes payload-level
detection (SQLi in JSON, prompt injection in chat APIs, credential stuffing) possible. Because bodies and
headers are attacker-controlled *and* may contain real user secrets, everything goes through
:mod:`tokiwa.llm.redact` here, before the event ever leaves the gate process.
"""

from __future__ import annotations

import codecs
import time
import zlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from tokiwa import payload_shapes
from tokiwa.config import RedactionSettings
from tokiwa.gate.netmatch import parse_ip
from tokiwa.llm.redact import redact_headers, redact_text
from tokiwa.schemas.events import DeceptionInfo, Endpoint, Event, EventKind, HttpInfo
from tokiwa.schemas.response import DecoyRoute
from tokiwa.util import utcnow

DATASET_HTTP = "gate.http"
DATASET_DECEPTION = "gate.deception"
# Distinct header names kept per event. The web detectors inspect the first 64 entries of ``http.headers``
# (``detect.web_common.MAX_HEADERS``), so a larger map would hide its tail from them anyway.
MAX_CAPTURED_HEADERS = 64
# Repeats of one name recorded in ``header_order`` (enough to show "sent twice" without letting one repeated
# header fill the list).
MAX_ORDER_REPEATS = 2
# Repeated header lines are joined into one value; the join stops growing here (one header sent 10,000 times).
MAX_JOINED_HEADER_CHARS = 8192

# Captured wherever they appear in the request (audit #140): before, only the first 64 header lines were kept,
# so 64 dummy headers in front made User-Agent, Referer, Sec-Fetch-* ... vanish from the event while the
# upstream still received them. These are the headers detectors, deception provenance (``Sec-Fetch-*``,
# Origin, Referer), the respond auto-approval guard, client fingerprints and AI attribution read, plus every
# header the Gate strips or rewrites before forwarding (spoofing attempts stay visible). Kept well below
# MAX_CAPTURED_HEADERS so the arrival-order tail still has room.
PRIORITY_HEADERS = frozenset(
    {
        # identity of the client / request framing
        "host",
        "user-agent",
        "referer",
        "origin",
        "cookie",
        "authorization",
        "proxy-authorization",
        "content-type",
        "content-length",
        "content-encoding",
        "transfer-encoding",
        "connection",
        # fingerprints (aidetect STABLE_FINGERPRINT_HEADERS) and header anomalies
        "accept",
        "accept-language",
        "accept-encoding",
        "dnt",
        "sec-gpc",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "x-requested-with",
        # fetch metadata: deception provenance / respond auto-approval guard (audit #133)
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "sec-fetch-user",
        "sec-purpose",
        "purpose",
        # client address / scheme claims (stripped or rewritten by gate.proxy, audit #138)
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
        "x-forwarded-prefix",
        "x-forwarded-server",
        "x-forwarded-scheme",
        "x-forwarded-ssl",
        "front-end-https",
        "x-url-scheme",
        "x-original-forwarded-for",
        "x-real-ip",
        "true-client-ip",
        "cf-connecting-ip",
        "x-client-ip",
        "x-cluster-client-ip",
        "fastly-client-ip",
        "x-originating-ip",
        "client-ip",
        # routing / method overrides (stripped by gate.proxy, audit #147)
        "x-original-url",
        "x-rewrite-url",
        "x-override-url",
        "x-http-method-override",
        "x-http-method",
        "x-method-override",
        # payload carriers the web detectors inspect by name (detect.web_common.INJECTABLE_HEADERS)
        "x-api-version",
        "x-wap-profile",
    }
)
# Header fields that are not lists (RFC 9110 §5.3): a request carrying one of them twice is malformed, and the
# upstream may read either copy (Host / Content-Length disagreement is the classic smuggling and routing trick).
SINGLETON_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "content-type",
        "user-agent",
        "referer",
        "origin",
        "authorization",
        "x-forwarded-host",
        "x-real-ip",
        "true-client-ip",
        "cf-connecting-ip",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "x-original-url",
        "x-rewrite-url",
    }
)

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


def body_text(data: bytes, truncated: bool, content_type: str | None) -> str | None:
    """Decoded text of a (prefix of a) textual body; None for binary or empty bodies."""
    if not data:
        return None
    kind = classify_content_type(content_type)
    if kind is False or (kind is None and not looks_textual(data[:512])):
        return None
    return decode_prefix(data, truncated)


# Request Content-Encoding the Gate undoes before capture (audit #141). Upstreams such as Express body-parser or
# ASP.NET Core's request decompression inflate these, so a compressed SQLi reached the app but not the detectors.
_REQUEST_CODINGS: dict[str, tuple[int, ...]] = {
    "gzip": (16 + zlib.MAX_WBITS,),
    "x-gzip": (16 + zlib.MAX_WBITS,),
    "deflate": (zlib.MAX_WBITS, -zlib.MAX_WBITS),  # zlib-wrapped (correct) or raw (common in the wild)
}
MAX_REQUEST_CODINGS = 2  # "gzip, gzip" is decoded; deeper stacks are reported as unknown


@dataclass(slots=True)
class DecodedBody:
    data: bytes
    truncated: bool
    codings: tuple[str, ...] = ()  # the codings listed in Content-Encoding (minus identity)
    # identity | decoded | unknown (unsupported coding) | failed (corrupt stream) | empty (nothing captured)
    status: str = "identity"


def _inflate(data: bytes, wbits: int, limit: int) -> tuple[bytes, bool] | None:
    """Inflate at most ``limit`` output bytes. Returns (output, incomplete) or None when ``data`` is not this format.

    Concatenated gzip members are one valid gzip stream (and inflated as such by upstreams), so every member is
    read: a harmless first member must not hide the payload in the second.
    """
    out = bytearray()
    rest = data
    while True:
        d = zlib.decompressobj(wbits)
        try:
            out += d.decompress(rest, limit - len(out))
        except zlib.error:
            return (bytes(out), True) if out else None
        if len(out) >= limit and (d.unconsumed_tail or not d.eof):
            return bytes(out[:limit]), True  # output limit reached: the decompression-bomb guard
        if not d.eof:
            return bytes(out), True  # the captured compressed prefix ends mid-stream
        rest = d.unused_data
        if not rest or wbits != 16 + zlib.MAX_WBITS or len(out) >= limit:
            return bytes(out), bool(rest)


def decode_request_body(
    prefix: bytes, content_encoding: str | None, limit: int, truncated: bool
) -> DecodedBody:
    """Undo the request's ``Content-Encoding`` on the captured prefix, producing at most ``limit`` bytes.

    Only the prefix is inflated and the output is capped at the capture limit, so neither a decompression bomb
    nor a large compressed body costs more than ``capture_body_bytes`` of work and memory.
    """
    codings = tuple(
        c for c in (p.strip().lower() for p in (content_encoding or "").split(",")) if c and c != "identity"
    )
    if not codings:
        return DecodedBody(prefix, truncated)
    if not prefix or limit <= 0:  # nothing captured (and limit 0 would mean "unlimited" to zlib)
        return DecodedBody(prefix, truncated, codings, "empty")
    if len(codings) > MAX_REQUEST_CODINGS or any(c not in _REQUEST_CODINGS for c in codings):
        return DecodedBody(prefix, truncated, codings, "unknown")
    data = prefix
    for coding in reversed(codings):  # the last listed coding was applied last
        result = None
        for wbits in _REQUEST_CODINGS[coding]:
            result = _inflate(data, wbits, limit)
            if result is not None:
                break
        if result is None:
            return DecodedBody(prefix, truncated, codings, "failed")
        data, incomplete = result
        truncated = truncated or incomplete
    return DecodedBody(data, truncated, codings, "decoded")


class BodyCapture:
    """Keeps the first ``limit`` bytes of a streamed body and counts the total size.

    Bytes past the kept prefix are never stored, but up to ``payload_shapes.MAX_SCAN_CHARS`` of them are classified
    as they stream by (ADR-0007 C, audit #21): padding a payload past the capture limit no longer hides it entirely,
    the event says which attack shapes were beyond the limit (classes only).
    """

    __slots__ = ("_buf", "_scan_tail", "_scanned", "beyond_classes", "complete", "limit", "size")

    def __init__(self, limit: int) -> None:
        self.limit = max(0, limit)
        self._buf = bytearray()
        self.size = 0
        self.complete = False  # True once the whole body went through feed()
        self.beyond_classes: set[str] = set()
        self._scanned = 0
        self._scan_tail = ""  # end of the previous chunk, so a payload split across chunks is still seen

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.size += len(chunk)
        room = self.limit - len(self._buf)
        if room > 0:
            self._buf += chunk[:room]
            rest = chunk[room:]
        else:
            rest = chunk
        if rest and self._scanned < payload_shapes.MAX_SCAN_CHARS:
            part = rest[: payload_shapes.MAX_SCAN_CHARS - self._scanned].decode("utf-8", "replace")
            self._scanned += len(part)
            text = self._scan_tail + part
            self.beyond_classes |= payload_shapes.classify(text)
            self._scan_tail = text[-256:]

    @property
    def prefix(self) -> bytes:
        return bytes(self._buf)

    @property
    def truncated(self) -> bool:
        return self.size > len(self._buf) or not self.complete

    def text(self, content_type: str | None) -> str | None:
        """Decoded prefix for textual bodies; None for binary or empty bodies (size is still recorded)."""
        return body_text(bytes(self._buf), self.truncated, content_type)


@dataclass(slots=True)
class HeaderCapture:
    """What :func:`capture_headers` kept of a request's header block, and what it had to leave out."""

    headers: dict[str, str]  # lower-cased name -> value (repeats joined), in arrival order
    order: list[str]  # arrival order of the kept names, each repeated at most MAX_ORDER_REPEATS times
    total: int  # header lines received
    dropped: int = 0  # header lines not kept (names beyond MAX_CAPTURED_HEADERS)
    clipped: int = 0  # names whose joined repeats were cut at MAX_JOINED_HEADER_CHARS
    duplicated: list[str] = field(default_factory=list)  # SINGLETON_HEADERS that arrived more than once

    @property
    def truncated(self) -> bool:
        return self.dropped > 0 or self.clipped > 0


def capture_headers(
    raw: list[tuple[bytes, bytes]],
    *,
    priority: frozenset[str] = PRIORITY_HEADERS,
    limit: int = MAX_CAPTURED_HEADERS,
) -> HeaderCapture:
    """Lower-cased header map + arrival order for fingerprinting, bounded to ``limit`` distinct names.

    ``priority`` names present in the request are always kept, wherever they are; the remaining room goes to
    the other names in arrival order. Every line is still counted (``total`` / ``dropped``) so a truncated
    capture is visible on the event instead of looking like a request without those headers.
    """
    lines = [(k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in raw]
    reserved = {name for name, _ in lines if name in priority}
    room = max(0, limit - len(reserved))
    cap = HeaderCapture(headers={}, order=[], total=len(lines))
    headers = cap.headers
    seen: dict[str, int] = {}
    clipped: set[str] = set()
    others = 0
    for name, value in lines:
        if name in headers:
            current = headers[name]
            if len(current) >= MAX_JOINED_HEADER_CHARS:
                clipped.add(name)
            else:
                joined = current + ("; " if name == "cookie" else ", ") + value
                if len(joined) > MAX_JOINED_HEADER_CHARS:
                    clipped.add(name)
                    joined = joined[:MAX_JOINED_HEADER_CHARS]
                headers[name] = joined
            if name in SINGLETON_HEADERS and name not in cap.duplicated:
                cap.duplicated.append(name)
        elif name in reserved or others < room:
            if name not in reserved:
                others += 1
            headers[name] = value
        else:
            cap.dropped += 1
            continue
        seen[name] = seen.get(name, 0) + 1
        if seen[name] <= MAX_ORDER_REPEATS:
            cap.order.append(name)
    cap.clipped = len(clipped)
    return cap


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
    # The TCP peer is a trusted proxy, so its X-Forwarded-* values were used (#22). Decides what goes upstream too.
    forwarded_trusted: bool = False

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

    def __init__(
        self,
        *,
        sensor_id: str,
        capture_body_bytes: int,
        redaction: RedactionSettings,
        priority_headers: Iterable[str] = (),
    ) -> None:
        self.sensor_id = sensor_id
        self.capture_body_bytes = capture_body_bytes
        self.redaction = redaction
        # Bodies may legitimately be longer than the generic per-field cap; let the capture limit govern.
        self.body_redaction = redaction.model_copy(
            update={"max_field_chars": max(redaction.max_field_chars or 0, capture_body_bytes)}
        )
        # e.g. the deception canary header: following the AI-canary instruction must stay visible (#140)
        self.priority_headers = PRIORITY_HEADERS | {h.strip().lower() for h in priority_headers if h.strip()}

    def capture(self, ex: Exchange) -> HeaderCapture:
        """Capture the headers and mark the exchange when the capture is incomplete or the block is malformed."""
        cap = capture_headers(ex.raw_headers, priority=self.priority_headers)
        if cap.truncated:
            ex.tag("gate:headers_truncated")
            ex.labels["gate.header_count"] = str(cap.total)
            if cap.dropped:
                ex.labels["gate.headers_dropped"] = str(cap.dropped)
            if cap.clipped:
                ex.labels["gate.headers_clipped"] = str(cap.clipped)
        if cap.duplicated:
            ex.tag("gate:duplicate_header")
            ex.labels["gate.duplicate_headers"] = ",".join(cap.duplicated)
        return cap

    def decode_body(self, ex: Exchange, cap: HeaderCapture) -> DecodedBody:
        """Undo the request Content-Encoding on the captured prefix and say on the event that it was encoded."""
        body = decode_request_body(
            ex.body.prefix, cap.headers.get("content-encoding"), self.capture_body_bytes, ex.body.truncated
        )
        if body.status in ("identity", "empty"):
            return body
        known = [c for c in body.codings if c in _REQUEST_CODINGS]
        ex.labels["gate.request_encoding"] = ",".join(known) if len(known) == len(body.codings) else "unknown"
        if body.status == "decoded":
            # request_body is the inflated text; request_body_size stays the wire size
            ex.tag("gate:req_encoded")
            ex.labels["gate.request_body_decoded_bytes"] = str(len(body.data))
        elif body.status == "unknown":
            ex.tag("gate:req_encoding_unknown")  # br / zstd / compress / deeper stacks: body not inspectable
        else:
            ex.tag("gate:req_decode_failed")  # declared gzip/deflate but not a valid stream
        return body

    def http_info(
        self, ex: Exchange, cap: HeaderCapture | None = None, body: DecodedBody | None = None
    ) -> HttpInfo:
        cfg = self.redaction
        cap = cap or capture_headers(ex.raw_headers, priority=self.priority_headers)
        headers, order = cap.headers, cap.order
        content_type = headers.get("content-type")
        body_size = ex.body.size
        if not ex.body.complete:
            declared = headers.get("content-length", "")
            if declared.isdigit():
                body_size = max(body_size, int(declared))
        if body is None:
            body = decode_request_body(
                ex.body.prefix, headers.get("content-encoding"), self.capture_body_bytes, ex.body.truncated
            )
        # An unsupported coding stays opaque bytes: sniffing them could only produce garbage "text".
        text = body_text(body.data, body.truncated, content_type) if body.status != "unknown" else None
        shown_headers = redact_headers(headers, cfg)
        shown_body = redact_text(text, self.body_redaction) if text else None
        shown_path = redact_text(ex.path, cfg)
        shown_query = redact_text(ex.query, cfg) if ex.query else None
        self._mark_hidden(ex, shown_path, shown_query, shown_headers, text, shown_body)
        return HttpInfo(
            method=ex.method,
            scheme=ex.scheme,
            host=redact_text(headers.get("host"), cfg),
            path=shown_path,
            query=shown_query,
            headers=shown_headers,
            header_order=order,
            user_agent=redact_text(headers.get("user-agent"), cfg),
            referrer=redact_text(headers.get("referer"), cfg),
            content_type=content_type,
            request_body_size=body_size,
            request_body=shown_body,
            status=ex.status,
            response_size=ex.response_size,
            response_content_type=ex.response_content_type,
            duration_ms=ex.duration_ms,
            http_version=ex.http_version,
        )

    @staticmethod
    def _mark_hidden(
        ex: Exchange,
        shown_path: str | None,
        shown_query: str | None,
        shown_headers: dict[str, str],
        body: str | None,
        shown_body: str | None,
    ) -> None:
        """Label the attack shapes that masking or cutting hid from the server (ADR-0007 C; classes only).

        Each value is compared with what the event will carry; only a value that changed is scanned, and only
        classes absent from the shown value count, so a payload the detectors can still read is not reported twice.
        Raw header values are taken from the request itself: a Cookie / X-Api-Key value is replaced wholesale,
        and a header past the captured set is not in the event at all.
        """
        hidden: dict[str, set[str]] = {}

        def note(where: str, classes: set[str]) -> None:
            if classes:
                hidden.setdefault(where, set()).update(classes)

        note("path", payload_shapes.hidden_classes(ex.path, shown_path))
        note("query", payload_shapes.hidden_classes(ex.query or None, shown_query))
        joined: dict[
            str, list[str]
        ] = {}  # repeated lines are joined in the capture: compare the joined value
        for k, v in ex.raw_headers:
            joined.setdefault(k.decode("latin-1").lower(), []).append(v.decode("latin-1"))
        for name, values in joined.items():
            raw_value = ", ".join(values)
            note(f"header:{name[:48]}", payload_shapes.hidden_classes(raw_value, shown_headers.get(name)))
        note("body", payload_shapes.hidden_classes(body, shown_body))
        note("body_beyond", set(ex.body.beyond_classes))
        label = payload_shapes.format_label(hidden)
        if label:
            ex.tag("gate:hidden_signals")
            ex.labels[payload_shapes.HIDDEN_SIGNALS_LABEL] = label

    def build(self, ex: Exchange) -> list[Event]:
        """One HTTP event per exchange, plus a DECEPTION event when a Mirage decoy was served."""
        ex.finish()
        cap = self.capture(ex)
        http = self.http_info(ex, cap, self.decode_body(ex, cap))
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
