"""Normalized telemetry event schema (ECS-inspired, intentionally smaller).

Every sensor / adapter converts its native format into :class:`Event`. Field names follow ECS where a
counterpart exists (``source.ip``, ``http.request.method`` -> ``http.method`` ...), flattened one level to keep
LLM prompts and DB columns simple. See docs/decisions/ADR-0003-event-schema.md.

All string fields that can be controlled by a remote party (URL, headers, UA, body) are UNTRUSTED. Never feed
them to the LLM without :mod:`tokiwa.llm.redact` + the untrusted-data envelope in :mod:`tokiwa.llm.prompting`.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, Field, model_validator

from tokiwa.util import new_id, utcnow

# --- size caps (audit #57) -------------------------------------------------------------------------------
# Every string in an event (including header values, label values and list items) is cut to this many
# characters. Oversized values are *truncated, not rejected*, so one absurd field never costs the rest of the
# event (or the batch) its detection. The cap must stay >= every detector's per-field inspection window, or
# the truncation itself becomes a way to push a payload out of view (audit #21): Sigma matches up to 65,536
# chars per field (tokiwa.detect.sigma.evaluator.MAX_MATCH_CHARS), detect-web up to
# ``detection.web.max_inspect_chars`` (default 8192). tests/core/test_event_limits.py pins this relation.
EVENT_FIELD_MAX_CHARS = 65_536
# ``raw`` (kept for forensics only) is capped by its JSON size; adapters already keep 4 KiB
# (tokiwa.sensors.normalize.truncate_raw) and the oversized form below is the same shape they use.
EVENT_RAW_MAX_BYTES = 65_536
# Marks on a truncated event: a tag for filtering, and a label listing "<field>:<original length>".
TRUNCATED_TAG = "truncated"
TRUNCATED_LABEL = "tokiwa.truncated"
_TRUNCATED_LABEL_MAX = 1024


# Audit #25: a lone UTF-16 surrogate (JSON "\\ud800") cannot be encoded as UTF-8. Left in, it crashed every hash of
# the field (the sessionizer and the AI detectors fingerprint the User-Agent), so one such request escaped AI
# attribution, and it failed the event's own ``raw`` size check. Replaced with U+FFFD here; NUL is kept (it is
# attack evidence and Python handles it) and only removed at storage (tokiwa.db.sanitize).
_SURROGATE = re.compile(r"[\ud800-\udfff]")


def _fix(value: str) -> str:
    return _SURROGATE.sub("\ufffd", value)


def _fix_json(value: Any, depth: int = 0) -> Any:
    """Replace surrogates only, never cut (``raw`` is capped as a whole by :func:`_clip_raw`)."""
    if isinstance(value, str):
        return _fix(value) if _SURROGATE.search(value) else value
    if depth > 64:
        return value
    if isinstance(value, dict):
        return {_fix_json(k, depth + 1): _fix_json(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_fix_json(v, depth + 1) for v in value]
    return value


def _cut(value: str, path: str, clipped: list[str]) -> str:
    clipped.append(f"{path}:{len(value)}")
    return value[:EVENT_FIELD_MAX_CHARS]


# The walkers below run on every Event validation (5000 per ingest request), so they avoid per-field function
# calls and string formatting unless something actually has to be cut.


def _clip_model(model: BaseModel, prefix: str, clipped: list[str], skip: str | None = None) -> None:
    fields = model.__dict__
    for (
        name,
        item,
    ) in fields.items():  # values of existing keys are replaced in place: no resize while iterating
        if isinstance(item, str):
            if len(item) > EVENT_FIELD_MAX_CHARS:
                item = fields[name] = _cut(item, prefix + name, clipped)
            if _SURROGATE.search(item):
                fields[name] = _fix(item)
        elif isinstance(item, BaseModel):
            _clip_model(item, f"{prefix}{name}.", clipped)
        elif isinstance(item, list | dict) and item and name != skip:
            new = _clip_container(item, prefix + name, clipped)
            if new is not item:
                fields[name] = new


def _clip_container(value: list[Any] | dict[Any, Any], path: str, clipped: list[str]) -> Any:
    if isinstance(value, list):
        for i, item in enumerate(value):
            if isinstance(item, str):
                if len(item) > EVENT_FIELD_MAX_CHARS:
                    item = value[i] = _cut(item, path + "[]", clipped)
                if _SURROGATE.search(item):
                    value[i] = _fix(item)
            elif isinstance(item, BaseModel):
                _clip_model(item, path + "[].", clipped)
            elif isinstance(item, list | dict) and item:
                value[i] = _clip_container(item, path + "[]", clipped)
        return value
    changed = False
    out: dict[Any, Any] = {}
    for key, item in value.items():
        if isinstance(key, str):
            if len(key) > EVENT_FIELD_MAX_CHARS:
                key = _cut(key, path + "{}", clipped)
                changed = True
            if _SURROGATE.search(key):
                key = _fix(key)
                changed = True
        if isinstance(item, str):
            if len(item) > EVENT_FIELD_MAX_CHARS:
                item = _cut(item, path + "{}", clipped)
                changed = True
            if _SURROGATE.search(item):
                item = _fix(item)
                changed = True
        elif isinstance(item, BaseModel):
            _clip_model(item, path + "{}.", clipped)
        elif isinstance(item, list | dict) and item:
            new = _clip_container(item, path + "{}", clipped)
            changed = changed or new is not item
            item = new
        out[key] = item
    return out if changed else value


def _clip_raw(raw: dict[str, Any], clipped: list[str]) -> dict[str, Any]:
    text_field = raw.get("text")
    if (
        raw.get("_truncated") is True
        and set(raw) <= {"_truncated", "_bytes", "text"}
        and isinstance(text_field, str)
        and len(text_field.encode("utf-8")) <= EVENT_RAW_MAX_BYTES
    ):
        return raw  # already in the truncated form (re-validation of a stored event): keep it as is
    try:
        text = json.dumps(raw, ensure_ascii=False, default=str, separators=(",", ":"))
    except (TypeError, ValueError):  # e.g. circular references from an in-process caller
        text = repr(raw)
    size = len(text.encode("utf-8"))
    if size <= EVENT_RAW_MAX_BYTES:
        return raw
    clipped.append(f"raw:{size}")
    head = text.encode("utf-8")[:EVENT_RAW_MAX_BYTES].decode("utf-8", errors="ignore")
    return {"_truncated": True, "_bytes": size, "text": head}


class EventKind(StrEnum):
    HTTP = "http"  # one HTTP request/response pair (gate, nginx, caddy, waf)
    PORT_SNAPSHOT = "port_snapshot"  # full list of listening sockets on a host at a point in time
    PORT_CHANGE = "port_change"  # a listener appeared/disappeared (derived from snapshots)
    CONNECTION = "connection"  # a network connection / flow (host sensor, zeek conn, suricata flow)
    IDS_ALERT = "ids_alert"  # signature hit from Suricata / Zeek notice
    DNS = "dns"
    PROCESS = "process"
    AUTH = "auth"
    DECEPTION = "deception"  # interaction with a decoy / honeytoken / AI canary
    LLM_APP = "llm_app"  # prompt sent to a protected LLM application
    CUSTOM = "custom"


class Endpoint(BaseModel):
    ip: str | None = None
    port: int | None = None
    hostname: str | None = None
    geo_country: str | None = None
    asn: int | None = None
    asn_org: str | None = None


class HostInfo(BaseModel):
    name: str | None = None
    ip: list[str] = Field(default_factory=list)
    os: str | None = None


class HttpInfo(BaseModel):
    method: str | None = None
    scheme: str | None = None
    host: str | None = None
    path: str | None = None
    query: str | None = None
    # Allow-listed + redacted request headers, lower-cased names. Order preserved when known.
    headers: dict[str, str] = Field(default_factory=dict)
    header_order: list[str] = Field(default_factory=list)
    user_agent: str | None = None
    referrer: str | None = None
    content_type: str | None = None
    request_body_size: int | None = None
    # First N bytes of the body (redacted, decoded as UTF-8 with replacement). Only Gate/WAF can see bodies.
    request_body: str | None = None
    status: int | None = None
    response_size: int | None = None
    response_content_type: str | None = None
    duration_ms: float | None = None
    http_version: str | None = None


class ProcessInfo(BaseModel):
    pid: int | None = None
    name: str | None = None
    exe: str | None = None
    cmdline: str | None = None
    username: str | None = None


class ListeningSocket(BaseModel):
    protocol: str  # tcp / udp / tcp6 / udp6
    bind_ip: str
    port: int
    process: ProcessInfo | None = None


class PortInfo(BaseModel):
    """For PORT_SNAPSHOT (``listeners``) and PORT_CHANGE (``change`` + ``socket``)."""

    listeners: list[ListeningSocket] = Field(default_factory=list)
    change: str | None = None  # "opened" | "closed" | "process_changed"
    socket: ListeningSocket | None = None


class NetworkInfo(BaseModel):
    transport: str | None = None  # tcp / udp / icmp
    protocol: str | None = None  # application protocol (http, tls, ssh, dns ...)
    direction: str | None = None  # inbound / outbound / internal
    state: str | None = None  # ESTABLISHED, SYN_SENT, S0 ...
    bytes_in: int | None = None
    bytes_out: int | None = None
    packets: int | None = None
    duration_ms: float | None = None
    process: ProcessInfo | None = None


class IdsInfo(BaseModel):
    engine: str | None = None  # suricata / zeek
    signature: str | None = None
    signature_id: int | None = None
    category: str | None = None
    severity: int | None = None  # engine-native severity (suricata: 1=high .. 3=low)
    action: str | None = None


class DeceptionInfo(BaseModel):
    asset_id: str | None = None
    asset_kind: str | None = None  # honeytoken / decoy_path / ai_canary / labyrinth
    token: str | None = None  # the canary value that was observed (never a real secret)
    detail: str | None = None


class LLMAppInfo(BaseModel):
    """A prompt observed on its way to a protected LLM application (prompt-injection monitoring)."""

    app: str | None = None
    prompt: str | None = None  # redacted + truncated
    role: str | None = None
    model: str | None = None
    tool_names: list[str] = Field(default_factory=list)


class Event(BaseModel):
    id: str = Field(default_factory=new_id)
    timestamp: datetime = Field(default_factory=utcnow)
    ingested_at: datetime | None = None
    kind: EventKind
    # "<sensor family>.<stream>", e.g. gate.http, nginx.access, host.ports, suricata.eve, zeek.conn
    dataset: str
    sensor_id: str | None = None
    message: str | None = None
    host: HostInfo | None = None
    source: Endpoint | None = None
    destination: Endpoint | None = None
    http: HttpInfo | None = None
    network: NetworkInfo | None = None
    port: PortInfo | None = None
    ids: IdsInfo | None = None
    deception: DeceptionInfo | None = None
    llm_app: LLMAppInfo | None = None
    process: ProcessInfo | None = None
    # Assigned by the sessionizer enricher (actor session = same source + client fingerprint + idle window).
    session_id: str | None = None
    asset_id: str | None = None
    tags: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    # Original record (truncated) for forensics. Never sent to the LLM as-is.
    raw: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _cap_sizes(self) -> Self:
        """Truncate oversized strings / ``raw`` (see EVENT_FIELD_MAX_CHARS) and mark the event when it happens.

        Runs on every validation (ingest, in-process construction, DB reads); it is idempotent, and an event that
        needed no cut is left untouched, so a mark stored at ingest survives re-reads. Tags and labels are
        sender-controlled, so the mark is informational, not proof.
        """
        clipped: list[str] = []
        _clip_model(self, "", clipped, skip="raw")
        if self.raw:
            self.raw = _clip_raw(_fix_json(self.raw), clipped)
        if clipped:
            if TRUNCATED_TAG not in self.tags:
                self.tags.append(TRUNCATED_TAG)
            self.labels[TRUNCATED_LABEL] = ",".join(clipped)[:_TRUNCATED_LABEL_MAX]
        return self

    @property
    def source_ip(self) -> str | None:
        return self.source.ip if self.source else None


class IngestBatch(BaseModel):
    events: list[Event] = Field(max_length=5000)


class IngestResult(BaseModel):
    accepted: int
    alerts: int
    alert_ids: list[str] = Field(default_factory=list)
    # Events of the batch that were already stored or repeated within it (a sensor retry), skipped (audit #25).
    duplicates: int = 0
