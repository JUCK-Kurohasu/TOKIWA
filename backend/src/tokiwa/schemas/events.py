"""Normalized telemetry event schema (ECS-inspired, intentionally smaller).

Every sensor / adapter converts its native format into :class:`Event`. Field names follow ECS where a
counterpart exists (``source.ip``, ``http.request.method`` -> ``http.method`` ...), flattened one level to keep
LLM prompts and DB columns simple. See docs/decisions/ADR-0003-event-schema.md.

All string fields that can be controlled by a remote party (URL, headers, UA, body) are UNTRUSTED. Never feed
them to the LLM without :mod:`tokiwa.llm.redact` + the untrusted-data envelope in :mod:`tokiwa.llm.prompting`.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from tokiwa.util import new_id, utcnow


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

    @property
    def source_ip(self) -> str | None:
        return self.source.ip if self.source else None


class IngestBatch(BaseModel):
    events: list[Event] = Field(max_length=5000)


class IngestResult(BaseModel):
    accepted: int
    alerts: int
    alert_ids: list[str] = Field(default_factory=list)
