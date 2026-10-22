"""Plain data types shared by the simulator, the virtual lab and the dataset writer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SimRequest:
    method: str
    path: str  # path only, may contain percent-encoding exactly as sent
    query: str | None = None  # raw query string (already encoded) without "?"
    headers: list[tuple[str, str]] = field(default_factory=list)  # extra/override headers, in send order
    body: str | None = None
    content_type: str | None = None
    # Ground-truth annotations (never sent on the wire)
    attack: str = "none"
    phase: str = ""

    @property
    def target(self) -> str:
        return f"{self.path}?{self.query}" if self.query else self.path


@dataclass
class SimResponse:
    status: int
    content_type: str = ""
    body: str = ""
    size: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None  # transport error (connection refused, timeout ...)

    @property
    def is_error(self) -> bool:
        return self.status >= 400 or self.error is not None


@dataclass
class ClientIdentity:
    """Who the simulated actor looks like on the wire."""

    source_ip: str
    user_agent: str
    family: str  # chrome / firefox / safari / curl / httpx / requests / aiohttp / go / nuclei / sqlmap ...
    accept_language: str | None = None


@dataclass
class Exchange:
    """One request/response pair as observed by a Gate-like sensor, plus ground truth."""

    request: SimRequest
    response: SimResponse
    timestamp: datetime
    duration_ms: float
    source_ip: str
    source_port: int
    headers: list[tuple[str, str]]  # full header list as sent (lower-case names, in order)
    host: str
    scheme: str
    labels: dict[str, str] = field(default_factory=dict)
