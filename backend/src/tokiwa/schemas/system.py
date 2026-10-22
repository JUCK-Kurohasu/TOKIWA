"""Users, tokens, LLM audit records, rules, jobs, audit log."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from tokiwa.schemas.common import ORMModel


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(ORMModel):
    id: str
    username: str
    role: Role
    created_at: datetime
    last_login: datetime | None = None


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=10, max_length=256)
    role: Role = Role.ANALYST


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: User


class AuthStatus(BaseModel):
    setup_required: bool
    version: str


class ApiTokenScope(StrEnum):
    INGEST = "ingest"  # push events (agents, gate)
    GATE = "gate"  # pull gate policy
    READ = "read"  # read-only API automation


class ApiToken(ORMModel):
    id: str
    name: str
    scopes: list[str]
    prefix: str  # first chars for identification; the secret itself is shown only once
    created_at: datetime
    last_used: datetime | None = None
    revoked: bool = False


class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    scopes: list[ApiTokenScope] = Field(default_factory=lambda: [ApiTokenScope.INGEST, ApiTokenScope.GATE])


class ApiTokenCreated(ApiToken):
    token: str


class LLMCallStatus(StrEnum):
    OK = "ok"
    REFUSED = "refused"
    ERROR = "error"
    BUDGET_EXCEEDED = "budget_exceeded"
    INVALID_OUTPUT = "invalid_output"


class LLMCall(ORMModel):
    id: str
    created_at: datetime
    provider: str
    model: str
    tier: str
    purpose: str
    prompt_version: str
    status: LLMCallStatus
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    web_search_requests: int
    cost_usd: float
    latency_ms: float
    related: dict[str, str]
    error: str | None = None


class LLMCallDetail(LLMCall):
    request_redacted: str | None = None
    response_text: str | None = None


class RuleKind(StrEnum):
    SIGMA = "sigma"


class RuleStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    PROPOSED = "proposed"  # e.g. drafted by the LLM advisor, awaiting human review
    REJECTED = "rejected"


class RuleSource(StrEnum):
    BUILTIN = "builtin"
    USER = "user"
    LLM = "llm"


class Rule(ORMModel):
    id: str
    kind: RuleKind
    title: str
    content: str
    status: RuleStatus
    source: RuleSource
    created_at: datetime
    updated_at: datetime
    hit_count: int = 0
    meta: dict[str, Any] = Field(default_factory=dict)


class RuleIn(BaseModel):
    kind: RuleKind = RuleKind.SIGMA
    content: str
    status: RuleStatus = RuleStatus.ACTIVE


class DetectorInfo(BaseModel):
    id: str
    name: str
    description: str
    category: str
    kinds: list[str]
    enabled: bool
    mitre: list[str] = Field(default_factory=list)


class JobInfo(BaseModel):
    name: str
    interval_seconds: float
    running: bool
    last_started: datetime | None = None
    last_finished: datetime | None = None
    last_error: str | None = None
    run_count: int = 0


class AuditEntry(ORMModel):
    id: str
    created_at: datetime
    actor: str
    action: str
    target: str | None
    details: dict[str, Any]


class SystemInfo(BaseModel):
    version: str
    env: str
    llm_provider: str
    llm_available: bool
    database: str
    detectors: int
    jobs: list[JobInfo]
