"""Read-only tools the copilot LLM may call (docs/tasks/copilot.md, architecture §7-4).

Security model:

- **No write / execute tools exist.** Every handler only SELECTs, and runs inside :func:`read_only_session`,
  which always rolls back and never commits.
- **The LLM never writes SQL.** Inputs are validated by strict Pydantic models (``extra="forbid"``, bounded
  ``limit``, id/IP patterns) and turned into parameterized SQLAlchemy expressions. ``path_contains`` uses
  ``icontains(..., autoescape=True)`` so ``%``/``_`` are matched literally.
- **Results are bounded and inert.** Rows are projected to compact dicts (long strings clipped), redacted with
  :func:`tokiwa.llm.redact.redact_obj`, trimmed to ``copilot.max_tool_result_chars`` and wrapped with
  :func:`tokiwa.llm.prompting.untrusted_block` because they contain attacker-controlled telemetry.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import logging
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError, model_validator
from pydantic.json_schema import GenerateJsonSchema, JsonSchemaValue
from pydantic_core import core_schema
from sqlalchemy import ColumnElement, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.config import get_settings
from tokiwa.db.models.detection import AlertRow, IncidentRow
from tokiwa.db.models.intel import AdvisoryRow, AssetRow, VulnMatchRow, VulnRow
from tokiwa.db.models.response import ResponseActionRow
from tokiwa.db.models.telemetry import ActorSessionRow, EventRow
from tokiwa.db.session import get_sessionmaker
from tokiwa.llm.base import ToolSpec
from tokiwa.llm.prompting import untrusted_block
from tokiwa.llm.redact import redact_obj
from tokiwa.schemas.alerts import AlertCategory, AlertStatus, IncidentStatus
from tokiwa.schemas.common import ActorType, Severity
from tokiwa.schemas.events import EventKind
from tokiwa.schemas.intel import MatchStatus
from tokiwa.schemas.response import ActionStatus
from tokiwa.schemas.triage import ActionType
from tokiwa.util import ensure_utc, utcnow

log = logging.getLogger(__name__)

# Hard caps (independent of settings) so a misconfiguration cannot turn a tool into a bulk export.
MAX_LIST_LIMIT = 50
MAX_TOP_SOURCES = 25
MAX_EVIDENCE_EVENTS = 10
MAX_INCIDENT_ALERTS = 25
MAX_INCIDENT_ACTIONS = 10
MAX_SESSION_EVENTS = 50
MAX_ASSET_RESULTS = 5
MAX_LOOKBACK_HOURS = 24 * 30


# --------------------------------------------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------------------------------------------

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_VULN_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$"


def _valid_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError("must be a single IPv4/IPv6 address (no CIDR, no hostname)") from exc


IdStr = Annotated[str, Field(pattern=_ID_PATTERN, max_length=128)]
IpStr = Annotated[str, Field(max_length=64, description="IPv4/IPv6 address"), AfterValidator(_valid_ip)]


class ToolInput(BaseModel):
    """Base for tool inputs: unknown keys are rejected so the JSON schema is the whole contract."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class _TimeWindow(ToolInput):
    since: datetime | None = Field(
        default=None, description="Window start, ISO 8601 (UTC when no offset). Takes precedence over hours."
    )
    until: datetime | None = Field(default=None, description="Window end, ISO 8601 (UTC when no offset).")
    hours: int | None = Field(
        default=None, ge=1, le=MAX_LOOKBACK_HOURS, description="Look back this many hours from now."
    )

    def window(self) -> tuple[datetime | None, datetime | None]:
        since = ensure_utc(self.since) if self.since else None
        if since is None and self.hours:
            since = utcnow() - timedelta(hours=self.hours)
        until = ensure_utc(self.until) if self.until else None
        return since, until


def _limit(default: int, maximum: int = MAX_LIST_LIMIT) -> Any:
    return Field(default=default, ge=1, le=maximum, description=f"Max rows to return (1-{maximum}).")


class SearchEventsInput(_TimeWindow):
    kind: EventKind | None = Field(default=None, description="Event kind.")
    source_ip: IpStr | None = Field(default=None, description="Exact source IP address.")
    path_contains: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
        description="Case-insensitive literal substring of the HTTP path (no wildcards).",
    )
    session_id: IdStr | None = Field(default=None, description="Actor session id.")
    host: str | None = Field(default=None, max_length=255, description="Exact monitored host name.")
    http_status: int | None = Field(default=None, ge=100, le=599, description="Exact HTTP response status.")
    limit: int = _limit(20)


class AlertIdInput(ToolInput):
    alert_id: IdStr = Field(description="Alert id.")


class ListAlertsInput(_TimeWindow):
    status: AlertStatus | None = None
    min_severity: Severity | None = Field(default=None, description="Only alerts at or above this severity.")
    category: AlertCategory | None = None
    source_ip: IpStr | None = None
    incident_id: IdStr | None = None
    rule_id: str | None = Field(default=None, max_length=128, description="Exact rule id.")
    min_ai_score: float | None = Field(
        default=None, ge=0.0, le=1.0, description="Only alerts whose AI-agent score is at least this."
    )
    limit: int = _limit(20)


class IncidentIdInput(ToolInput):
    incident_id: IdStr = Field(description="Incident id.")


class ListIncidentsInput(_TimeWindow):
    status: IncidentStatus | None = None
    min_severity: Severity | None = None
    actor_type: ActorType | None = None
    limit: int = _limit(20)


class SessionInput(ToolInput):
    session_id: IdStr = Field(description="Actor session id.")
    event_limit: int = Field(
        default=30, ge=1, le=MAX_SESSION_EVENTS, description="Most recent events of the session to include."
    )


class TopSourcesInput(ToolInput):
    hours: int = Field(default=24, ge=1, le=MAX_LOOKBACK_HOURS, description="Look-back window in hours.")
    kind: EventKind | None = Field(default=None, description="Only count events of this kind.")
    limit: int = _limit(10, MAX_TOP_SOURCES)


class LookupVulnInput(ToolInput):
    vuln_id: str = Field(
        pattern=_VULN_ID_PATTERN, description="Vulnerability id, e.g. CVE-2025-12345, GHSA-xxxx-xxxx-xxxx."
    )


class ListVulnMatchesInput(ToolInput):
    status: MatchStatus | None = None
    kev_only: bool = Field(default=False, description="Only vulnerabilities in CISA KEV.")
    min_epss: float | None = Field(default=None, ge=0.0, le=1.0, description="Minimum EPSS probability.")
    asset_id: IdStr | None = None
    vuln_id: str | None = Field(default=None, pattern=_VULN_ID_PATTERN)
    limit: int = _limit(20)


class GetAssetInput(ToolInput):
    asset_id: IdStr | None = Field(default=None, description="Exact asset id.")
    name: str | None = Field(
        default=None, min_length=1, max_length=128, description="Substring of asset name or hostname."
    )
    ip: IpStr | None = Field(default=None, description="An IP address assigned to the asset.")

    @model_validator(mode="after")
    def _one_selector(self) -> GetAssetInput:
        if not (self.asset_id or self.name or self.ip):
            raise ValueError("provide asset_id, name or ip")
        return self


class ListActionsInput(ToolInput):
    status: ActionStatus | None = None
    action_type: ActionType | None = None
    incident_id: IdStr | None = None
    target: str | None = Field(default=None, max_length=255, description="Exact target (IP/CIDR).")
    limit: int = _limit(20)


# --------------------------------------------------------------------------------------------------------------
# JSON schema generation (single source of truth = the Pydantic input models)
# --------------------------------------------------------------------------------------------------------------


class _ToolSchemaGenerator(GenerateJsonSchema):
    def nullable_schema(self, schema: core_schema.NullableSchema) -> JsonSchemaValue:
        # ``X | None = None`` -> plain ``X``: optional fields are simply omitted, the model never needs null.
        return self.generate_inner(schema["schema"])


def _clean_schema(node: Any, defs: dict[str, Any]) -> Any:
    if isinstance(node, list):
        return [_clean_schema(v, defs) for v in node]
    if not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/$defs/"):
        # Inline the definition (input models are not recursive); sibling keys (description ...) win.
        target = copy.deepcopy(defs[ref.rsplit("/", 1)[-1]])
        return _clean_schema({**target, **{k: v for k, v in node.items() if k != "$ref"}}, defs)
    all_of = node.get("allOf")
    if isinstance(all_of, list) and len(all_of) == 1:
        merged = {**node}
        merged.pop("allOf")
        return _clean_schema({**all_of[0], **merged}, defs)
    out: dict[str, Any] = {}
    for k, v in node.items():
        if k == "title" and isinstance(v, str):
            continue
        if k == "default" and v is None:
            continue
        out[k] = _clean_schema(v, defs)
    return out


def tool_input_schema(model: type[BaseModel]) -> dict[str, Any]:
    """Self-contained JSON schema: no ``$ref``, no titles, ``additionalProperties: false``."""
    raw = model.model_json_schema(schema_generator=_ToolSchemaGenerator)
    defs = raw.pop("$defs", {})
    schema: dict[str, Any] = _clean_schema(raw, defs)
    schema["type"] = "object"
    schema["additionalProperties"] = False
    schema.setdefault("properties", {})
    schema.setdefault("required", [])
    return schema


# --------------------------------------------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------------------------------------------


class ToolError(Exception):
    """Expected failure (not found, bad combination). Message is shown to the model as ``is_error``."""


@dataclass(frozen=True)
class ToolOutput:
    data: dict[str, Any]
    summary: str  # short, data-free description for the UI (SSE ``tool_result``)


Handler = Callable[[AsyncSession, Any], Awaitable[ToolOutput]]


@dataclass(frozen=True)
class CopilotTool:
    name: str
    description: str
    input_model: type[ToolInput]
    handler: Handler

    def spec(self) -> ToolSpec:
        return ToolSpec(
            name=self.name, description=self.description, input_schema=tool_input_schema(self.input_model)
        )


_TOOLS: dict[str, CopilotTool] = {}


def _register(name: str, description: str, input_model: type[ToolInput]) -> Callable[[Handler], Handler]:
    def deco(fn: Handler) -> Handler:
        _TOOLS[name] = CopilotTool(name=name, description=description, input_model=input_model, handler=fn)
        return fn

    return deco


def registered_tools() -> dict[str, CopilotTool]:
    return dict(_TOOLS)


def tool_specs() -> list[ToolSpec]:
    """Deterministic order (registration order) so the tools prefix stays cacheable."""
    return [t.spec() for t in _TOOLS.values()]


@asynccontextmanager
async def read_only_session() -> AsyncIterator[AsyncSession]:
    """A session that is always rolled back: tools are read-only by construction, never by convention."""
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        await session.rollback()
        await session.close()


@dataclass
class ToolExecution:
    tool_use_id: str
    name: str
    ok: bool
    content: str  # tool_result.content: untrusted-wrapped JSON on success, a short message on error
    summary: str
    input: dict[str, Any] = field(default_factory=dict)

    def block(self) -> dict[str, Any]:
        block: dict[str, Any] = {
            "type": "tool_result",
            "tool_use_id": self.tool_use_id,
            "content": self.content,
        }
        if not self.ok:
            block["is_error"] = True
        return block


def _validation_message(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors()[:5]:
        loc = ".".join(str(p) for p in err.get("loc", ()))[:64] or "input"
        parts.append(f"{loc}: {err.get('msg', 'invalid')}")
    return "; ".join(parts)


def error_execution(tool_use_id: str, name: str, message: str, raw_input: Any = None) -> ToolExecution:
    return ToolExecution(
        tool_use_id=tool_use_id,
        name=name,
        ok=False,
        content=f"Error: {message}",
        summary=f"error: {message}"[:300],
        input=raw_input if isinstance(raw_input, dict) else {},
    )


def render_result(name: str, data: dict[str, Any], max_chars: int | None = None) -> str:
    cap = max_chars or get_settings().copilot.max_tool_result_chars
    redacted = redact_obj(data)
    fitted = fit_to_budget(redacted if isinstance(redacted, dict) else {"result": redacted}, cap)
    # Already redacted above; the envelope escapes "<"/">" so data cannot close it.
    return untrusted_block(f"tool_result:{name}", fitted, redact=False, max_chars=cap)


def _json_len(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False, default=str, sort_keys=True))


def fit_to_budget(data: dict[str, Any], max_chars: int) -> dict[str, Any]:
    """Drop trailing items of the largest top-level list until the JSON fits; mark the result as truncated."""
    budget = max(200, max_chars - 120)  # room for the truncation markers
    if _json_len(data) <= budget:
        return data
    out = dict(data)
    for k, v in out.items():
        if isinstance(v, list):
            out[k] = list(v)
    omitted = 0
    while _json_len(out) > budget:
        candidates = [k for k, v in out.items() if isinstance(v, list) and v]
        if not candidates:
            break
        key = max(candidates, key=lambda k: _json_len(out[k]))
        out[key].pop()
        omitted += 1
    out["truncated"] = True
    out["omitted_items"] = omitted
    return out


async def execute_tool(name: str, tool_use_id: str, raw_input: Any) -> ToolExecution:
    tool = _TOOLS.get(name)
    if tool is None:
        return error_execution(
            tool_use_id, str(name)[:64], f"unknown tool. Available tools: {', '.join(_TOOLS)}", raw_input
        )
    try:
        args = tool.input_model.model_validate(raw_input if raw_input is not None else {})
    except ValidationError as exc:
        return error_execution(tool_use_id, name, f"invalid input: {_validation_message(exc)}", raw_input)
    try:
        async with read_only_session() as session:
            out = await tool.handler(session, args)
    except ToolError as exc:
        return error_execution(tool_use_id, name, str(exc)[:500], raw_input)
    except Exception:
        log.exception("copilot tool %s failed", name)
        return error_execution(tool_use_id, name, "internal error while running the tool", raw_input)
    return ToolExecution(
        tool_use_id=tool_use_id,
        name=name,
        ok=True,
        content=render_result(name, out.data),
        summary=out.summary,
        input=args.model_dump(mode="json", exclude_none=True),
    )


# --------------------------------------------------------------------------------------------------------------
# Projections (compact, clipped views of rows)
# --------------------------------------------------------------------------------------------------------------


def _iso(dt: datetime | None) -> str | None:
    return ensure_utc(dt).isoformat() if dt else None


def _clip(value: Any, n: int) -> str | None:
    if value is None:
        return None
    s = str(value)
    return s if len(s) <= n else f"{s[:n]}...[+{len(s) - n} chars]"


def _clip_obj(obj: Any, n: int) -> Any:
    """Keep small JSON values as-is; replace large ones by a clipped JSON string."""
    if obj is None:
        return None
    text = json.dumps(obj, ensure_ascii=False, default=str, sort_keys=True)
    return obj if len(text) <= n else _clip(text, n)


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _prune(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None and v != [] and v != {}}


def _pick(src: Any, fields: tuple[str, ...], clip: int = 200) -> dict[str, Any] | None:
    if not isinstance(src, dict):
        return None
    out = _prune(
        {f: (_clip(src.get(f), clip) if isinstance(src.get(f), str) else src.get(f)) for f in fields}
    )
    return out or None


def event_brief(row: EventRow) -> dict[str, Any]:
    d = row.data if isinstance(row.data, dict) else {}
    out: dict[str, Any] = {
        "id": row.id,
        "timestamp": _iso(row.timestamp),
        "kind": row.kind,
        "dataset": row.dataset,
        "source_ip": row.source_ip,
        "destination": f"{row.dest_ip}:{row.dest_port}" if row.dest_ip else None,
        "host": row.host_name,
        "session_id": row.session_id,
        "asset_id": row.asset_id,
        "tags": list(row.tags or [])[:10],
        "message": _clip(d.get("message"), 300),
    }
    http = d.get("http")
    if isinstance(http, dict):
        headers = _as_dict(http.get("headers"))
        out["http"] = _prune(
            {
                "method": http.get("method"),
                "host": _clip(http.get("host"), 200),
                "path": _clip(http.get("path"), 300),
                "query": _clip(http.get("query"), 300),
                "status": http.get("status"),
                "user_agent": _clip(http.get("user_agent"), 200),
                "content_type": _clip(http.get("content_type"), 100),
                "request_body_size": http.get("request_body_size"),
                "request_body_excerpt": _clip(http.get("request_body"), 300),
                "response_size": http.get("response_size"),
                "duration_ms": http.get("duration_ms"),
                # Header order is an AI-agent/tooling fingerprint; values stay out (volume + secrets).
                "header_names": [str(h)[:64] for h in (http.get("header_order") or list(headers))][:30],
            }
        )
    out["ids"] = _pick(
        d.get("ids"), ("engine", "signature", "signature_id", "category", "severity", "action")
    )
    out["deception"] = _pick(d.get("deception"), ("asset_id", "asset_kind", "detail"))
    out["network"] = _pick(
        d.get("network"), ("transport", "protocol", "direction", "state", "bytes_in", "bytes_out")
    )
    llm_app = d.get("llm_app")
    if isinstance(llm_app, dict):
        out["llm_app"] = _prune(
            {
                "app": _clip(llm_app.get("app"), 100),
                "role": llm_app.get("role"),
                "model": _clip(llm_app.get("model"), 100),
                "tool_names": [str(t)[:64] for t in (llm_app.get("tool_names") or [])][:20],
                "prompt_excerpt": _clip(llm_app.get("prompt"), 500),
            }
        )
    port = d.get("port")
    if isinstance(port, dict) and (port.get("change") or port.get("socket")):
        sock = _as_dict(port.get("socket"))
        proc = _as_dict(sock.get("process"))
        out["port"] = _prune(
            {
                "change": port.get("change"),
                "protocol": sock.get("protocol"),
                "bind_ip": sock.get("bind_ip"),
                "port": sock.get("port"),
                "process": _clip(proc.get("name"), 100),
            }
        )
    out["process"] = _pick(d.get("process"), ("pid", "name", "cmdline", "username"))
    return _prune(out)


def _triage_brief(triage: Any, *, detail: bool) -> dict[str, Any] | None:
    if not isinstance(triage, dict):
        return None
    result = _as_dict(triage.get("result"))
    out: dict[str, Any] = {
        "tier": triage.get("tier"),
        "summary": _clip(result.get("summary"), 600),
        "severity": result.get("severity"),
        "confidence": result.get("confidence"),
        "actor_type": result.get("actor_type"),
        "ai_agent_likelihood": result.get("ai_agent_likelihood"),
        "attack_stage": result.get("attack_stage"),
        "mitre_techniques": list(result.get("mitre_techniques") or [])[:10],
    }
    if detail:
        out["rationale"] = _clip(result.get("rationale"), 600)
        out["ai_agent_indicators"] = [_clip(i, 200) for i in (result.get("ai_agent_indicators") or [])][:10]
        out["next_steps"] = [_clip(s, 200) for s in (result.get("next_steps") or [])][:8]
        # Proposals only: they still require human approval in the respond module.
        out["recommended_actions"] = [
            _pick(a, ("action_type", "target", "ttl_minutes", "reason"))
            for a in (result.get("recommended_actions") or [])
        ][:5]
    return _prune(out)


def alert_brief(row: AlertRow, *, detail: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": row.id,
        "title": _clip(row.title, 200),
        "rule_id": row.rule_id,
        "detector": row.detector,
        "severity": row.severity,
        "confidence": row.confidence,
        "category": row.category,
        "status": row.status,
        "source_ip": row.source_ip,
        "ai_score": row.ai_score,
        "count": row.count,
        "first_seen": _iso(row.first_seen),
        "last_seen": _iso(row.last_seen),
        "incident_id": row.incident_id,
        "mitre": list(row.mitre or [])[:10],
        "tags": list(row.tags or [])[:10],
        "triage": _triage_brief(row.triage, detail=detail),
    }
    if detail:
        out["description"] = _clip(row.description, 800)
        out["entities"] = _clip_obj(row.entities, 800)
        out["evidence_event_ids"] = list(row.evidence_event_ids or [])[:25]
        out["details"] = _clip_obj(row.details, 1500)
    return _prune(out)


def incident_brief(row: IncidentRow, *, detail: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": row.id,
        "title": _clip(row.title, 200),
        "severity": row.severity,
        "status": row.status,
        "category": row.category,
        "actor_type": row.actor_type,
        "ai_score": row.ai_score,
        "source_ips": list(row.source_ips or [])[:20],
        "alert_count": row.alert_count,
        "first_seen": _iso(row.first_seen),
        "last_seen": _iso(row.last_seen),
        "assignee": row.assignee,
        "kill_chain": list(row.kill_chain or [])[:15],
        "triage": _triage_brief(row.triage, detail=detail),
    }
    if detail:
        out["summary"] = _clip(row.summary, 800)
        out["mitre"] = list(row.mitre or [])[:20]
        out["tags"] = list(row.tags or [])[:10]
    return _prune(out)


def session_brief(row: ActorSessionRow, *, features: bool = True) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": row.id,
        "source_ip": row.source_ip,
        "client_fingerprint": row.client_fingerprint,
        "user_agent": _clip(row.user_agent, 200),
        "first_seen": _iso(row.first_seen),
        "last_seen": _iso(row.last_seen),
        "request_count": row.request_count,
        "error_count": row.error_count,
        "unique_paths": row.unique_paths,
        "ai_score": row.ai_score,
        "classification": row.classification,
        "incident_id": row.incident_id,
    }
    if features:
        out["features"] = _clip_obj(row.features, 2000)
    return _prune(out)


def vuln_brief(row: VulnRow, *, detail: bool = True) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": row.id,
        "title": _clip(row.title, 200),
        "severity": row.severity,
        "cvss_score": row.cvss_score,
        "epss": row.epss,
        "epss_percentile": row.epss_percentile,
        "kev": row.kev,
        "kev_date_added": _iso(row.kev_date_added),
        "kev_due_date": _iso(row.kev_due_date),
        "kev_ransomware": row.kev_ransomware,
        "published": _iso(row.published),
    }
    if detail:
        out.update(
            {
                "aliases": list(row.aliases or [])[:10],
                "sources": list(row.sources or [])[:10],
                "description": _clip(row.description, 800),
                "cvss_vector": row.cvss_vector,
                "modified": _iso(row.modified),
                "cwe": list(row.cwe or [])[:10],
                "affected": [
                    _pick(a, ("vendor", "product", "version", "cpe", "ecosystem"))
                    for a in (row.affected or [])[:10]
                ],
                "references": [_clip(r, 200) for r in (row.references or [])][:10],
            }
        )
    return _prune(out)


def asset_brief(row: AssetRow) -> dict[str, Any]:
    return _prune(
        {
            "id": row.id,
            "name": _clip(row.name, 200),
            "kind": row.kind,
            "hostname": row.hostname,
            "ips": list(row.ips or [])[:20],
            "criticality": row.criticality,
            "owner": _clip(row.owner, 100),
            "tags": list(row.tags or [])[:10],
            "notes": _clip(row.notes, 300),
            "software": [
                _pick(s, ("vendor", "product", "version", "cpe", "ecosystem"))
                for s in (row.software or [])[:50]
            ],
        }
    )


def action_brief(row: ResponseActionRow) -> dict[str, Any]:
    return _prune(
        {
            "id": row.id,
            "action_type": row.action_type,
            "target": row.target,
            "status": row.status,
            "reason": _clip(row.reason, 300),
            "proposed_by": row.proposed_by,
            "incident_id": row.incident_id,
            "alert_id": row.alert_id,
            "ttl_minutes": row.ttl_minutes,
            "created_at": _iso(row.created_at),
            "approved_by": row.approved_by,
            "approved_at": _iso(row.approved_at),
            "executed_at": _iso(row.executed_at),
            "expires_at": _iso(row.expires_at),
            "reverted_at": _iso(row.reverted_at),
        }
    )


def _severity_at_least(minimum: Severity) -> list[str]:
    return [s.value for s in Severity if s.rank >= minimum.rank]


async def _count(session: AsyncSession, model: Any, conds: list[ColumnElement[bool]]) -> int:
    stmt = select(func.count()).select_from(model)
    if conds:
        stmt = stmt.where(*conds)
    return int((await session.execute(stmt)).scalar_one())


def _normalize_vuln_id(value: str) -> str:
    v = value.strip()
    if re.match(r"(?i)^cve-", v):
        return v.upper()
    m = re.match(r"(?i)^(ghsa|jvndb)-(.*)$", v)
    if m:
        return f"{m.group(1).upper()}-{m.group(2)}"
    return v


# --------------------------------------------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------------------------------------------


@_register(
    "search_events",
    "Search normalized telemetry events (HTTP requests, port changes, IDS alerts, deception trips, LLM-app "
    "prompts ...), newest first. Combine filters to stay narrow. Returns compact events and the total match count.",
    SearchEventsInput,
)
async def search_events(session: AsyncSession, args: SearchEventsInput) -> ToolOutput:
    conds: list[ColumnElement[bool]] = []
    if args.kind:
        conds.append(EventRow.kind == args.kind.value)
    if args.source_ip:
        conds.append(EventRow.source_ip == args.source_ip)
    if args.path_contains:
        conds.append(EventRow.http_path.icontains(args.path_contains, autoescape=True))
    if args.session_id:
        conds.append(EventRow.session_id == args.session_id)
    if args.host:
        conds.append(EventRow.host_name == args.host)
    if args.http_status:
        conds.append(EventRow.http_status == args.http_status)
    since, until = args.window()
    if since:
        conds.append(EventRow.timestamp >= since)
    if until:
        conds.append(EventRow.timestamp <= until)
    total = await _count(session, EventRow, conds)
    stmt = select(EventRow).where(*conds).order_by(EventRow.timestamp.desc()).limit(args.limit)
    rows = (await session.execute(stmt)).scalars().all()
    return ToolOutput(
        data={"total": total, "returned": len(rows), "items": [event_brief(r) for r in rows]},
        summary=f"{len(rows)} of {total} events",
    )


@_register(
    "get_alert",
    "Get one alert by id with its triage verdict and up to 10 evidence events.",
    AlertIdInput,
)
async def get_alert(session: AsyncSession, args: AlertIdInput) -> ToolOutput:
    row = await session.get(AlertRow, args.alert_id)
    if row is None:
        raise ToolError(f"alert {args.alert_id} not found")
    ids = list(row.evidence_event_ids or [])[:MAX_EVIDENCE_EVENTS]
    evidence: list[EventRow] = []
    if ids:
        found = (await session.execute(select(EventRow).where(EventRow.id.in_(ids)))).scalars().all()
        by_id = {e.id: e for e in found}
        evidence = [by_id[i] for i in ids if i in by_id]
    return ToolOutput(
        data={"alert": alert_brief(row, detail=True), "evidence": [event_brief(e) for e in evidence]},
        summary=f"alert {row.id} ({row.severity}) with {len(evidence)} evidence events",
    )


@_register(
    "list_alerts",
    "List alerts (most recently seen first) filtered by status, minimum severity, category, source IP, incident, "
    "rule, AI-agent score and time window (on last_seen).",
    ListAlertsInput,
)
async def list_alerts(session: AsyncSession, args: ListAlertsInput) -> ToolOutput:
    conds: list[ColumnElement[bool]] = []
    if args.status:
        conds.append(AlertRow.status == args.status.value)
    if args.min_severity:
        conds.append(AlertRow.severity.in_(_severity_at_least(args.min_severity)))
    if args.category:
        conds.append(AlertRow.category == args.category.value)
    if args.source_ip:
        conds.append(AlertRow.source_ip == args.source_ip)
    if args.incident_id:
        conds.append(AlertRow.incident_id == args.incident_id)
    if args.rule_id:
        conds.append(AlertRow.rule_id == args.rule_id)
    if args.min_ai_score is not None:
        conds.append(AlertRow.ai_score >= args.min_ai_score)
    since, until = args.window()
    if since:
        conds.append(AlertRow.last_seen >= since)
    if until:
        conds.append(AlertRow.last_seen <= until)
    total = await _count(session, AlertRow, conds)
    stmt = select(AlertRow).where(*conds).order_by(AlertRow.last_seen.desc()).limit(args.limit)
    rows = (await session.execute(stmt)).scalars().all()
    return ToolOutput(
        data={"total": total, "returned": len(rows), "items": [alert_brief(r) for r in rows]},
        summary=f"{len(rows)} of {total} alerts",
    )


@_register(
    "get_incident",
    "Get one incident by id with its triage verdict, up to 25 linked alerts and up to 10 response actions.",
    IncidentIdInput,
)
async def get_incident(session: AsyncSession, args: IncidentIdInput) -> ToolOutput:
    row = await session.get(IncidentRow, args.incident_id)
    if row is None:
        raise ToolError(f"incident {args.incident_id} not found")
    alerts = (
        (
            await session.execute(
                select(AlertRow)
                .where(AlertRow.incident_id == row.id)
                .order_by(AlertRow.last_seen.desc())
                .limit(MAX_INCIDENT_ALERTS)
            )
        )
        .scalars()
        .all()
    )
    actions = (
        (
            await session.execute(
                select(ResponseActionRow)
                .where(ResponseActionRow.incident_id == row.id)
                .order_by(ResponseActionRow.created_at.desc())
                .limit(MAX_INCIDENT_ACTIONS)
            )
        )
        .scalars()
        .all()
    )
    return ToolOutput(
        data={
            "incident": incident_brief(row, detail=True),
            "alerts": [alert_brief(a) for a in alerts],
            "actions": [action_brief(a) for a in actions],
        },
        summary=f"incident {row.id} ({row.severity}) with {len(alerts)} alerts, {len(actions)} actions",
    )


@_register(
    "list_incidents",
    "List incidents (most recently active first) filtered by status, minimum severity, actor type "
    "(e.g. ai_agent) and time window (on last_seen).",
    ListIncidentsInput,
)
async def list_incidents(session: AsyncSession, args: ListIncidentsInput) -> ToolOutput:
    conds: list[ColumnElement[bool]] = []
    if args.status:
        conds.append(IncidentRow.status == args.status.value)
    if args.min_severity:
        conds.append(IncidentRow.severity.in_(_severity_at_least(args.min_severity)))
    if args.actor_type:
        conds.append(IncidentRow.actor_type == args.actor_type.value)
    since, until = args.window()
    if since:
        conds.append(IncidentRow.last_seen >= since)
    if until:
        conds.append(IncidentRow.last_seen <= until)
    total = await _count(session, IncidentRow, conds)
    stmt = select(IncidentRow).where(*conds).order_by(IncidentRow.last_seen.desc()).limit(args.limit)
    rows = (await session.execute(stmt)).scalars().all()
    return ToolOutput(
        data={"total": total, "returned": len(rows), "items": [incident_brief(r) for r in rows]},
        summary=f"{len(rows)} of {total} incidents",
    )


@_register(
    "get_session",
    "Get one actor session (source IP + client fingerprint, bounded by idle time) with its AI-agent attribution "
    "features and its most recent events in chronological order (gap_ms = time since the previous event).",
    SessionInput,
)
async def get_session(session: AsyncSession, args: SessionInput) -> ToolOutput:
    row = await session.get(ActorSessionRow, args.session_id)
    if row is None:
        raise ToolError(f"session {args.session_id} not found")
    conds = [EventRow.session_id == row.id]
    total = await _count(session, EventRow, conds)
    recent = (
        (
            await session.execute(
                select(EventRow).where(*conds).order_by(EventRow.timestamp.desc()).limit(args.event_limit)
            )
        )
        .scalars()
        .all()
    )
    events: list[dict[str, Any]] = []
    prev: datetime | None = None
    for ev in reversed(recent):
        brief = event_brief(ev)
        ts = ensure_utc(ev.timestamp)
        if prev is not None:
            brief["gap_ms"] = round((ts - prev).total_seconds() * 1000, 1)
        prev = ts
        events.append(brief)
    return ToolOutput(
        data={"session": session_brief(row), "event_count": total, "events": events},
        summary=f"session {row.id} (ai_score {row.ai_score:.2f}) with {len(events)} of {total} events",
    )


@_register(
    "top_sources",
    "Rank source IPs by event volume within the last N hours, with error counts, distinct paths, alert counts "
    "and the highest AI-agent session score per source.",
    TopSourcesInput,
)
async def top_sources(session: AsyncSession, args: TopSourcesInput) -> ToolOutput:
    since = utcnow() - timedelta(hours=args.hours)
    conds: list[ColumnElement[bool]] = [EventRow.timestamp >= since, EventRow.source_ip.is_not(None)]
    if args.kind:
        conds.append(EventRow.kind == args.kind.value)
    n = func.count().label("n")
    stmt = (
        select(
            EventRow.source_ip,
            n,
            func.sum(case((EventRow.http_status >= 400, 1), else_=0)).label("errors"),
            func.count(func.distinct(EventRow.http_path)).label("paths"),
            func.min(EventRow.timestamp).label("first_seen"),
            func.max(EventRow.timestamp).label("last_seen"),
        )
        .where(*conds)
        .group_by(EventRow.source_ip)
        .order_by(n.desc())
        .limit(args.limit)
    )
    rows = (await session.execute(stmt)).all()
    ips = [r.source_ip for r in rows]
    alert_counts: dict[str, int] = {}
    ai_scores: dict[str, float] = {}
    if ips:
        for ip, cnt in (
            await session.execute(
                select(AlertRow.source_ip, func.count())
                .where(AlertRow.source_ip.in_(ips), AlertRow.last_seen >= since)
                .group_by(AlertRow.source_ip)
            )
        ).all():
            if ip:
                alert_counts[ip] = int(cnt)
        for ip, score in (
            await session.execute(
                select(ActorSessionRow.source_ip, func.max(ActorSessionRow.ai_score))
                .where(ActorSessionRow.source_ip.in_(ips), ActorSessionRow.last_seen >= since)
                .group_by(ActorSessionRow.source_ip)
            )
        ).all():
            if ip and score is not None:
                ai_scores[ip] = float(score)
    items = [
        _prune(
            {
                "source_ip": r.source_ip,
                "events": int(r.n),
                "http_errors": int(r.errors or 0),
                "distinct_paths": int(r.paths or 0),
                "first_seen": _iso(r.first_seen),
                "last_seen": _iso(r.last_seen),
                "alerts": alert_counts.get(r.source_ip, 0),
                "max_session_ai_score": ai_scores.get(r.source_ip),
            }
        )
        for r in rows
    ]
    return ToolOutput(
        data={"window_hours": args.hours, "since": _iso(since), "items": items},
        summary=f"top {len(items)} sources over {args.hours}h",
    )


@_register(
    "lookup_vuln",
    "Look up a vulnerability (CVE / GHSA / JVNDB id) in TOKIWA's local intel database: CVSS, EPSS, CISA KEV "
    "status, description, matched assets and advisories. found=false means it is not in the local database.",
    LookupVulnInput,
)
async def lookup_vuln(session: AsyncSession, args: LookupVulnInput) -> ToolOutput:
    vid = _normalize_vuln_id(args.vuln_id)
    row = await session.get(VulnRow, vid)
    if row is None and vid != args.vuln_id:
        row = await session.get(VulnRow, args.vuln_id)
    if row is None:
        return ToolOutput(
            data={
                "found": False,
                "vuln_id": vid,
                "note": "not in TOKIWA's local intel database (feeds may not have synced it yet)",
            },
            summary=f"{vid} not in local intel",
        )
    matches = (
        await session.execute(
            select(VulnMatchRow, AssetRow.name)
            .outerjoin(AssetRow, AssetRow.id == VulnMatchRow.asset_id)
            .where(VulnMatchRow.vuln_id == row.id)
            .order_by(VulnMatchRow.created_at.desc())
            .limit(20)
        )
    ).all()
    advisories: list[dict[str, Any]] = []
    recent_adv = (
        (await session.execute(select(AdvisoryRow).order_by(AdvisoryRow.created_at.desc()).limit(500)))
        .scalars()
        .all()
    )
    for adv in recent_adv:  # vuln_ids is a JSON list: filter in Python (portable across SQLite/PostgreSQL)
        if row.id in (adv.vuln_ids or []):
            advisories.append(
                _prune(
                    {
                        "id": adv.id,
                        "title": _clip(adv.title, 200),
                        "priority": adv.priority,
                        "status": adv.status,
                        "created_at": _iso(adv.created_at),
                    }
                )
            )
            if len(advisories) >= 5:
                break
    return ToolOutput(
        data={
            "found": True,
            "vuln": vuln_brief(row),
            "matches": [
                _prune(
                    {
                        "match_id": m.id,
                        "asset_id": m.asset_id,
                        "asset_name": name,
                        "status": m.status,
                        "confidence": m.confidence,
                        "reason": _clip(m.reason, 300),
                    }
                )
                for m, name in matches
            ],
            "advisories": advisories,
        },
        summary=f"{row.id}: kev={row.kev}, {len(matches)} asset matches",
    )


@_register(
    "list_vuln_matches",
    "List vulnerability-to-asset matches (KEV first, then by EPSS), optionally only KEV, by status, minimum "
    "EPSS, asset or vulnerability.",
    ListVulnMatchesInput,
)
async def list_vuln_matches(session: AsyncSession, args: ListVulnMatchesInput) -> ToolOutput:
    conds: list[ColumnElement[bool]] = []
    if args.status:
        conds.append(VulnMatchRow.status == args.status.value)
    if args.kev_only:
        conds.append(VulnRow.kev.is_(True))
    if args.min_epss is not None:
        conds.append(VulnRow.epss >= args.min_epss)
    if args.asset_id:
        conds.append(VulnMatchRow.asset_id == args.asset_id)
    if args.vuln_id:
        conds.append(VulnMatchRow.vuln_id == _normalize_vuln_id(args.vuln_id))
    base = (
        select(VulnMatchRow, VulnRow, AssetRow)
        .outerjoin(VulnRow, VulnRow.id == VulnMatchRow.vuln_id)
        .outerjoin(AssetRow, AssetRow.id == VulnMatchRow.asset_id)
        .where(*conds)
    )
    count_stmt = (
        select(func.count(VulnMatchRow.id))
        .select_from(VulnMatchRow)
        .outerjoin(VulnRow, VulnRow.id == VulnMatchRow.vuln_id)
        .where(*conds)
    )
    total = int((await session.execute(count_stmt)).scalar_one())
    rows = (
        await session.execute(
            base.order_by(
                func.coalesce(VulnRow.kev, False).desc(),
                func.coalesce(VulnRow.epss, 0.0).desc(),
                VulnMatchRow.created_at.desc(),
            ).limit(args.limit)
        )
    ).all()
    items = []
    for m, v, a in rows:
        items.append(
            _prune(
                {
                    "match_id": m.id,
                    "vuln_id": m.vuln_id,
                    "asset_id": m.asset_id,
                    "asset_name": a.name if a else None,
                    "asset_criticality": a.criticality if a else None,
                    "software": _pick(m.software, ("vendor", "product", "version", "cpe")),
                    "status": m.status,
                    "confidence": m.confidence,
                    "reason": _clip(m.reason, 300),
                    "created_at": _iso(m.created_at),
                    "kev": v.kev if v else None,
                    "epss": v.epss if v else None,
                    "cvss_score": v.cvss_score if v else None,
                    "severity": v.severity if v else None,
                    "vuln_title": _clip(v.title, 200) if v else None,
                }
            )
        )
    return ToolOutput(
        data={"total": total, "returned": len(items), "items": items},
        summary=f"{len(items)} of {total} vulnerability matches",
    )


@_register(
    "get_asset",
    "Find assets by exact id, by name/hostname substring, or by assigned IP. Returns up to 5 assets with "
    "software inventory and open vulnerability matches.",
    GetAssetInput,
)
async def get_asset(session: AsyncSession, args: GetAssetInput) -> ToolOutput:
    assets: list[AssetRow] = []
    if args.asset_id:
        row = await session.get(AssetRow, args.asset_id)
        if row is not None:
            assets.append(row)
    else:
        conds: list[ColumnElement[bool]] = []
        if args.name:
            conds.append(
                or_(
                    AssetRow.name.icontains(args.name, autoescape=True),
                    AssetRow.hostname.icontains(args.name, autoescape=True),
                )
            )
        stmt = select(AssetRow).where(*conds).order_by(AssetRow.name).limit(2000 if args.ip else 50)
        for row in (await session.execute(stmt)).scalars().all():
            # ips is a JSON list: membership is checked in Python (portable across SQLite/PostgreSQL)
            if args.ip and args.ip not in (row.ips or []):
                continue
            assets.append(row)
            if len(assets) >= MAX_ASSET_RESULTS:
                break
    if not assets:
        raise ToolError("no matching asset")
    out = []
    for a in assets:
        brief = asset_brief(a)
        matches = (
            await session.execute(
                select(VulnMatchRow, VulnRow.kev, VulnRow.epss)
                .outerjoin(VulnRow, VulnRow.id == VulnMatchRow.vuln_id)
                .where(VulnMatchRow.asset_id == a.id, VulnMatchRow.status == MatchStatus.OPEN.value)
                .order_by(VulnMatchRow.created_at.desc())
                .limit(10)
            )
        ).all()
        brief["open_vuln_matches"] = [
            _prune({"vuln_id": m.vuln_id, "kev": kev, "epss": epss, "confidence": m.confidence})
            for m, kev, epss in matches
        ]
        out.append(brief)
    return ToolOutput(data={"items": out}, summary=f"{len(out)} asset(s)")


@_register(
    "list_actions",
    "List response actions (block/rate-limit/tarpit/deceive proposals and their approval status), newest first. "
    "Read-only: actions are proposed and approved by humans in the Response page, never by the copilot.",
    ListActionsInput,
)
async def list_actions(session: AsyncSession, args: ListActionsInput) -> ToolOutput:
    conds: list[ColumnElement[bool]] = []
    if args.status:
        conds.append(ResponseActionRow.status == args.status.value)
    if args.action_type:
        conds.append(ResponseActionRow.action_type == args.action_type.value)
    if args.incident_id:
        conds.append(ResponseActionRow.incident_id == args.incident_id)
    if args.target:
        conds.append(ResponseActionRow.target == args.target)
    total = await _count(session, ResponseActionRow, conds)
    stmt = (
        select(ResponseActionRow)
        .where(*conds)
        .order_by(ResponseActionRow.created_at.desc())
        .limit(args.limit)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return ToolOutput(
        data={"total": total, "returned": len(rows), "items": [action_brief(r) for r in rows]},
        summary=f"{len(rows)} of {total} response actions",
    )
