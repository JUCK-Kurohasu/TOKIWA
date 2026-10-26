"""Sigma field names / logsources -> TOKIWA :class:`~tokiwa.schemas.events.Event` attributes.

Sigma rules are written against log-format specific field names (W3C/IIS ``cs-uri-query``, proxy ``c-uri``,
Sysmon ``CommandLine``) or ECS names (``url.path``, ``source.ip``). TOKIWA has one normalized event model, so
every supported name is mapped to a *resolver* (``Event -> value | list[value] | None``).

Resolution order for a field name (case-insensitive):

1. the alias table below (Sigma conventions + ECS + TOKIWA short names);
2. a dotted path into the Event model, e.g. ``http.headers.x-forwarded-for``, ``labels.env``,
   ``source.geo_country``, ``llm_app.tool_names``. Dict-typed attributes (headers, labels, raw) accept any key.

Unknown names are a validation error: a rule that references a field TOKIWA never produces can never fire,
and catching that early matters for LLM-proposed rules.

URI-ish fields (path / query / full URI / body) yield both the raw value and its URL-decoded form (up to two
rounds) so a rule written as ``|contains: '../'`` also matches ``%2e%2e%2f``. This is a deliberate deviation
from strict "match the log line as-is" Sigma semantics, chosen because attack payloads are routinely encoded.
"""

from __future__ import annotations

import json
import types
import typing
from collections.abc import Callable
from posixpath import splitext
from typing import Any
from urllib.parse import unquote, unquote_plus

from pydantic import BaseModel

from tokiwa.schemas.events import Event, EventKind

Resolver = Callable[[Event], Any]

# ---------------------------------------------------------------------------------------------------------
# helpers


def _decoded_variants(value: str | None, *, plus: bool) -> Any:
    """Raw value plus up to two rounds of URL-decoding (only when decoding changes something)."""
    if value is None:
        return None
    if "%" not in value and not (plus and "+" in value):
        return value
    out = [value]
    cur = value
    for _ in range(2):
        nxt = unquote_plus(cur) if plus else unquote(cur)
        if nxt == cur:
            break
        out.append(nxt)
        cur = nxt
    return out


def _http_attr(attr: str) -> Resolver:
    def resolve(e: Event) -> Any:
        return getattr(e.http, attr) if e.http is not None else None

    return resolve


def _header(name: str) -> Resolver:
    def resolve(e: Event) -> Any:
        if e.http is None:
            return None
        return e.http.headers.get(name)

    return resolve


def _path(e: Event) -> Any:
    return _decoded_variants(e.http.path, plus=False) if e.http is not None else None


def _query(e: Event) -> Any:
    return _decoded_variants(e.http.query, plus=True) if e.http is not None else None


def _uri(e: Event) -> Any:
    """``path?query`` (no scheme/host), as webserver logs usually record the request target."""
    if e.http is None or e.http.path is None:
        return None
    raw = e.http.path + (f"?{e.http.query}" if e.http.query else "")
    return _decoded_variants(raw, plus=True)


def _url_full(e: Event) -> Any:
    h = e.http
    if h is None or h.path is None:
        return None
    prefix = f"{h.scheme or 'http'}://{h.host}" if h.host else ""
    return prefix + h.path + (f"?{h.query}" if h.query else "")


def _uri_extension(e: Event) -> Any:
    if e.http is None or not e.http.path:
        return None
    ext = splitext(e.http.path)[1]
    return ext.lstrip(".") or None


def _user_agent(e: Event) -> Any:
    if e.http is None:
        return None
    return e.http.user_agent or e.http.headers.get("user-agent")


def _referrer(e: Event) -> Any:
    if e.http is None:
        return None
    return e.http.referrer or e.http.headers.get("referer")


def _body(e: Event) -> Any:
    if e.http is None:
        return None
    return _decoded_variants(e.http.request_body, plus=True)


def _is_llm_app_path(path: str | None) -> bool:
    if not path:
        return False
    from tokiwa.config import get_settings  # read lazily: compiled rules stay settings-independent

    for p in get_settings().detection.llm_app_paths:
        base = p.rstrip("/")
        if path in (p, base) or path.startswith(base + "/"):
            return True
    return False


def _prompt(e: Event) -> Any:
    """LLM prompt: ``llm_app.prompt``; for HTTP events to a protected LLM app path, the request body."""
    if e.llm_app is not None and e.llm_app.prompt is not None:
        return e.llm_app.prompt
    if e.http is not None and e.http.request_body and _is_llm_app_path(e.http.path):
        return e.http.request_body
    return None


def _endpoint(side: str, attr: str) -> Resolver:
    def resolve(e: Event) -> Any:
        ep = getattr(e, side)
        return getattr(ep, attr) if ep is not None else None

    return resolve


def _sub(obj: str, attr: str) -> Resolver:
    def resolve(e: Event) -> Any:
        o = getattr(e, obj)
        return getattr(o, attr) if o is not None else None

    return resolve


def _process(attr: str) -> Resolver:
    """Process info: top-level ``process`` or the one attached to a network flow."""

    def resolve(e: Event) -> Any:
        if e.process is not None:
            return getattr(e.process, attr)
        if e.network is not None and e.network.process is not None:
            return getattr(e.network.process, attr)
        return None

    return resolve


def _host_name(e: Event) -> Any:
    return e.host.name if e.host is not None else None


# ---------------------------------------------------------------------------------------------------------
# alias table (keys are lower-case)

_ALIASES: dict[str, Resolver] = {}


def _alias(resolver: Resolver, *names: str) -> None:
    for n in names:
        _ALIASES[n.lower()] = resolver


# HTTP request line
_alias(_uri, "c-uri", "cs-uri", "url.original", "uri", "request")
_alias(_url_full, "url.full")
_alias(_path, "cs-uri-stem", "c-uri-stem", "url.path", "http.path", "uri_path", "path")
_alias(_query, "cs-uri-query", "c-uri-query", "url.query", "http.query", "uri_query", "query")
_alias(_uri_extension, "c-uri-extension", "url.extension")
_alias(_http_attr("method"), "cs-method", "http.request.method", "http.method", "method")
_alias(_http_attr("status"), "sc-status", "http.response.status_code", "http.status", "status")
_alias(
    _user_agent, "c-useragent", "cs-user-agent", "cs(user-agent)", "user_agent.original", "http.user_agent"
)
_alias(_user_agent, "useragent", "user_agent")
_alias(_referrer, "cs-referer", "cs-referrer", "cs(referer)", "http.request.referrer", "http.referrer")
_alias(_referrer, "referer", "referrer")
_alias(_header("cookie"), "cs-cookie", "cs(cookie)")
_alias(_http_attr("host"), "cs-host", "r-dns", "url.domain", "http.host", "destination.domain")
_alias(_body, "request_body", "http.request.body.content", "http.request_body", "cs-body", "body")
_alias(_http_attr("content_type"), "cs-content-type", "http.request.mime_type", "http.content_type")
_alias(_http_attr("request_body_size"), "cs-bytes", "http.request.body.bytes", "http.request_body_size")
_alias(_http_attr("response_size"), "sc-bytes", "http.response.body.bytes", "http.response_size")
_alias(_http_attr("response_content_type"), "sc-content-type", "http.response.mime_type")
_alias(_http_attr("http_version"), "cs-version", "http.version", "http.http_version")
_alias(_http_attr("duration_ms"), "time-taken", "http.duration_ms")

# endpoints
_alias(_endpoint("source", "ip"), "c-ip", "src_ip", "source.ip", "sourceip", "clientip", "client_ip")
_alias(_endpoint("source", "port"), "c-port", "src_port", "source.port", "sourceport")
_alias(_endpoint("destination", "ip"), "s-ip", "dst_ip", "dest_ip", "destination.ip", "destinationip")
_alias(_endpoint("destination", "port"), "s-port", "dst_port", "dest_port", "destination.port")
_alias(_endpoint("destination", "port"), "destinationport")
_alias(_endpoint("source", "geo_country"), "source.geo.country_iso_code")
_alias(_endpoint("source", "asn"), "source.as.number")
_alias(_endpoint("source", "asn_org"), "source.as.organization.name")

# LLM application prompts
_alias(_prompt, "prompt", "llm.prompt", "llm_app.prompt", "gen_ai.prompt")
_alias(_sub("llm_app", "app"), "llm.app", "llm_app.app", "app")
_alias(_sub("llm_app", "model"), "llm.model", "llm_app.model", "gen_ai.request.model")
_alias(_sub("llm_app", "role"), "llm.role", "llm_app.role")
_alias(_sub("llm_app", "tool_names"), "llm.tool_names", "llm_app.tool_names", "tool_names")

# IDS
_alias(_sub("ids", "signature"), "signature", "alert.signature", "ids.signature", "rule.name")
_alias(_sub("ids", "signature_id"), "signature_id", "alert.signature_id", "ids.signature_id", "rule.id")
_alias(_sub("ids", "category"), "alert.category", "ids.category")

# processes (Sysmon-ish + ECS)
_alias(_process("exe"), "image", "process.executable", "process.exe")
_alias(_process("name"), "process.name", "processname")
_alias(_process("cmdline"), "commandline", "process.command_line", "process.cmdline")
_alias(_process("username"), "user", "user.name", "process.username")
_alias(_process("pid"), "processid", "process.pid")

# network flows
_alias(_sub("network", "transport"), "network.transport")
_alias(_sub("network", "protocol"), "network.protocol", "app_proto")
_alias(_sub("network", "direction"), "network.direction", "direction")

# deception
_alias(_sub("deception", "asset_kind"), "deception.asset_kind")
_alias(_sub("deception", "token"), "deception.token")

# event metadata
_alias(lambda e: e.dataset, "dataset", "event.dataset")
_alias(lambda e: e.kind.value, "kind", "tokiwa.kind")
_alias(lambda e: e.message, "message", "msg")
_alias(lambda e: e.sensor_id, "sensor_id", "observer.name")
_alias(lambda e: e.session_id, "session_id")
_alias(lambda e: e.asset_id, "asset_id")
_alias(lambda e: e.tags, "tags")
_alias(_host_name, "host.name", "hostname", "computer", "computername")


# ---------------------------------------------------------------------------------------------------------
# dotted-path fallback


def _unwrap(annotation: Any) -> Any:
    """``X | None`` -> ``X`` (keeps lists/dicts intact)."""
    origin = typing.get_origin(annotation)
    if origin is typing.Union or origin is types.UnionType:
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        return args[0] if len(args) == 1 else annotation
    return annotation


def _is_model(t: Any) -> bool:
    return isinstance(t, type) and issubclass(t, BaseModel)


def _path_resolver(field: str) -> Resolver | None:
    """Validate ``a.b.c`` against the Event model at compile time and return a resolver (or None)."""
    parts = field.split(".")
    if not all(parts):
        return None
    model: Any = Event
    steps: list[tuple[str, str]] = []  # (op, name) with op in {"attr", "key", "each"}
    i = 0
    while i < len(parts):
        name = parts[i]
        if not _is_model(model) or name not in model.model_fields:
            return None
        steps.append(("attr", name))
        ann = _unwrap(model.model_fields[name].annotation)
        origin = typing.get_origin(ann)
        i += 1
        if i == len(parts):
            break
        if _is_model(ann):
            model = ann
        elif origin is dict:
            steps.append(("key", ".".join(parts[i:])))  # header names may contain dots? keep the rest
            break
        elif origin is list and _is_model(_unwrap(typing.get_args(ann)[0])):
            steps.append(("each", ""))
            model = _unwrap(typing.get_args(ann)[0])
        else:
            return None  # scalar with trailing path segments

    def resolve(e: Event) -> Any:
        cur: Any = [e]
        many = False
        for op, name in steps:
            nxt: list[Any] = []
            for obj in cur:
                if obj is None:
                    continue
                if op == "attr":
                    nxt.append(getattr(obj, name, None))
                elif op == "key" and isinstance(obj, dict):
                    val = obj.get(name)
                    if val is None:
                        val = obj.get(name.lower())
                    nxt.append(val)
                elif op == "each" and isinstance(obj, list):
                    many = True
                    nxt.extend(obj)
            cur = nxt
        values = [v for v in cur if v is not None]
        if not values:
            return None
        return values if many or len(values) > 1 else values[0]

    return resolve


def resolve_field(field: str) -> Resolver | None:
    """Return a resolver for a Sigma field name, or None when TOKIWA has no such field."""
    key = field.strip()
    if not key:
        return None
    res = _ALIASES.get(key.lower())
    if res is not None:
        return res
    return _path_resolver(key) or _path_resolver(key.lower())


def known_aliases() -> list[str]:
    return sorted(_ALIASES)


# ---------------------------------------------------------------------------------------------------------
# keyword (full-text) search corpus


def keyword_corpus(e: Event) -> list[str]:
    """Strings searched by Sigma keyword selections (values without a field name)."""
    out: list[str] = []
    if e.message:
        out.append(e.message)
    h = e.http
    if h is not None:
        for v, plus in (
            (h.path, False),
            (h.query, True),
            (h.request_body, True),
            (h.user_agent, False),
            (h.referrer, False),
        ):
            if v:
                dv = _decoded_variants(v, plus=plus)
                out.extend(dv if isinstance(dv, list) else [dv])
    if e.llm_app is not None and e.llm_app.prompt:
        out.append(e.llm_app.prompt)
    if e.ids is not None and e.ids.signature:
        out.append(e.ids.signature)
    proc = e.process or (e.network.process if e.network is not None else None)
    if proc is not None and proc.cmdline:
        out.append(proc.cmdline)
    if e.deception is not None and e.deception.detail:
        out.append(e.deception.detail)
    return out


def stringify(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, dict | list):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


# ---------------------------------------------------------------------------------------------------------
# logsource -> event kinds

_HTTP = frozenset({EventKind.HTTP})
_CATEGORY_KINDS: dict[str, frozenset[EventKind]] = {
    "webserver": _HTTP,
    "proxy": _HTTP,
    "web": _HTTP,
    "http": _HTTP,
    # Prompts arrive either as llm_app events (app hooks) or as HTTP bodies to protected LLM app paths.
    "llm_app": frozenset({EventKind.LLM_APP, EventKind.HTTP}),
    "llm": frozenset({EventKind.LLM_APP, EventKind.HTTP}),
    "network_connection": frozenset({EventKind.CONNECTION}),
    "firewall": frozenset({EventKind.CONNECTION}),
    "dns": frozenset({EventKind.DNS}),
    "dns_query": frozenset({EventKind.DNS}),
    "process_creation": frozenset({EventKind.PROCESS}),
    "authentication": frozenset({EventKind.AUTH}),
    "ids": frozenset({EventKind.IDS_ALERT}),
    "deception": frozenset({EventKind.DECEPTION}),
    "port_change": frozenset({EventKind.PORT_CHANGE}),
}
_TOKIWA_SERVICES: dict[str, frozenset[EventKind]] = {k.value: frozenset({k}) for k in EventKind}
_TOKIWA_SERVICES["gate"] = _HTTP


def supported_categories() -> list[str]:
    return sorted(_CATEGORY_KINDS)


def logsource_kinds(logsource: dict[str, Any]) -> frozenset[EventKind] | None:
    """Event kinds a rule applies to, or None when the logsource is not something TOKIWA ingests.

    ``category`` decides when present (``product`` is informational, e.g. nginx/apache for webserver).
    Without a category, ``product: tokiwa`` + ``service: <event kind>`` selects a kind (no service = all).
    """
    category = str(logsource.get("category") or "").strip().lower()
    product = str(logsource.get("product") or "").strip().lower()
    service = str(logsource.get("service") or "").strip().lower()
    if category:
        return _CATEGORY_KINDS.get(category)
    if product == "tokiwa":
        if not service:
            return frozenset(EventKind)
        return _TOKIWA_SERVICES.get(service)
    return None
