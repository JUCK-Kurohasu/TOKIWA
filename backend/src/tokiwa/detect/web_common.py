"""Shared helpers for the web (HTTP) detectors ``tokiwa.detect.detectors.web_*`` (detect-web, FR-05).

Why this module exists:

* ~15 detectors inspect the same request. Decoding/normalising it once per event (cached in
  ``ctx.scratch``; the engine runs every detector on event N before moving to event N+1) keeps the whole
  signature family well under 1 ms/event.
* Attackers - and LLM agents that mutate a payload after a WAF 403 - lean on encoding tricks: double/mixed
  percent-encoding, ``%uXXXX``, overlong UTF-8 (``%c0%ae``), HTML entities, ``\\u003c`` escapes, SQL
  ``/**/`` comments, full-width characters. Signatures are written against normalised *views* so one
  pattern covers all spellings.
* Every regex is compiled through :func:`rx` so a single test can assert that none of them backtracks
  catastrophically (ReDoS) on adversarial input.

Rules for signature authors (enforced by tests/detect/test_web_perf.py):

* bounded repetition only (``{0,N}``), never ``*``/``+`` on a class that overlaps its neighbour;
* on the ``norm`` view whitespace is already collapsed to one space, so write `` ?`` not ``\\s*``;
* no backreferences (patterns of one detector are OR-ed into a single prefilter regex);
* lowercase patterns for the ``lower``/``norm``/``value``/``raw`` views (those views are lower-cased).

Views of a :class:`Target`:

``raw``      lower-cased, undecoded (to see *encoded* evasions such as ``%2e%2e%2f``)
``decoded``  fully decoded, case preserved (base64 markers such as ``rO0AB`` are case-sensitive)
``lower``    decoded + NFKC + lower-cased, whitespace preserved (shell newlines matter)
``norm``     ``lower`` + SQL comments removed + whitespace collapsed (SQLi/XSS/SSTI)
``value``    like ``lower`` but only the value part of a ``name=value`` parameter
"""

from __future__ import annotations

import html
import json
import logging
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, ClassVar, Literal
from urllib.parse import unquote, unquote_plus

from tokiwa.config import Settings, WebDetectionSettings
from tokiwa.detect.base import Detector
from tokiwa.detect.context import DetectionContext
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind

log = logging.getLogger(__name__)

View = Literal["raw", "decoded", "lower", "norm", "value"]

# --- inspection locations -------------------------------------------------------------------------------
PATH = "path"
QUERY = "query"
BODY = "body"  # body parameters (form / JSON leaves / multipart parts) or the whole unstructured body
BODY_RAW = "body_raw"  # the whole body, only present when it was also split into parameters
HEADER = "header"  # headers commonly reflected/logged by apps (UA, Referer, X-Forwarded-For, ...)
HEADER_OTHER = "header_other"  # every other header (Log4Shell / OGNL style payloads hide here)
COOKIE = "cookie"
FILENAME = "filename"  # multipart upload file names

INJECTION_LOCATIONS = frozenset({PATH, QUERY, BODY, HEADER, COOKIE, FILENAME})
PARAM_LOCATIONS = frozenset({QUERY, BODY, COOKIE})
WHOLE_BODY_LOCATIONS = frozenset({BODY, BODY_RAW})
ALL_LOCATIONS = frozenset({PATH, QUERY, BODY, BODY_RAW, HEADER, HEADER_OTHER, COOKIE, FILENAME})

INJECTABLE_HEADERS = frozenset(
    {
        "user-agent",
        "referer",
        "origin",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-real-ip",
        "x-client-ip",
        "true-client-ip",
        "x-originating-ip",
        "client-ip",
        "forwarded",
        "x-api-version",
        "x-wap-profile",
    }
)
# Never inspected as payload carriers: credentials (redacted anyway) and pure framing headers.
_SKIP_HEADERS = frozenset({"authorization", "proxy-authorization", "content-length", "connection"})

MAX_DECODE_ROUNDS = 3
MAX_PARAMS = 64
MAX_HEADERS = 64
MAX_JSON_LEAVES = 128
MAX_JSON_DEPTH = 16
MAX_MULTIPART_PARTS = 32
MAX_FRAGMENT = 200

_SCRATCH_KEY = "web.view"

# --- regex registry -------------------------------------------------------------------------------------
_PATTERNS: list[tuple[str, re.Pattern[str]]] = []


def rx(pattern: str, name: str = "") -> re.Pattern[str]:
    """Compile and register a pattern so the ReDoS test covers it."""
    compiled = re.compile(pattern)
    _PATTERNS.append((name or pattern[:60], compiled))
    return compiled


def registered_patterns() -> list[tuple[str, re.Pattern[str]]]:
    return list(_PATTERNS)


# --- settings -------------------------------------------------------------------------------------------


def web_settings(settings: Settings) -> WebDetectionSettings:
    cfg = getattr(settings.detection, "web", None)
    return cfg if isinstance(cfg, WebDetectionSettings) else WebDetectionSettings()


@lru_cache(maxsize=16)
def compile_user_regex(pattern: str, fallback: str) -> re.Pattern[str]:
    """Compile an operator-supplied regex (config). Invalid/oversized patterns fall back to the default.

    User patterns are matched only against short, length-capped strings (paths), which bounds the damage of a
    poorly written expression.
    """
    if len(pattern) <= 2000:
        try:
            return re.compile(pattern, re.IGNORECASE)
        except re.error:
            log.warning("invalid regex in detection.web config, using default: %r", pattern[:120])
    return re.compile(fallback, re.IGNORECASE)


# --- decoding / normalisation ---------------------------------------------------------------------------
_PCT_U = rx(r"%[uU]([0-9a-fA-F]{4})", "decode.pct_u")
_OVERLONG2 = rx(r"%[cC]([01])%([89abAB][0-9a-fA-F])", "decode.overlong2")
_OVERLONG3 = rx(r"%[eE]0%([89][0-9a-fA-F])%([89abAB][0-9a-fA-F])", "decode.overlong3")
_BS_ESC = rx(r"\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))", "decode.backslash")
_WS = rx(r"\s+", "norm.ws")
_CTRL = rx(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "snippet.ctrl")


def _sub_pct_u(m: re.Match[str]) -> str:
    return chr(int(m.group(1), 16))


def _sub_overlong2(m: re.Match[str]) -> str:
    # %c0%ae -> "." / %c0%af -> "/" / %c1%9c -> "\" (non-shortest UTF-8 forms, rejected by sane decoders)
    return chr(((int(m.group(1)) & 0x1F) << 6) | (int(m.group(2), 16) & 0x3F))


def _sub_overlong3(m: re.Match[str]) -> str:
    return chr(((int(m.group(1), 16) & 0x3F) << 6) | (int(m.group(2), 16) & 0x3F))


def _sub_bs(m: re.Match[str]) -> str:
    return chr(int(m.group(1) or m.group(2), 16))


def decode(text: str, *, plus: bool = False, rounds: int = MAX_DECODE_ROUNDS) -> str:
    """Iteratively undo URL/HTML/JS escaping until the string is stable (bounded rounds).

    ``plus`` turns ``+`` into a space - only in the first round and only for form-encoded contexts, so a
    double-encoded ``%2B`` stays a plus sign.
    """
    s = text
    for i in range(rounds):
        prev = s
        if "%" in s:
            if "%u" in s or "%U" in s:
                s = _PCT_U.sub(_sub_pct_u, s)
            s = _OVERLONG3.sub(_sub_overlong3, s)
            s = _OVERLONG2.sub(_sub_overlong2, s)
            s = unquote_plus(s) if plus and i == 0 else unquote(s)
        elif plus and i == 0 and "+" in s:
            s = s.replace("+", " ")
        if "&" in s:
            s = html.unescape(s)
        if "\\" in s:
            s = _BS_ESC.sub(_sub_bs, s)
        if s == prev:
            break
    return s


def strip_sql_comments(s: str) -> str:
    """Replace ``/* ... */`` with a space in linear time. MySQL ``/*!50000 ... */`` keeps its content."""
    if "/*" not in s:
        return s
    out: list[str] = []
    i = 0
    while True:
        j = s.find("/*", i)
        if j < 0:
            out.append(s[i:])
            break
        k = s.find("*/", j + 2)
        if k < 0:
            out.append(s[i:])
            break
        out.append(s[i:j])
        inner = s[j + 2 : k]
        if inner.startswith("!"):
            out.append(" " + inner[1:].lstrip("0123456789") + " ")
        else:
            out.append(" ")
        i = k + 2
    return "".join(out)


def to_lower(decoded: str) -> str:
    if not decoded.isascii():
        decoded = unicodedata.normalize("NFKC", decoded)
    return decoded.lower()


def normalize(lower: str) -> str:
    return _WS.sub(" ", strip_sql_comments(lower)).strip()


def snippet(text: str, start: int, end: int, limit: int = MAX_FRAGMENT) -> str:
    """Matched fragment with some context, printable, JSON-safe and at most ``limit`` chars."""
    if end - start >= limit:
        frag = text[start : start + limit]
    else:
        pad = (limit - (end - start)) // 2
        s0 = max(0, start - pad)
        frag = text[s0 : s0 + limit]
    frag = _CTRL.sub(lambda m: f"\\x{ord(m.group(0)):02x}", frag)
    frag = frag.encode("utf-8", "replace").decode("utf-8")  # lone surrogates from %uD800 etc.
    return frag[:limit]


def clean_label(text: str | None, limit: int = 100) -> str:
    """Short printable label (param names, header values) for titles/entities."""
    if not text:
        return ""
    return snippet(text, 0, min(len(text), limit), limit)


# --- inspection targets ---------------------------------------------------------------------------------


@dataclass(slots=True)
class Target:
    location: str
    param: str | None
    raw: str
    decoded: str
    lower: str
    norm: str
    value: str


def make_target(
    location: str,
    text: str,
    *,
    param: str | None = None,
    name: str | None = None,
    plus: bool = False,
    max_chars: int = 8192,
) -> Target:
    """Build a target. With ``name`` the text is treated as ``name=value`` (both parts decoded separately)."""
    text = text[:max_chars]
    if name is not None:
        dname = decode(name[:256], plus=plus)
        dvalue = decode(text, plus=plus)
        raw = f"{name[:256]}={text}".lower()
        decoded = f"{dname}={dvalue}"
        lower = to_lower(decoded)
        value = to_lower(dvalue)
    else:
        decoded = decode(text, plus=plus)
        raw = text.lower()
        lower = to_lower(decoded)
        value = lower
    return Target(location, param, raw, decoded, lower, normalize(lower), value)


def _split_params(qs: str, location: str, max_chars: int, plus: bool) -> list[Target]:
    out: list[Target] = []
    pieces = qs.split("&")
    if len(pieces) > MAX_PARAMS:
        pieces = [*pieces[: MAX_PARAMS - 1], "&".join(pieces[MAX_PARAMS - 1 :])]
    for piece in pieces:
        if not piece:
            continue
        name, sep, value = piece.partition("=")
        if sep:
            pname = clean_label(decode(name[:256], plus=plus))
            out.append(make_target(location, value, param=pname, name=name, plus=plus, max_chars=max_chars))
        else:
            out.append(make_target(location, piece, plus=plus, max_chars=max_chars))
    return out


def _json_leaves(obj: Any, prefix: str, out: list[tuple[str, str]], depth: int) -> None:
    if len(out) >= MAX_JSON_LEAVES or depth > MAX_JSON_DEPTH:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            _json_leaves(v, f"{prefix}.{k}" if prefix else str(k), out, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _json_leaves(v, f"{prefix}[{i}]", out, depth + 1)
    elif isinstance(obj, str):
        out.append((prefix[:100], obj))


_BOUNDARY = rx(r'(?:B|b)oundary="?([^";,\s]{1,200})', "multipart.boundary")
_PART_NAME = rx(r'\bname="([^"\r\n]{0,200})"', "multipart.name")
_PART_FILENAME = rx(r'\bfilename="([^"\r\n]{0,500})"', "multipart.filename")
_FORMISH = rx(r"^[\w.\[\]%-]{1,100}=[^\r\n<>{}]{0,8192}$", "body.formish")


def _parse_multipart(body: str, content_type: str, max_chars: int) -> list[Target] | None:
    m = _BOUNDARY.search(content_type)
    if m:
        boundary = m.group(1)
    elif body.startswith("--"):
        boundary = body[2 : body.find("\n")].strip() if "\n" in body else ""
    else:
        return None
    if not boundary:
        return None
    out: list[Target] = []
    for chunk in body.split("--" + boundary)[1 : MAX_MULTIPART_PARTS + 1]:
        if chunk.startswith("--"):
            break
        head, sep, content = chunk.partition("\r\n\r\n")
        if not sep:
            head, sep, content = chunk.partition("\n\n")
        nm = _PART_NAME.search(head)
        fn = _PART_FILENAME.search(head)
        pname = clean_label(nm.group(1)) if nm else None
        if fn and fn.group(1):
            out.append(make_target(FILENAME, fn.group(1), param=pname, max_chars=max_chars))
        content = content.strip("\r\n")
        if content:
            out.append(make_target(BODY, content, param=pname, max_chars=max_chars))
    return out


def _parse_body(body: str, content_type: str, max_chars: int) -> list[Target] | None:
    """Split a body into parameter targets, or ``None`` when it is unstructured (inspect it whole)."""
    ct = content_type.lower()
    if "multipart/" in ct or (not ct and body.startswith("--")):
        return _parse_multipart(body, content_type, max_chars)
    head = body.lstrip()[:1]
    if "json" in ct or (head in ("{", "[") and "xml" not in ct):
        try:
            data = json.loads(body)
        except Exception:  # truncated capture, invalid JSON, absurd nesting -> inspect whole body
            return None
        leaves: list[tuple[str, str]] = []
        _json_leaves(data, "", leaves, 0)
        return [make_target(BODY, v, param=clean_label(k) or None, max_chars=max_chars) for k, v in leaves]
    if "x-www-form-urlencoded" in ct or (not ct and _FORMISH.match(body)):
        return _split_params(body, BODY, max_chars, plus=True)
    return None


def _cookie_targets(cookie: str, max_chars: int) -> list[Target]:
    out: list[Target] = []
    for piece in cookie.split(";")[:MAX_PARAMS]:
        piece = piece.strip()
        if not piece:
            continue
        name, sep, value = piece.partition("=")
        pname = clean_label(name.strip()) or None
        if sep:
            out.append(make_target(COOKIE, value, param=pname, name=name.strip(), max_chars=max_chars))
        else:
            out.append(make_target(COOKIE, piece, param=pname, max_chars=max_chars))
    return out


_NUM_SEG = rx(r"\d{1,20}", "pathkey.num")
_ID_SEG = rx(r"[0-9a-f]{8,64}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "pathkey.id")
_SAFE_SEG = rx(r"[a-z0-9_~.-]{1,40}", "pathkey.safe")
_SLASHES = rx(r"/{2,}", "path.slashes")


def path_key(lower_path: str, max_segments: int = 3) -> str:
    """Route-like key for fingerprints: ids/numbers/odd segments collapsed so payload variants dedup together."""
    out: list[str] = []
    for seg in lower_path.replace("\\", "/").split("/"):
        if not seg:
            continue
        if _NUM_SEG.fullmatch(seg):
            tok = "{n}"
        elif _ID_SEG.fullmatch(seg):
            tok = "{id}"
        elif ".." in seg or not _SAFE_SEG.fullmatch(seg):
            tok = "{x}"
        else:
            tok = seg
        if tok == "{x}" and out and out[-1] == "{x}":
            continue
        out.append(tok)
        if len(out) >= max_segments:
            break
    return "/" + "/".join(out)


def clean_path(lower_path: str) -> str:
    """Decoded lower-cased path with ``\\`` -> ``/``, duplicate slashes and ``/./`` removed."""
    p = _SLASHES.sub("/", lower_path.replace("\\", "/"))
    for _ in range(4):
        if "/./" not in p:
            break
        p = p.replace("/./", "/")
    return p


@dataclass(slots=True)
class HttpView:
    """Decoded, normalised view of one HTTP event shared by all web detectors."""

    source: Event
    method: str
    host: str
    path: str  # decoded, lower-cased, no query
    path_clean: str
    path_key: str
    status: int | None
    content_type: str
    headers: dict[str, str]
    targets: list[Target]

    def entities(self, param: str | None = None) -> dict[str, str]:
        ents = {"path": clean_label(self.path, 200), "host": clean_label(self.host, 200)}
        if param:
            ents["param"] = clean_label(param, 100)
        return {k: v for k, v in ents.items() if v}


def build_view(event: Event, max_chars: int = 8192) -> HttpView | None:
    http = event.http
    if http is None:
        return None
    headers: dict[str, str] = {}
    for k, v in list(http.headers.items())[:MAX_HEADERS]:
        headers[str(k).lower()] = str(v)[:max_chars]
    if http.user_agent and "user-agent" not in headers:
        headers["user-agent"] = http.user_agent[:max_chars]
    if http.referrer and "referer" not in headers:
        headers["referer"] = http.referrer[:max_chars]

    path_raw = http.path or ""
    query_raw = http.query or ""
    if not query_raw and "?" in path_raw:
        path_raw, _, query_raw = path_raw.partition("?")
    if query_raw.startswith("?"):
        query_raw = query_raw[1:]

    targets: list[Target] = []
    if path_raw:
        targets.append(make_target(PATH, path_raw, max_chars=max_chars))
    if query_raw:
        targets.extend(_split_params(query_raw[:max_chars], QUERY, max_chars, plus=True))

    raw_content_type = http.content_type or headers.get("content-type") or ""
    content_type = raw_content_type.lower()
    body = http.request_body
    if body:
        body = body[:max_chars]
        parts = _parse_body(body, raw_content_type, max_chars)  # multipart boundary is case-sensitive
        if parts is None:
            targets.append(make_target(BODY, body, max_chars=max_chars))
        else:
            targets.extend(parts)
            targets.append(make_target(BODY_RAW, body, max_chars=max_chars))

    for name, value in headers.items():
        if not value or name in _SKIP_HEADERS:
            continue
        if name == "cookie":
            targets.extend(_cookie_targets(value, max_chars))
        elif name in INJECTABLE_HEADERS:
            targets.append(make_target(HEADER, value, param=name, max_chars=max_chars))
        else:
            targets.append(make_target(HEADER_OTHER, value, param=name, max_chars=max_chars))

    lower_path = to_lower(decode(path_raw[:max_chars]))
    host = http.host or (event.destination.hostname if event.destination else None) or ""
    if not host and event.destination and event.destination.ip:
        host = event.destination.ip
    return HttpView(
        source=event,
        method=(http.method or "").upper()[:32],
        host=host,
        path=lower_path,
        path_clean=clean_path(lower_path),
        path_key=path_key(lower_path),
        status=http.status,
        content_type=content_type,
        headers=headers,
        targets=targets,
    )


def get_view(event: Event, ctx: DetectionContext | None) -> HttpView | None:
    """Per-event cached :class:`HttpView` (single slot: the engine finishes one event before the next)."""
    if event.http is None:
        return None
    if ctx is None:
        return build_view(event)
    cached = ctx.scratch.get(_SCRATCH_KEY)
    if isinstance(cached, HttpView) and cached.source is event:
        return cached
    view = build_view(event, web_settings(ctx.settings).max_inspect_chars)
    ctx.scratch[_SCRATCH_KEY] = view
    return view


# --- signatures -----------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Signature:
    id: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float
    view: View
    locations: frozenset[str] | None
    description: str
    mitre: tuple[str, ...]


def sig(
    sig_id: str,
    pattern: str,
    severity: Severity,
    *,
    confidence: float = 0.7,
    view: View = "norm",
    locations: frozenset[str] | None = None,
    description: str = "",
    mitre: tuple[str, ...] = (),
) -> Signature:
    return Signature(
        id=sig_id,
        pattern=rx(pattern, sig_id),
        severity=severity,
        confidence=confidence,
        view=view,
        locations=locations,
        description=description or sig_id,
        mitre=mitre,
    )


@dataclass(slots=True)
class Hit:
    sig: Signature
    location: str
    param: str | None
    fragment: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "signature": self.sig.id,
            "location": self.location,
            "param": self.param,
            "fragment": self.fragment,
        }


Plan = tuple[tuple[View, re.Pattern[str], tuple[Signature, ...]], ...]


def build_plan(signatures: tuple[Signature, ...], owner: str) -> Plan:
    """Group signatures by view and OR them into one prefilter regex per view (fast negative path)."""
    by_view: dict[View, list[Signature]] = {}
    for s in signatures:
        by_view.setdefault(s.view, []).append(s)
    plan = []
    for view, sigs in by_view.items():
        combined = "|".join(f"(?:{s.pattern.pattern})" for s in sigs)
        plan.append((view, rx(combined, f"{owner}.prefilter.{view}"), tuple(sigs)))
    return tuple(plan)


def scan_targets(
    targets: list[Target],
    plan: Plan,
    default_locations: frozenset[str],
    scan_locations: frozenset[str],
    max_hits: int = 8,
) -> list[Hit]:
    hits: list[Hit] = []
    seen: set[str] = set()
    for t in targets:
        if t.location not in scan_locations:
            continue
        for view, prefilter, sigs in plan:
            text: str = getattr(t, view)
            if not text or prefilter.search(text) is None:
                continue
            for s in sigs:
                if s.id in seen or t.location not in (s.locations or default_locations):
                    continue
                m = s.pattern.search(text)
                if m is None:
                    continue
                seen.add(s.id)
                hits.append(Hit(s, t.location, t.param, snippet(text, m.start(), m.end())))
                if len(hits) >= max_hits:
                    return hits
    return hits


def scan_text(text: str, plan: Plan, location: str, max_hits: int = 8) -> list[Hit]:
    """Scan one plain string (e.g. the cleaned path) with every signature of the plan."""
    t = Target(location, None, text, text, text, text, text)
    return scan_targets([t], plan, frozenset({location}), frozenset({location}), max_hits)


class WebSignatureDetector(Detector):
    """Base for stateless web signature detectors. Subclasses set ``signatures`` (and maybe ``locations``).

    One alert per event and detector; the highest-severity hit drives title/severity and every distinct
    signature hit raises confidence a little. ``fingerprint`` = ``rule|source_ip|path_key`` so payload variants
    from one source against one route collapse into one alert (``count`` increments).
    """

    kinds = frozenset({EventKind.HTTP})
    category = AlertCategory.EXPLOIT_ATTEMPT
    family: ClassVar[str] = "web"
    signatures: ClassVar[tuple[Signature, ...]] = ()
    locations: ClassVar[frozenset[str]] = INJECTION_LOCATIONS
    max_hits: ClassVar[int] = 8
    _plan: ClassVar[Plan] = ()
    _scan_locations: ClassVar[frozenset[str]] = frozenset()

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if "signatures" in cls.__dict__ and cls.signatures:
            cls._plan = build_plan(cls.signatures, getattr(cls, "id", cls.__name__))
            extra: set[str] = set()
            for s in cls.signatures:
                extra |= s.locations or frozenset()
            cls._scan_locations = cls.locations | frozenset(extra)

    def scan(self, view: HttpView) -> list[Hit]:
        return scan_targets(view.targets, self._plan, self.locations, self._scan_locations, self.max_hits)

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        view = get_view(event, ctx)
        if view is None:
            return []
        return self.build_alert(event, view, self.scan(view))

    def build_alert(
        self,
        event: Event,
        view: HttpView,
        hits: list[Hit],
        *,
        severity: Severity | None = None,
        title: str | None = None,
        fingerprint: str | None = None,
        extra_tags: tuple[str, ...] = (),
        extra_details: dict[str, Any] | None = None,
    ) -> list[AlertDraft]:
        if not hits:
            return []
        hits = sorted(hits, key=lambda h: (h.sig.severity.rank, h.sig.confidence), reverse=True)
        top = hits[0]
        ids = list(dict.fromkeys(h.sig.id for h in hits))
        confidence = min(0.95, max(h.sig.confidence for h in hits) + 0.05 * (len(ids) - 1))
        mitre = list(dict.fromkeys([*self.mitre, *(m for h in hits for m in h.sig.mitre)]))
        where = top.location + (f" '{clean_label(top.param, 40)}'" if top.param else "")
        details: dict[str, Any] = {
            "matched": top.fragment,
            "signature": top.sig.id,
            "location": top.location,
            "param": top.param,
            "signatures": ids,
            "matches": [h.as_dict() for h in hits[:5]],
            "method": view.method,
            "status": view.status,
        }
        if extra_details:
            details.update(extra_details)
        return [
            self.draft(
                event,
                title=(title or f"{self.name}: {top.sig.description} [{where}]")[:200],
                description=self.description,
                severity=severity or top.sig.severity,
                confidence=round(confidence, 2),
                entities=view.entities(top.param),
                tags=list(dict.fromkeys(["web", self.family, *ids, *extra_tags])),
                fingerprint=fingerprint or f"{self.id}|{event.source_ip or '-'}|{view.path_key}",
                details=details,
                mitre=mitre,
            )
        ]
