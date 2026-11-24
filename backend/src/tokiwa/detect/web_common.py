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

import base64
import binascii
import html
import json
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, ClassVar, Literal
from urllib.parse import unquote, unquote_plus, urlsplit

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
# Application-specific headers (X-Tenant-Id, X-User-Id, X-Request-Id ...): apps feed them into queries, logs and
# templates, so the injection detectors read them (audit #53). Before, they were header_other and only
# Log4Shell / SSTI / SSRF-metadata / deserialization looked at them.
HEADER_CUSTOM = "header_custom"
HEADER_OTHER = (
    "header_other"  # framing headers (Accept*, Sec-*, If-*, Content-Type ...): Log4Shell / OGNL only
)
COOKIE = "cookie"
FILENAME = "filename"  # multipart upload file names

INJECTION_LOCATIONS = frozenset({PATH, QUERY, BODY, HEADER, HEADER_CUSTOM, COOKIE, FILENAME})
PARAM_LOCATIONS = frozenset({QUERY, BODY, COOKIE})
WHOLE_BODY_LOCATIONS = frozenset({BODY, BODY_RAW})
HEADER_LOCATIONS = frozenset({HEADER, HEADER_CUSTOM, HEADER_OTHER})
ALL_LOCATIONS = frozenset(
    {PATH, QUERY, BODY, BODY_RAW, HEADER, HEADER_CUSTOM, HEADER_OTHER, COOKIE, FILENAME}
)

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
# Headers written by browsers, proxies, HTTP libraries and tracing SDKs - negotiation, caching, client hints,
# fetch metadata, trace context. Applications do not treat their values as data, and several carry quotes, ``;``
# and ``,`` by design (``sec-ch-ua: "Chromium";v="130"``, ``if-none-match: W/"x"``), so the injection detectors
# skip them (header_other). Content-Type stays here too, but Log4Shell / OGNL (Struts CVE-2017-5638) /
# Shellshock still read every header_other value. Extend with ``detection.web.extra_framing_headers``.
FRAMING_HEADERS = frozenset(
    {
        "accept",
        "accept-charset",
        "accept-encoding",
        "accept-language",
        "accept-datetime",
        "access-control-request-headers",
        "access-control-request-method",
        "alt-used",
        "baggage",
        "cache-control",
        "content-encoding",
        "content-language",
        "content-type",
        "device-memory",
        "dnt",
        "downlink",
        "dpr",
        "early-data",
        "ect",
        "expect",
        "if-match",
        "if-modified-since",
        "if-none-match",
        "if-range",
        "if-unmodified-since",
        "keep-alive",
        "max-forwards",
        "pragma",
        "priority",
        "purpose",
        "range",
        "rtt",
        "save-data",
        "te",
        "traceparent",
        "tracestate",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "upgrade-insecure-requests",
        "viewport-width",
        "width",
        "x-amzn-trace-id",
        "x-cloud-trace-context",
        "x-forwarded-port",
        "x-forwarded-proto",
        "x-requested-with",
        "b3",
    }
)
FRAMING_HEADER_PREFIXES = ("sec-ch-", "sec-fetch-", "sec-websocket-", "sec-purpose", "sec-gpc", "x-b3-")


def is_framing_header(name: str, extra: tuple[str, ...] = ()) -> bool:
    """``name`` (lower-case) is a framing header; ``extra`` entries ending in ``*`` match as prefixes."""
    if name in FRAMING_HEADERS or name.startswith(FRAMING_HEADER_PREFIXES):
        return True
    return any(name.startswith(e[:-1]) if e.endswith("*") else name == e for e in extra)


# Defaults of the structural limits; the effective values come from ``detection.web`` (WebDetectionSettings).
# Decoding stops as soon as a value is stable, so the bound only matters for deliberately nested encodings;
# 3 rounds let a 4x URL-encoded payload through (audit #89).
MAX_DECODE_ROUNDS = 8
MAX_PARAMS = 64
MAX_HEADERS = 64
MAX_JSON_LEAVES = 128
MAX_JSON_DEPTH = 16
MAX_MULTIPART_PARTS = 32
MAX_FRAGMENT = 200

# Joins the items folded into one "overflow" target (JSON keys, leaves past the limit, extra headers). NUL is
# neither whitespace (the ``norm`` view would collapse it into a space) nor a shell separator (``\n`` would make
# web.cmd_injection read "name<LF>id" as ";id"), so no signature treats two neighbouring items as one statement.
OVERFLOW_SEP = "\x00"
OVERFLOW_PARAM = "(overflow)"
JSON_KEYS_PARAM = "(json keys)"
MAX_BASE64_TARGETS = 8  # decoded base64 parameter values per request (audit #89)

# Reasons recorded in ``HttpView.truncated`` when a limit was reached (audit #51). Items past a structural limit
# are still inspected (folded into one overflow target); only text past ``max_inspect_chars`` is not.
TRUNC_JSON_LEAVES = "json_leaves"
TRUNC_JSON_DEPTH = "json_depth"
TRUNC_MULTIPART_PARTS = "multipart_parts"
TRUNC_PARAMS = "params"
TRUNC_COOKIES = "cookies"
TRUNC_HEADERS = "headers"
TRUNC_CHARS = "chars"  # "chars:<location>" - a field longer than max_inspect_chars was cut
TRUNC_BODY = "body_chars"  # the body was longer than max_inspect_chars (the rest is not inspected)
# The sensor captured only a prefix of the body (request_body_size is larger than the captured text).
TRUNC_SENSOR_BODY = "sensor_body"
INSPECTION_TRUNCATED_TAG = "inspection-truncated"

# Evasion indicators recorded in ``HttpView.evasion`` (web.inspection_evasion turns them into a low alert).
EVADE_PADDING = "padding"  # "padding:<location|json_leaves|multipart_parts|params:...|sensor_body>"
EVADE_BOUNDARY = "multipart_boundary_ambiguous"  # several different boundary= parameters (audit #52)
PADDING_MIN_CHARS = 1024
PADDING_MIN_ITEMS = 16


def is_padding(text: str) -> bool:
    """True when one character makes up >= 90% of a long text ("A" * 8200 in front of a payload).

    NUL / U+FFFD runs are left out: they are what binary uploads look like after UTF-8 decoding with replacement.
    Only a few candidate characters are counted (``str.count`` is C speed), never the whole alphabet.
    """
    n = len(text)
    if n < PADDING_MIN_CHARS:
        return False
    candidates = {text[0], text[n // 2], text[-1]} - {"\x00", "�"}
    return any(text.count(c) * 10 >= n * 9 for c in candidates)


def is_padding_items(items: list[str]) -> bool:
    """True when a list that overflowed a structural limit is mostly empty / identical items (dummy elements)."""
    if len(items) < PADDING_MIN_ITEMS:
        return False
    distinct = {i for i in items if i}
    return len(distinct) * 10 <= len(items)


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
_LONE_BYTE = rx(r"[\udc80-\udcff]", "decode.lone_byte")  # surrogateescape'd invalid UTF-8 bytes
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


def _sub_lone_byte(m: re.Match[str]) -> str:
    return chr(ord(m.group(0)) - 0xDC00)


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
            # Bytes that are not valid UTF-8 (a lone %A0) become their Latin-1 character instead of U+FFFD:
            # MySQL treats 0xA0 as whitespace, and NFKC (``lower`` view) turns U+00A0 into a space (audit #89).
            if plus and i == 0:
                s = unquote_plus(s, errors="surrogateescape")
            else:
                s = unquote(s, errors="surrogateescape")
            if not s.isascii():
                s = _LONE_BYTE.sub(_sub_lone_byte, s)
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
    rounds: int = MAX_DECODE_ROUNDS,
    notes: set[str] | None = None,
) -> Target:
    """Build a target. With ``name`` the text is treated as ``name=value`` (both parts decoded separately).

    ``notes`` collects ``chars:<location>`` when the text had to be cut to ``max_chars`` (audit #51).
    """
    if len(text) > max_chars:
        text = text[:max_chars]
        if notes is not None:
            notes.add(f"{TRUNC_CHARS}:{location}")
    if name is not None:
        dname = decode(name[:256], plus=plus, rounds=rounds)
        dvalue = decode(text, plus=plus, rounds=rounds)
        raw = f"{name[:256]}={text}".lower()
        decoded = f"{dname}={dvalue}"
        lower = to_lower(decoded)
        value = to_lower(dvalue)
    else:
        decoded = decode(text, plus=plus, rounds=rounds)
        raw = text.lower()
        lower = to_lower(decoded)
        value = lower
    return Target(location, param, raw, decoded, lower, normalize(lower), value)


@dataclass(slots=True)
class _Build:
    """Limits + the truncation notes of one :func:`build_view` call."""

    max_chars: int = 8192
    rounds: int = MAX_DECODE_ROUNDS
    max_params: int = MAX_PARAMS
    max_headers: int = MAX_HEADERS
    max_json_leaves: int = MAX_JSON_LEAVES
    max_json_depth: int = MAX_JSON_DEPTH
    max_multipart_parts: int = MAX_MULTIPART_PARTS
    custom_headers: bool = True
    extra_framing: tuple[str, ...] = ()
    notes: set[str] | None = None
    flags: set[str] = field(default_factory=set)  # evasion indicators (padding, ambiguous framing)
    derived: list[Target] = field(default_factory=list)  # decoded base64 values (appended after the rest)
    base64_left: int = MAX_BASE64_TARGETS

    @classmethod
    def from_settings(cls, cfg: WebDetectionSettings | None, max_chars: int) -> _Build:
        if cfg is None:
            return cls(max_chars=max_chars, notes=set())
        return cls(
            max_chars=max_chars,
            rounds=cfg.max_decode_rounds,
            max_params=cfg.max_params,
            max_headers=cfg.max_headers,
            max_json_leaves=cfg.max_json_leaves,
            max_json_depth=cfg.max_json_depth,
            max_multipart_parts=cfg.max_multipart_parts,
            custom_headers=cfg.inspect_custom_headers,
            extra_framing=tuple(h.strip().lower() for h in cfg.extra_framing_headers if h.strip()),
            notes=set(),
        )

    def header_location(self, name: str) -> str:
        if name in INJECTABLE_HEADERS:
            return HEADER
        if not self.custom_headers or is_framing_header(name, self.extra_framing):
            return HEADER_OTHER
        return HEADER_CUSTOM

    def note(self, reason: str) -> None:
        if self.notes is not None:
            self.notes.add(reason)

    def flag(self, reason: str) -> None:
        self.flags.add(reason)

    def target(
        self,
        location: str,
        text: str,
        *,
        param: str | None = None,
        name: str | None = None,
        plus: bool = False,
    ) -> Target:
        if len(text) > self.max_chars and is_padding(text[: self.max_chars]):
            self.flag(f"{EVADE_PADDING}:{location}")
        if location in _BASE64_LOCATIONS and self.base64_left > 0 and param not in _FOLDED_PARAMS:
            plain = try_base64(text)
            if plain is not None:
                self.base64_left -= 1
                label = f"{param or ''}{BASE64_SUFFIX}"
                self.derived.append(
                    make_target(
                        location,
                        plain,
                        param=label,
                        max_chars=self.max_chars,
                        rounds=self.rounds,
                        notes=self.notes,
                    )
                )
        return make_target(
            location,
            text,
            param=param,
            name=name,
            plus=plus,
            max_chars=self.max_chars,
            rounds=self.rounds,
            notes=self.notes,
        )


# --- extra decodings (audit #89) -------------------------------------------------------------------------
BASE64_SUFFIX = "(base64)"
JOINED_SUFFIX = "(joined)"
MAX_JOINED_TARGETS = 4
_BASE64_LOCATIONS = frozenset({QUERY, BODY, COOKIE, HEADER_CUSTOM})
_FOLDED_PARAMS = frozenset({OVERFLOW_PARAM, JSON_KEYS_PARAM})
_B64_VALUE = rx(r"^[A-Za-z0-9+/_-]{16,8192}={0,2}$", "decode.base64_value")
_B64URL = str.maketrans("-_", "+/")


def try_base64(value: str) -> str | None:
    """The text a base64 / base64url parameter carries, or None (not base64, or binary once decoded).

    Apps that take ``filter=`` / ``state=`` / ``q=`` as base64 decode it themselves, so the signature detectors
    must see the decoded text too. Random tokens, hashes, IDs and serialized binaries decode to non-text and
    are skipped: the result has to be valid UTF-8 and >= 95% printable.
    """
    v = value.strip()
    if "%" in v:
        v = unquote(v)
    if not _B64_VALUE.match(v):
        return None
    core = v.rstrip("=")
    if "-" in core or "_" in core:
        if "+" in core or "/" in core:
            return None  # mixed alphabets: not base64 of anything
        core = core.translate(_B64URL)
    if len(core) % 4 == 1:
        return None
    try:
        raw = base64.b64decode(core + "=" * (-len(core) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError):  # UnicodeDecodeError is a ValueError
        return None
    if len(text) < 8:
        return None
    printable = sum(1 for c in text if c.isprintable() or c in "\t\r\n")
    return text if printable * 20 >= len(text) * 19 else None


def utf16_text(body: str) -> str | None:
    """ASCII text that arrived as UTF-16 (``{\\x00"\\x00q\\x00...``), with the NULs removed; else None.

    JSON parsers such as Jackson detect UTF-16 bodies on their own, while the sensor decoded the bytes as UTF-8,
    so every second character is NUL and no signature matched (audit #89). Only the alternating pattern counts:
    a zero-filled binary (NUL everywhere) or text with a few NULs is left alone. Non-ASCII characters were
    already lost by the sensor's UTF-8 decoding; ASCII payloads survive.
    """
    s = body.lstrip("﻿�")  # BOM: U+FEFF, or FF FE / FE FF decoded as two U+FFFD
    head = s[:256]
    odd, even = head[1::2], head[0::2]
    if len(head) < 8:
        return None
    odd_nul, even_nul = odd.count("\x00"), even.count("\x00")
    little = odd_nul * 10 >= len(odd) * 9 and even_nul * 10 <= len(even)
    big = even_nul * 10 >= len(even) * 9 and odd_nul * 10 <= len(odd)
    return s.replace("\x00", "") if little or big else None


def _split_params(qs: str, location: str, b: _Build, plus: bool) -> list[Target]:
    out: list[Target] = []
    by_name: dict[str, list[str]] = {}
    pieces = qs.split("&")
    if len(pieces) > b.max_params:
        # The tail stays inspected as one piece (its first name labels it), never dropped.
        if is_padding_items(pieces[: b.max_params - 1]):
            b.flag(f"{EVADE_PADDING}:{TRUNC_PARAMS}:{location}")
        pieces = [*pieces[: b.max_params - 1], "&".join(pieces[b.max_params - 1 :])]
        b.note(f"{TRUNC_PARAMS}:{location}")
    for piece in pieces:
        if not piece:
            continue
        name, sep, value = piece.partition("=")
        if sep:
            pname = clean_label(decode(name[:256], plus=plus, rounds=b.rounds))
            out.append(b.target(location, value, param=pname, name=name, plus=plus))
            by_name.setdefault(name, []).append(value)
        else:
            out.append(b.target(location, piece, plus=plus))
    # HTTP parameter pollution: ASP.NET hands the app "a,b" for ?q=a&q=b, so a payload split over repeated
    # parameters only exists joined (audit #89). TODO(verify): other frameworks keep the first or the last value
    # (both are inspected above) or a list; comma-joining is the documented ASP.NET behaviour.
    joined = 0
    for name, values in by_name.items():
        if len(values) < 2 or joined >= MAX_JOINED_TARGETS:
            continue
        joined += 1
        pname = clean_label(decode(name[:256], plus=plus, rounds=b.rounds)) + JOINED_SUFFIX
        out.append(b.target(location, ",".join(values), param=pname, name=name, plus=plus))
    return out


def _json_targets(data: Any, b: _Build) -> list[Target]:
    """String leaves as targets; keys and everything past the leaf/depth limits folded into overflow targets.

    Before audit #51 the walk stopped at the 128th leaf / 16th level and ignored keys, so 128 dummy elements in
    front of the payload, or a payload used as a key (sort field names, NoSQL operators) hid it from every
    ``web.*`` detector. Now nothing in the (already length-capped) body is skipped: keys go to one target, and
    leaves past the limits to another, each joined with :data:`OVERFLOW_SEP`. The walk is iterative, so the
    nesting depth json.loads accepted cannot overflow the Python stack here.
    """
    leaves: list[tuple[str, str]] = []
    keys: list[str] = []
    overflow: list[str] = []
    stack: list[tuple[Any, str, int]] = [(data, "", 0)]
    while stack:
        obj, prefix, depth = stack.pop()
        if isinstance(obj, dict):
            items = list(obj.items())
            keys.extend(str(k) for k, _ in items)
            for k, v in reversed(items):
                stack.append((v, (f"{prefix}.{k}" if prefix else str(k))[:200], depth + 1))
        elif isinstance(obj, list):
            for i in range(len(obj) - 1, -1, -1):
                stack.append((obj[i], f"{prefix}[{i}]"[:200], depth + 1))
        elif isinstance(obj, str):
            if depth > b.max_json_depth:
                b.note(TRUNC_JSON_DEPTH)
                overflow.append(obj)
            elif len(leaves) >= b.max_json_leaves:
                b.note(TRUNC_JSON_LEAVES)
                overflow.append(obj)
            else:
                leaves.append((prefix[:100], obj))
    out = [b.target(BODY, v, param=clean_label(k) or None) for k, v in leaves]
    if overflow and is_padding_items([v for _, v in leaves]):
        b.flag(f"{EVADE_PADDING}:{TRUNC_JSON_LEAVES}")
    if overflow:
        out.append(b.target(BODY, OVERFLOW_SEP.join(overflow), param=OVERFLOW_PARAM))
    if keys:
        out.append(b.target(BODY, OVERFLOW_SEP.join(keys), param=JSON_KEYS_PARAM))
    return out


_PART_NAME = rx(r'\bname="([^"\r\n]{0,200})"', "multipart.name")
_PART_FILENAME = rx(r'\bfilename="([^"\r\n]{0,500})"', "multipart.filename")
_FORMISH = rx(r"^[\w.\[\]%-]{1,100}=[^\r\n<>{}]{0,8192}$", "body.formish")
_MAX_CT_CHARS = 1024
_MAX_CT_PARAMS = 32
_MAX_BOUNDARY_CHARS = 200  # RFC 2046 allows 1-70; tolerate longer, as lenient parsers do
_MAX_BOUNDARY_CANDIDATES = 4


def content_type_params(content_type: str) -> list[tuple[str, str]]:
    """Parameters of a Content-Type value, in order and with duplicates (audit #52).

    ``multipart/form-data; xboundary=ZZ; Boundary="B;B"`` -> ``[("xboundary", "ZZ"), ("boundary", "B;B")]``.
    ``;``-separated ``name=value`` pairs (RFC 2045 §5.1 / RFC 9110 §5.6.6): names are matched exactly and
    case-insensitively, values keep their case (a multipart boundary is case-sensitive), a quoted value may
    contain ``;`` and backslash escapes. The old prefix regex took ``xboundary=`` for ``boundary=`` and missed
    ``BOUNDARY=``. RFC 2231 continuations (``boundary*0=``) are not reassembled: they do not match ``boundary``.
    """
    s = content_type[:_MAX_CT_CHARS]
    out: list[tuple[str, str]] = []
    i = s.find(";")
    if i < 0:
        return out
    i += 1
    n = len(s)
    while i < n and len(out) < _MAX_CT_PARAMS:
        while i < n and s[i] in " \t;":
            i += 1
        j = i
        while j < n and s[j] not in "=;":
            j += 1
        name = s[i:j].strip().lower()
        if j >= n or s[j] == ";":  # parameter without a value
            i = j + 1
            continue
        j += 1
        while j < n and s[j] in " \t":
            j += 1
        if j < n and s[j] == '"':
            j += 1
            buf: list[str] = []
            while j < n and s[j] != '"':
                if s[j] == "\\" and j + 1 < n:
                    j += 1
                buf.append(s[j])
                j += 1
            value = "".join(buf)
            k = s.find(";", j)
        else:
            k = s.find(";", j)
            value = (s[j:] if k < 0 else s[j:k]).strip()
        i = n if k < 0 else k + 1
        if name:
            out.append((name, value))
    return out


def _multipart_boundaries(body: str, content_type: str, b: _Build) -> list[str]:
    """Boundary candidates: every distinct ``boundary`` parameter, else the delimiter on the body's first line.

    Servers disagree on which of several ``boundary`` parameters wins (TODO(verify): first vs last per framework),
    so every candidate is tried and the ambiguity itself is an evasion indicator - no legitimate client sends
    two different boundaries.
    """
    cands = list(
        dict.fromkeys(
            v[:_MAX_BOUNDARY_CHARS] for k, v in content_type_params(content_type) if k == "boundary" and v
        )
    )
    if len(cands) > 1:
        b.flag(EVADE_BOUNDARY)
    if not cands and body.startswith("--") and "\n" in body:
        first = body[2 : body.find("\n")].strip()
        if first:
            cands.append(first[:_MAX_BOUNDARY_CHARS])
    return cands[:_MAX_BOUNDARY_CANDIDATES]


def _parse_multipart(body: str, content_type: str, b: _Build) -> list[Target] | None:
    """Parts as targets; ``None`` (inspect the whole body) when no candidate boundary splits anything."""
    out: list[Target] = []
    for boundary in _multipart_boundaries(body, content_type, b):
        out.extend(_split_multipart(body, boundary, b))
    return out or None


def _split_multipart(body: str, boundary: str, b: _Build) -> list[Target]:
    out: list[Target] = []
    contents: list[str] = []
    delim = "--" + boundary
    chunks = body.split(delim)[1:]
    for idx, chunk in enumerate(chunks):
        if chunk.startswith("--"):
            break
        if idx >= b.max_multipart_parts:
            # Parts past the limit stay inspected as one raw chunk (headers included) instead of being dropped.
            b.note(TRUNC_MULTIPART_PARTS)
            if is_padding_items(contents):
                b.flag(f"{EVADE_PADDING}:{TRUNC_MULTIPART_PARTS}")
            rest = delim.join(chunks[idx:]).strip("\r\n")
            if rest:
                out.append(b.target(BODY, rest, param=OVERFLOW_PARAM))
            break
        head, sep, content = chunk.partition("\r\n\r\n")
        if not sep:
            head, sep, content = chunk.partition("\n\n")
        nm = _PART_NAME.search(head)
        fn = _PART_FILENAME.search(head)
        pname = clean_label(nm.group(1)) if nm else None
        if fn and fn.group(1):
            out.append(b.target(FILENAME, fn.group(1), param=pname))
        content = content.strip("\r\n")
        contents.append(content)
        if content:
            out.append(b.target(BODY, content, param=pname))
    return out


def _parse_body(body: str, content_type: str, b: _Build) -> list[Target] | None:
    """Split a body into parameter targets, or ``None`` when it is unstructured (inspect it whole)."""
    ct = content_type.lower()
    if "multipart/" in ct or (not ct and body.startswith("--")):
        return _parse_multipart(body, content_type, b)
    head = body.lstrip()[:1]
    if "json" in ct or (head in ("{", "[") and "xml" not in ct):
        try:
            data = json.loads(body)
        except Exception:  # truncated capture, invalid JSON, absurd nesting -> inspect whole body
            return None
        return _json_targets(data, b)
    if "x-www-form-urlencoded" in ct or (not ct and _FORMISH.match(body)):
        return _split_params(body, BODY, b, plus=True)
    return None


def _cookie_targets(cookie: str, b: _Build) -> list[Target]:
    out: list[Target] = []
    pieces = cookie.split(";")
    if len(pieces) > b.max_params:
        # Same folding as query parameters: the tail is inspected as the value of the last kept cookie.
        if is_padding_items([p.strip() for p in pieces[: b.max_params - 1]]):
            b.flag(f"{EVADE_PADDING}:{TRUNC_COOKIES}")
        pieces = [*pieces[: b.max_params - 1], ";".join(pieces[b.max_params - 1 :])]
        b.note(TRUNC_COOKIES)
    for piece in pieces:
        piece = piece.strip()
        if not piece:
            continue
        name, sep, value = piece.partition("=")
        pname = clean_label(name.strip()) or None
        if sep:
            out.append(b.target(COOKIE, value, param=pname, name=name.strip()))
        else:
            out.append(b.target(COOKIE, piece, param=pname))
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


# Routing overrides that IIS URL Rewrite, legacy Symfony / Zend and some Java filters honour as "the real path"
# (audit #147): the request line says /static/app.js while the application serves the header's path. The Gate
# strips them before forwarding (gate.proxy.ROUTE_OVERRIDE_HEADERS) but records them on the event.
ROUTE_OVERRIDE_HEADERS = ("x-original-url", "x-rewrite-url", "x-override-url")


def override_path(value: str, rounds: int = MAX_DECODE_ROUNDS) -> str:
    """Path a routing-override header asks for, as :attr:`HttpView.path_clean` spells paths ("" when empty).

    Absolute URLs are reduced to their path and the query / fragment is dropped, like the Gate's decoy lookup.
    """
    v = value.strip()[:2048]
    if "://" in v:
        try:
            v = urlsplit(v).path
        except ValueError:
            v = ""
    v = v.split("?", 1)[0].split("#", 1)[0]
    if not v:
        return ""
    return clean_path(to_lower(decode(v if v.startswith("/") else "/" + v, rounds=rounds)))


def differing_override_paths(headers: dict[str, str], path_clean: str, rounds: int) -> list[tuple[str, str]]:
    """(header, path) of the routing-override headers that name another path than the request line ("" = empty).

    Front ends (IIS ARR, nginx ``X-Original-URL $request_uri`` ...) set the header to the URL they received, i.e. the
    request line again, possibly behind a stripped ``X-Forwarded-Prefix``: those are not an override and left out.
    """
    same = {path_clean}
    prefix = override_path(headers.get("x-forwarded-prefix", ""), rounds).rstrip("/")
    if prefix:
        same.add(prefix + path_clean)
    out: list[tuple[str, str]] = []
    for header in ROUTE_OVERRIDE_HEADERS:
        if header in headers:
            target = override_path(headers[header], rounds)
            if target not in same:
                out.append((header, target))
    return out


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
    # Limits that were reached while building the targets (``TRUNC_*`` reasons, sorted). Empty = complete view.
    truncated: tuple[str, ...] = ()
    # Evasion indicators (``EVADE_*`` reasons, sorted): padding in front of a limit, ambiguous framing.
    evasion: tuple[str, ...] = ()

    def entities(self, param: str | None = None) -> dict[str, str]:
        ents = {"path": clean_label(self.path, 200), "host": clean_label(self.host, 200)}
        if param:
            ents["param"] = clean_label(param, 100)
        return {k: v for k, v in ents.items() if v}


def build_view(
    event: Event, max_chars: int = 8192, cfg: WebDetectionSettings | None = None
) -> HttpView | None:
    http = event.http
    if http is None:
        return None
    b = _Build.from_settings(cfg, max_chars)
    header_items = list(http.headers.items())
    headers: dict[str, str] = {}
    for k, v in header_items[: b.max_headers]:
        headers[str(k).lower()] = str(v)
    if http.user_agent and "user-agent" not in headers:
        headers["user-agent"] = http.user_agent
    if http.referrer and "referer" not in headers:
        headers["referer"] = http.referrer

    path_raw = http.path or ""
    query_raw = http.query or ""
    if not query_raw and "?" in path_raw:
        path_raw, _, query_raw = path_raw.partition("?")
    if query_raw.startswith("?"):
        query_raw = query_raw[1:]

    targets: list[Target] = []
    if path_raw:
        targets.append(b.target(PATH, path_raw))
    if query_raw:
        if len(query_raw) > max_chars:
            b.note(f"{TRUNC_CHARS}:{QUERY}")
            if is_padding(query_raw[:max_chars]):
                b.flag(f"{EVADE_PADDING}:{QUERY}")
        targets.extend(_split_params(query_raw[:max_chars], QUERY, b, plus=True))

    raw_content_type = http.content_type or headers.get("content-type") or ""
    content_type = raw_content_type.lower()
    body = http.request_body
    if body:
        if http.request_body_size and http.request_body_size > len(body.encode("utf-8", "replace")):
            b.note(TRUNC_SENSOR_BODY)  # approximate: redaction can change the captured length a little
            if is_padding(body[:max_chars]):
                b.flag(f"{EVADE_PADDING}:{TRUNC_SENSOR_BODY}")
        if "\x00" in body and "multipart/" not in content_type:
            body = utf16_text(body) or body
        if len(body) > max_chars:
            b.note(TRUNC_BODY)
            body = body[:max_chars]
            if is_padding(body):
                b.flag(f"{EVADE_PADDING}:{BODY}")
        parts = _parse_body(body, raw_content_type, b)  # multipart boundary is case-sensitive
        if parts is None:
            targets.append(b.target(BODY, body))
        else:
            targets.extend(parts)
            targets.append(b.target(BODY_RAW, body))

    for name, value in headers.items():
        if not value or name in _SKIP_HEADERS:
            continue
        if name == "cookie":
            targets.extend(_cookie_targets(value, b))
        else:
            targets.append(b.target(b.header_location(name), value, param=name))
    if len(header_items) > b.max_headers:
        # Headers past the limit are inspected together ("name: value" items) instead of being dropped.
        b.note(TRUNC_HEADERS)
        if is_padding_items([str(v) for _, v in header_items[: b.max_headers]]):
            b.flag(f"{EVADE_PADDING}:{TRUNC_HEADERS}")
        rest = [
            f"{str(k).lower()}: {v}"
            for k, v in header_items[b.max_headers :]
            if str(k).lower() not in _SKIP_HEADERS
        ]
        if rest:
            where = HEADER_CUSTOM if b.custom_headers else HEADER_OTHER
            targets.append(b.target(where, OVERFLOW_SEP.join(rest), param=OVERFLOW_PARAM))

    targets.extend(b.derived)

    lower_path = to_lower(decode(path_raw[:max_chars], rounds=b.rounds))
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
        headers={k: v[:max_chars] for k, v in headers.items()},
        targets=targets,
        truncated=tuple(sorted(b.notes or ())),
        evasion=tuple(sorted(b.flags)),
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
    cfg = web_settings(ctx.settings)
    view = build_view(event, cfg.max_inspect_chars, cfg)
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
        if view.truncated:
            # Part of the request was not inspected (or only as an overflow target): analysts and the triage
            # LLM should know the verdict rests on an incomplete view (audit #51).
            details["inspection_truncated"] = list(view.truncated)
            extra_tags = (*extra_tags, INSPECTION_TRUNCATED_TAG)
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
