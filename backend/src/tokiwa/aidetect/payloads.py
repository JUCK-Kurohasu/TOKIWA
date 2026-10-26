"""Payload helpers: extraction, normalisation, attack markers, natural-language score, similarity.

Design constraints:
- Everything here runs inline on the ingest path, so inputs are truncated and regexes are linear-time friendly
  (bounded quantifiers, no nested unbounded groups) to avoid ReDoS on attacker-controlled strings.
- Attack markers are a *light* re-implementation used only as behavioural features (is this request carrying
  an attack payload?). The authoritative signature detectors live in ``detect/detectors/web_*.py``.
- Natural-language scoring is a heuristic (stop-word / particle ratios), not a language model. It is tuned to
  separate "explanatory sentences" (``-- check whether the id parameter is injectable``) from code tokens.
"""

from __future__ import annotations

import html
import json
import math
import re
import unicodedata
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, unquote, unquote_plus

MAX_TEXT = 4096
MAX_PARAMS = 64
SIGNATURE_CHARS = 256

STATIC_EXTENSIONS = frozenset(
    {
        ".js",
        ".mjs",
        ".css",
        ".map",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".webp",
        ".avif",
        ".bmp",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".mp4",
        ".webm",
        ".mp3",
        ".wav",
    }
)

_NUM_RE = re.compile(r"\d{1,20}")
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_HEX_RE = re.compile(r"[0-9a-fA-F]{16,128}")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]{24,256}")
# Characters that do not appear in ordinary route segments but do in injected values.
_SPECIAL_SEG_RE = re.compile(r"""['"<>;()*$`{}|\\\s]|%[0-9a-fA-F]{2}|\.\.""")


def split_path(path: str | None) -> str:
    return (path or "").split("?", 1)[0].split("#", 1)[0]


def is_static_asset(path: str | None) -> bool:
    p = split_path(path).lower()
    dot = p.rfind(".")
    return dot != -1 and dot > p.rfind("/") and p[dot:] in STATIC_EXTENSIONS


def is_js_asset(path: str | None) -> bool:
    p = split_path(path).lower()
    return p.endswith((".js", ".mjs", ".js.map", ".mjs.map"))


def _template_segment(seg: str) -> tuple[str, str | None]:
    """Return (template token, extracted value or None)."""
    if not seg:
        return seg, None
    if _NUM_RE.fullmatch(seg):
        return "{n}", None
    if _UUID_RE.fullmatch(seg):
        return "{uuid}", None
    if _HEX_RE.fullmatch(seg):
        return "{hex}", None
    decoded = unquote(seg)
    if _SPECIAL_SEG_RE.search(seg) or _SPECIAL_SEG_RE.search(decoded):
        return "{p}", decoded[:256]
    if _TOKEN_RE.fullmatch(seg) and any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg):
        return "{tok}", None
    return seg, None


def path_template(path: str | None) -> str:
    """Normalise ids / injected segments so variants of one endpoint share a template.

    ``/api/users/42`` -> ``/api/users/{n}``; ``/api/users/1'%20OR%201=1`` -> ``/api/users/{p}``.
    """
    p = split_path(path)[:512]
    if not p:
        return "/"
    segs = p.split("/")[:16]
    out = [_template_segment(s)[0] for s in segs]
    t = "/".join(out)
    if len(t) > 1 and t.endswith("/"):
        t = t[:-1]
    return t[:200] or "/"


def path_params(path: str | None) -> dict[str, str]:
    p = split_path(path)[:512]
    out: dict[str, str] = {}
    for i, s in enumerate(p.split("/")[:16]):
        _, value = _template_segment(s)
        if value is not None:
            out[f"_path{i}"] = value
    return out


def normalize_text(text: str | None, limit: int = MAX_TEXT) -> str:
    """Decode common encodings and normalise for marker matching (lower-case, NFKC, comments -> space)."""
    if not text:
        return ""
    t = text[:limit]
    for _ in range(2):  # double-encoding is common in evasion attempts
        if "%" in t or "+" in t:
            nt = unquote_plus(t) if "%" in t else t
            if nt == t:
                break
            t = nt
    if "&" in t:
        t = html.unescape(t)
    t = unicodedata.normalize("NFKC", t)
    t = t.replace("/**/", " ")
    return re.sub(r"\s+", " ", t).strip().lower()


# ---------------------------------------------------------------------------------------------------------------
# Payload extraction


@dataclass(slots=True)
class Payload:
    params: dict[str, str] = field(default_factory=dict)
    raw_body: str | None = None

    @property
    def present(self) -> bool:
        return bool(self.params) or bool(self.raw_body)

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self.params)

    def values_text(self, limit: int = MAX_TEXT) -> str:
        parts = list(self.params.values())
        if self.raw_body:
            parts.append(self.raw_body)
        return " ".join(parts)[:limit]

    def signature(self) -> str:
        """Values (sorted by name) joined; used to compare successive requests to the same endpoint."""
        vals = [self.params[k] for k in sorted(self.params)]
        if self.raw_body:
            vals.append(self.raw_body)
        return "\x1f".join(vals)[:SIGNATURE_CHARS]


def _flatten_json(obj: Any, prefix: str, out: dict[str, str], depth: int = 0) -> None:
    if len(out) >= MAX_PARAMS:
        return
    if isinstance(obj, dict):
        if depth >= 4:
            out[prefix or "_json"] = json.dumps(obj, ensure_ascii=False)[:512]
            return
        for k, v in list(obj.items())[:MAX_PARAMS]:
            _flatten_json(v, f"{prefix}.{k}" if prefix else str(k), out, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:16]):
            _flatten_json(v, f"{prefix}[{i}]", out, depth + 1)
    elif obj is None:
        out[prefix or "_json"] = "null"
    else:
        out[prefix or "_json"] = str(obj)[:1024]


def parse_body(body: str | None, content_type: str | None) -> tuple[dict[str, str], str | None]:
    if not body:
        return {}, None
    b = body[:MAX_TEXT]
    ct = (content_type or "").lower()
    stripped = b.lstrip()
    if "json" in ct or stripped[:1] in ("{", "["):
        try:
            data = json.loads(b)
        except (ValueError, RecursionError):
            return {}, b
        params: dict[str, str] = {}
        _flatten_json(data, "", params)
        return params, None
    if "x-www-form-urlencoded" in ct or (not ct and "=" in b and " " not in b[:200]):
        try:
            pairs = parse_qsl(b, keep_blank_values=True, max_num_fields=MAX_PARAMS)
        except ValueError:
            return {}, b
        if pairs:
            return {k[:128]: v[:1024] for k, v in pairs}, None
    return {}, b


def parse_query(query: str | None) -> dict[str, str]:
    if not query:
        return {}
    q = query[:MAX_TEXT].lstrip("?")
    try:
        pairs = parse_qsl(q, keep_blank_values=True, max_num_fields=MAX_PARAMS)
    except ValueError:
        return {"_query": q[:1024]}
    if not pairs and q:
        return {"_query": unquote_plus(q)[:1024]}
    return {k[:128]: v[:1024] for k, v in pairs}


def extract_payload(
    path: str | None, query: str | None, body: str | None, content_type: str | None = None
) -> Payload:
    params = path_params(path)
    params.update(parse_query(query))
    body_params, raw = parse_body(body, content_type)
    for k, v in body_params.items():
        if len(params) >= MAX_PARAMS:
            break
        params.setdefault(k if k not in params else f"body.{k}", v)
    return Payload(params=params, raw_body=raw)


# Headers that are routinely set by infrastructure / frameworks; never treated as "payload" text.
_ROUTINE_HEADERS = frozenset(
    {
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-real-ip",
        "x-request-id",
        "x-correlation-id",
        "x-requested-with",
        "x-csrf-token",
        "x-xsrf-token",
        "x-amzn-trace-id",
        "x-cloud-trace-context",
    }
)


def custom_header_text(headers: Mapping[str, str] | None, limit: int = 1024) -> str:
    """Values of non-standard (``x-*``) headers; agents sometimes annotate requests there."""
    parts = [
        v
        for k, v in (headers or {}).items()
        if k.lower().startswith("x-") and k.lower() not in _ROUTINE_HEADERS and v
    ]
    return " ".join(parts)[:limit]


# ---------------------------------------------------------------------------------------------------------------
# Attack markers (light-weight; behavioural feature only)

_ATTACK_RULES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(p))
    for name, p in (
        (
            "sqli",
            r"""['"]\s{0,3}(?:or|and)\s{1,3}[\w'"]{1,20}\s{0,3}(?:=|like\b|>|<)|\bunion\b.{0,40}?\bselect\b"""
            r"""|\b(?:sleep|benchmark|pg_sleep)\s{0,3}\(|\bwaitfor\s{1,3}delay\b|information_schema"""
            r"""|['"]\s{0,3}(?:;|--|#|/\*)|\border\s{1,3}by\s{1,3}\d{1,3}\s{0,3}(?:--|#)|['"]\)+\s{0,3}(?:or|and)\b""",
        ),
        (
            "xss",
            r"<\s{0,3}script\b|<\s{0,3}(?:img|svg|iframe|body|details|video|audio|input)\b[^>]{0,80}?\bon[a-z]{3,15}\s{0,3}="
            r"|javascript\s{0,3}:|\bon(?:error|load|mouseover|focus|toggle)\s{0,3}=",
        ),
        (
            "traversal",
            r"(?:\.\.[/\\]){2,}|\.\.(?:%2f|%5c)|/etc/(?:passwd|shadow|hosts)\b|\bwin\.ini\b|%00|\x00",
        ),
        (
            "cmdi",
            r"(?:^|[;&|\n]|\$\()\s{0,3}(?:id|whoami|uname(?:\s+-a)?|cat\s{1,3}/\S{1,40}|ls\s{1,3}-|wget\s|curl\s|nc\s{1,3}-|bash\s{1,3}-|sh\s{1,3}-c|ping\s{1,3}-c)\b"
            r"|`\s{0,3}(?:id|whoami|uname|cat|ls)\b",
        ),
        ("template", r"\{\{[^}]{1,60}\}\}|\$\{[^}]{1,60}\}|<%=?[^%]{1,60}%>|#\{[^}]{1,60}\}"),
        (
            "ssrf",
            r"169\.254\.169\.254|metadata\.google\.internal|\b(?:gopher|dict|file|php|expect|jar)://"
            r"|https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1?\])",
        ),
        (
            "nosqli",
            r"""\[\$(?:ne|gt|lt|gte|lte|regex|where|in)\]|["']\$(?:ne|gt|lt|gte|lte|regex|where)["']""",
        ),
        ("proto_pollution", r"__proto__|constructor\s{0,3}\[\s{0,3}['\"]?prototype|constructor\.prototype"),
        ("xxe", r"<!doctype[^>]{0,80}\[|<!entity\b"),
        ("log4shell", r"\$\{(?:jndi|\$\{|lower:|upper:|env:)"),
    )
)


def attack_markers(text: str | None, *, normalized: bool = False) -> frozenset[str]:
    t = text if normalized else normalize_text(text)
    if not t:
        return frozenset()
    return frozenset(name for name, pat in _ATTACK_RULES if pat.search(t))


# ---------------------------------------------------------------------------------------------------------------
# Natural-language score

# Function words that are *not* code keywords. Their density marks prose.
_EN_STOPWORDS = frozenset(
    """
the a an this that these those it its we our us you your i my me let lets let's if whether because
to of for in at with about into should would could will can may might must need needs please
check checking checks test testing tests verify verifying see try trying attempt attempting determine
confirm confirming see whether here there what which who how why been being was were are be do does
just also only now first then next payload vulnerable vulnerability injection parameter bypass filter
""".split()  # noqa: SIM905 - readable word list
)

# Tokens that look like English but are code (SQL / JS / shell / HTML) — removed before measuring prose.
_CODE_KEYWORDS = frozenset(
    """
select union from where and or not null order by group having insert into values update set delete drop
table tables sleep benchmark waitfor delay exec execute char concat information_schema like limit offset
case when then else end as is all distinct join on true false script alert document cookie window onerror
onload img src svg iframe javascript prompt confirm eval function return var const http https www com
passwd etc bin sh bash cat id whoami ls echo curl wget nc cmd admin user users username password pass
version database schema columns column name xss sqli lfi rfi ssrf ssti xxe rce
""".split()  # noqa: SIM905 - readable word list
)

_EN_WORD_RE = re.compile(r"[a-z][a-z']{0,30}")
_JP_CHAR_RE = re.compile(r"[぀-ゟ゠-ヿ一-鿿ｦ-ﾟ]")
_HIRAGANA_RE = re.compile(r"[぀-ゟ]")
_JP_FUNCTION_RE = re.compile(
    r"です|ます|する|して|した|ため|かどうか|ください|確認|検証|テスト|試す|試し|脆弱"
)
_COMMENT_RE = re.compile(
    r"/\*(.{1,400}?)\*/|<!--(.{1,400}?)-->|(?:^|\s)--\s(.{1,300})|(?:^|\s)#\s(.{1,300})", re.S
)


@dataclass(frozen=True, slots=True)
class NLResult:
    score: float
    lang: str | None  # "en" / "ja" / None
    in_comment: bool = False
    sample: str = ""


def _clamp(x: float) -> float:
    return 0.0 if x <= 0 else 1.0 if x >= 1 else x


def _nl_text_score(text: str) -> tuple[float, str | None]:
    if not text:
        return 0.0, None
    jp = len(_JP_CHAR_RE.findall(text))
    jp_score = 0.0
    if jp >= 6:
        hira = len(_HIRAGANA_RE.findall(text))
        fn = len(_JP_FUNCTION_RE.findall(text))
        jp_score = 0.4 * _clamp(jp / 12) + 0.4 * _clamp((hira / jp) / 0.3) + 0.2 * _clamp(fn / 2)
    words = [w for w in _EN_WORD_RE.findall(text.lower()) if w not in _CODE_KEYWORDS]
    en_score = 0.0
    if len(words) >= 4:
        stops = [w for w in words if w in _EN_STOPWORDS]
        distinct = len(set(stops))
        if distinct >= 2:
            ratio = len(stops) / len(words)
            en_score = (
                0.35 * _clamp(len(words) / 8) + 0.45 * _clamp(ratio / 0.35) + 0.2 * _clamp(distinct / 3)
            )
    if jp_score >= en_score:
        return round(jp_score, 3), ("ja" if jp_score > 0 else None)
    return round(en_score, 3), "en"


def extract_comments(text: str) -> list[str]:
    out: list[str] = []
    for m in _COMMENT_RE.finditer(text[:MAX_TEXT]):
        frag = next((g for g in m.groups() if g), "")
        if frag.strip():
            out.append(frag.strip())
        if len(out) >= 8:
            break
    return out


def natural_language_score(text: str | None) -> NLResult:
    """0..1 "is there an explanatory sentence in here" score, English or Japanese.

    Comments inside payloads (``-- ...``, ``/* ... */``, ``<!-- ... -->``, ``# ...``) are scored separately and get a
    small bonus: explaining *inside the payload* what the payload does is a habit of LLM-generated requests
    (hypothesis H4 in docs/detection/ai-attacks.md).
    """
    if not text:
        return NLResult(0.0, None)
    raw = text[:MAX_TEXT]
    try:
        decoded = unquote_plus(raw) if "%" in raw else raw
    except Exception:  # pragma: no cover - unquote is lenient
        decoded = raw
    decoded = unicodedata.normalize("NFKC", html.unescape(decoded) if "&" in decoded else decoded)
    best = NLResult(0.0, None)
    for c in extract_comments(decoded):
        s, lang = _nl_text_score(c)
        s = min(1.0, s + 0.1) if s >= 0.4 else s
        if s > best.score:
            best = NLResult(round(s, 3), lang, True, c[:160])
    s, lang = _nl_text_score(decoded)
    if s > best.score:
        best = NLResult(s, lang, False, decoded[:160])
    return best


# ---------------------------------------------------------------------------------------------------------------
# Similarity / entropy


def shingles(text: str, n: int = 3, limit: int = SIGNATURE_CHARS) -> frozenset[str]:
    t = text[:limit]
    if len(t) <= n:
        return frozenset({t}) if t else frozenset()
    return frozenset(t[i : i + n] for i in range(len(t) - n + 1))


def jaccard(a: Iterable[Any], b: Iterable[Any]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb)


def edit_distance(a: str, b: str, cap: int = 128) -> int:
    """Levenshtein distance on the first ``cap`` chars (O(cap^2); only used on candidate pairs)."""
    a, b = a[:cap], b[:cap]
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def edit_similarity(a: str, b: str, cap: int = 128) -> float:
    a, b = a[:cap], b[:cap]
    longest = max(len(a), len(b))
    if longest == 0:
        return 1.0
    return 1.0 - edit_distance(a, b, cap) / longest


def payload_similarity(a: str, b: str) -> float:
    """Cheap similarity for successive payloads: trigram Jaccard (fast) on the signatures."""
    if a == b:
        return 1.0
    return jaccard(shingles(a), shingles(b))


def shannon_entropy(text: str | None) -> float:
    """Bits per character."""
    if not text:
        return 0.0
    t = text[:MAX_TEXT]
    counts = Counter(t)
    n = len(t)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


SEMANTIC_TEST_TOKENS = frozenset(
    {
        "test",
        "testing",
        "verify",
        "probe",
        "check",
        "example",
        "sample",
        "demo",
        "dummy",
        "hello",
        "foo",
        "bar",
        "poc",
        "canary",
        "payload",
        "pentest",
    }
)


def semantic_test_tokens(text: str | None) -> int:
    """Count meaningful 'test-like' values (informational; LLMs tend to pick readable test values)."""
    if not text:
        return 0
    return sum(1 for w in _EN_WORD_RE.findall(text[:MAX_TEXT].lower()) if w in SEMANTIC_TEST_TOKENS)
