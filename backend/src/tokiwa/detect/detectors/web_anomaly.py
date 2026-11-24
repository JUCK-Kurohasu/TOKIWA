"""Request-shape anomalies that the signature detectors cannot see: the request is built to hide from inspection.

These detectors read what the Gate records about a request it could not capture completely (tags / labels set
by ``tokiwa.gate.capture``), plus the parts of the request itself that only make sense as evasion:

* ``web.header_anomaly`` (audit #140) - far more header lines than a client sends (padding to push headers out
  of the sensor's capture), or one of the non-list headers (Host, Content-Length ...) sent twice.
* ``web.uninspectable_body`` (audit #141) - a request body behind a ``Content-Encoding`` the Gate could not undo
  (br / zstd / deeper stacks, or a corrupt gzip / deflate stream): no body detector saw what the application got.
* ``web.route_override`` (audit #147) - ``X-Original-URL`` / ``X-Rewrite-URL`` / ``X-Override-URL``: an upstream
  that honours them serves another path than the request line names (decoys and path-based detection bypassed).
* ``web.deceptive_unicode`` (audit #150) - bidi controls (U+202E ...), zero-width or tag characters in the path,
  User-Agent or header values: text that reads differently to a human than to a machine (Trojan Source).

Each alert carries ``details.signatures`` (indicator ids), ``location`` and ``param`` like the ``web.*``
signature alerts, so marking one false positive suppresses that indicator only (``detect.suppress.match_of``).
Severities stay at low / medium: these say "something was hidden or disguised", not what. Rule-based triage
proposes response actions only from high, so none of these alone puts the source IP on a block proposal.
"""

from __future__ import annotations

import unicodedata
from typing import Any

from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.web_common import (
    PATH,
    ROUTE_OVERRIDE_HEADERS,
    HttpView,
    clean_label,
    differing_override_paths,
    get_view,
    rx,
    web_settings,
)
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind

_M, _L = Severity.MEDIUM, Severity.LOW

# Gate tags / labels (tokiwa.gate.capture / tokiwa.gate.app). Read as data: the Gate is the only sensor that sees
# the raw header block, an access log or another sensor simply never sets them.
TAG_HEADERS_TRUNCATED = "gate:headers_truncated"
TAG_TOO_MANY_HEADERS = "gate:too_many_headers"
TAG_DUPLICATE_HEADER = "gate:duplicate_header"
LABEL_HEADER_COUNT = "gate.header_count"  # header lines received (set when the capture was truncated)
LABEL_HEADERS_DROPPED = "gate.headers_dropped"  # lines whose names did not fit the 64 recorded names
LABEL_DUPLICATE_HEADERS = "gate.duplicate_headers"  # non-list headers that arrived more than once
TAG_REQ_ENCODING_UNKNOWN = "gate:req_encoding_unknown"  # coding the Gate does not inflate: body not recorded
# declared gzip / deflate, not a valid stream: the raw prefix is recorded
TAG_REQ_DECODE_FAILED = "gate:req_decode_failed"
LABEL_REQUEST_ENCODING = "gate.request_encoding"
TAG_ROUTE_OVERRIDE = "gate:route_override"  # X-Original-URL & co. present (every Gate path, since #147)
LABEL_ACTION = "gate.action"  # proxy | decoy | deceive | blocked | ...
LABEL_STRIPPED_HEADERS = "gate.stripped_headers"  # client headers removed before forwarding (proxy path only)

# Duplicates of these decide where a request goes or where it ends: RFC 9112 requires a 400 for several Host
# lines and rejecting differing Content-Length values, so a front end and a back end that pick different copies
# route or frame the request differently (request smuggling / routing confusion).
FRAMING_DUPLICATES = frozenset({"host", "content-length", "transfer-encoding"})
MAX_NAMES_SAMPLE = 8


def _draft(
    det: Detector,
    event: Event,
    view: HttpView,
    found: list[tuple[Severity, str, str]],
    *,
    location: str,
    param: str | None,
    extra: dict[str, Any],
    confidence: float = 0.6,
) -> list[AlertDraft]:
    """One alert from (severity, indicator id, human label) findings; the most severe drives the title."""
    found = sorted(found, key=lambda f: f[0].rank, reverse=True)
    severity, top, label = found[0]
    ids = list(dict.fromkeys(f[1] for f in found))
    details: dict[str, Any] = {
        "matched": label,
        "signature": top,
        "signatures": ids,
        "location": location,
        "param": param,
        "indicators": [{"signature": f[1], "severity": f[0].value, "detail": f[2]} for f in found],
        "method": view.method,
        "status": view.status,
    }
    details.update(extra)
    return [
        det.draft(
            event,
            title=f"{det.name}: {label}"[:200],
            description=det.description,
            severity=severity,
            confidence=round(min(0.9, confidence + 0.05 * (len(ids) - 1)), 2),
            entities=view.entities(param),
            tags=list(dict.fromkeys(["web", det.id.removeprefix("web."), *ids])),
            fingerprint=f"{det.id}|{event.source_ip or '-'}|{top}",
            details=details,
        )
    ]


# ---------------------------------------------------------------------------------------------------------
# web.header_anomaly (audit #140)
# ---------------------------------------------------------------------------------------------------------


def header_line_count(event: Event) -> tuple[int, bool]:
    """(header lines, exact). The Gate records the exact count only when it had to cut the capture; otherwise the
    recorded names / arrival order are the best estimate (repeats of one name are folded, so it can be low)."""
    raw = (event.labels or {}).get(LABEL_HEADER_COUNT, "")
    if raw.isdigit():
        return int(raw), True
    http = event.http
    if http is None:
        return 0, False
    return max(len(http.headers), len(http.header_order)), False


@register_detector
class HeaderAnomalyDetector(Detector):
    id = "web.header_anomaly"
    name = "Abnormal request headers"
    description = (
        "Far more header lines than browsers and HTTP libraries send (padding that pushes headers out of the "
        "sensor's capture: the Gate records 64 names and refuses more than gate.max_request_headers lines), or a "
        "non-list header such as Host or Content-Length sent twice (front end and application may read "
        "different copies). Compare the recorded headers with the request the application logged."
    )
    category = AlertCategory.ANOMALY
    kinds = frozenset({EventKind.HTTP})
    mitre = ("T1190",)
    default_severity = _L

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        view = get_view(event, ctx)
        if view is None or event.http is None:
            return []
        cfg = web_settings(ctx.settings)
        tags = set(event.tags)
        labels = event.labels or {}
        count, exact = header_line_count(event)
        dropped_raw = labels.get(LABEL_HEADERS_DROPPED, "")
        dropped = int(dropped_raw) if dropped_raw.isdigit() else 0
        found: list[tuple[Severity, str, str]] = []

        if TAG_TOO_MANY_HEADERS in tags:
            found.append((_M, "header_anomaly.rejected", "header lines over the Gate limit (431)"))
        if dropped > 0:
            found.append(
                (_M, "header_anomaly.capture_dropped", f"{count} header lines, {dropped} not recorded")
            )
        if cfg.header_count_medium and count > cfg.header_count_medium:
            found.append((_M, "header_anomaly.count", f"{count} header lines"))
        elif cfg.header_count_low and count > cfg.header_count_low:
            found.append((_L, "header_anomaly.count", f"{count} header lines"))

        duplicates = [
            d.strip().lower() for d in labels.get(LABEL_DUPLICATE_HEADERS, "").split(",") if d.strip()
        ]
        if duplicates or TAG_DUPLICATE_HEADER in tags:
            shown = ", ".join(clean_label(d, 40) for d in duplicates[:8]) or "?"
            if any(d in FRAMING_DUPLICATES for d in duplicates):
                found.append((_M, "header_anomaly.duplicate_framing", f"duplicate {shown}"))
            else:
                found.append((_L, "header_anomaly.duplicate", f"duplicate {shown}"))
        if not found:
            return []

        names = event.http.header_order or list(event.http.headers)
        return _draft(
            self,
            event,
            view,
            found,
            location="header",
            param=None,
            extra={
                "header_count": count,
                "header_count_exact": exact,
                "headers_dropped": dropped,
                "headers_truncated": TAG_HEADERS_TRUNCATED in tags,
                "duplicate_headers": duplicates[:16],
                # attacker-chosen names: a short, printable sample of the tail (the padding is usually there)
                "header_names_sample": [clean_label(n, 40) for n in names[-MAX_NAMES_SAMPLE:]],
            },
        )


# ---------------------------------------------------------------------------------------------------------
# web.uninspectable_body (audit #141)
# ---------------------------------------------------------------------------------------------------------


@register_detector
class UninspectableBodyDetector(Detector):
    id = "web.uninspectable_body"
    name = "Request body hidden behind Content-Encoding"
    description = (
        "The request body uses a Content-Encoding the Gate does not undo (br, zstd, compress, more than two "
        "codings) or a gzip / deflate stream that does not inflate, so no body detector saw the content. "
        "Applications that inflate request bodies (or ignore Content-Encoding and read the bytes as they are) "
        "still process it. Medium when the application accepted the request (status below 400)."
    )
    category = AlertCategory.ANOMALY
    kinds = frozenset({EventKind.HTTP})
    mitre = ("T1190",)
    default_severity = _L

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        tags = set(event.tags)
        unknown = TAG_REQ_ENCODING_UNKNOWN in tags
        if not unknown and TAG_REQ_DECODE_FAILED not in tags:
            return []
        view = get_view(event, ctx)
        if view is None or event.http is None:
            return []
        status = view.status
        accepted = status is not None and 200 <= status < 400
        coding = clean_label(view.headers.get("content-encoding", ""), 60) or "?"
        found: list[tuple[Severity, str, str]] = []
        if unknown:
            # Nothing of the body is on the event: the application may have read a payload nobody inspected.
            severity = _M if accepted else _L
            found.append(
                (severity, "body.encoding_unknown", f"body not inspected (Content-Encoding: {coding})")
            )
        else:
            # The Gate kept the raw prefix (body detectors ran on it); an upstream that cannot inflate it either
            # usually rejects the request, so this is mostly fuzzing or a broken client.
            found.append((_L, "body.decode_failed", f"corrupt compressed body (Content-Encoding: {coding})"))
        return _draft(
            self,
            event,
            view,
            found,
            location="body",
            param=None,
            confidence=0.55,
            extra={
                "content_encoding": coding,
                "request_encoding": clean_label((event.labels or {}).get(LABEL_REQUEST_ENCODING, ""), 40),
                "request_body_size": event.http.request_body_size,
                "upstream_accepted": accepted,
            },
        )


# ---------------------------------------------------------------------------------------------------------
# web.route_override (audit #147)
# ---------------------------------------------------------------------------------------------------------


def passed_through(event: Event, header: str) -> bool:
    """True when the Gate forwarded ``header`` because the operator allows it (``gate.forward_client_headers``,
    a trusted front proxy sets it). Needs positive evidence: a Gate that knows the header (``gate:route_override``)
    proxied the request and did not list it as stripped. Without the tag (an older Gate that still forwards these
    headers, or another sensor) the header counts as client-sent."""
    labels = event.labels or {}
    if TAG_ROUTE_OVERRIDE not in event.tags or labels.get(LABEL_ACTION) != "proxy":
        return False
    return header not in labels.get(LABEL_STRIPPED_HEADERS, "").split(",")


@register_detector
class RouteOverrideDetector(Detector):
    id = "web.route_override"
    name = "Routing override header"
    description = (
        "X-Original-URL / X-Rewrite-URL / X-Override-URL in a client request: IIS URL Rewrite, legacy Symfony / "
        "Zend and some Java filters serve the header's path instead of the request line's, which bypasses "
        "path-based access control, decoys and path-based detection. The Gate strips these headers (and serves "
        "the decoy when the header names one); check whether the application behind other paths honours them."
    )
    category = AlertCategory.EXPLOIT_ATTEMPT
    kinds = frozenset({EventKind.HTTP})
    mitre = ("T1190",)
    default_severity = _M

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        view = get_view(event, ctx)
        if view is None:
            return []
        if not any(h in view.headers for h in ROUTE_OVERRIDE_HEADERS):
            return []
        rounds = web_settings(ctx.settings).max_decode_rounds
        found: list[tuple[Severity, str, str]] = []
        targets: dict[str, str] = {}
        top_header = ""
        # a front end repeating the request line (IIS ARR, nginx "X-Original-URL $request_uri") is left out
        for header, target in differing_override_paths(view.headers, view.path_clean, rounds):
            if passed_through(event, header):
                continue
            targets[header] = clean_label(target, 200)
            if not target:
                found.append((_L, "route_override.empty", f"{header} without a path"))
                top_header = top_header or header
            else:
                shown = f"{clean_label(target, 100)} (request line {clean_label(view.path_clean, 60)})"
                found.append((_M, "route_override.different_path", f"{header}: {shown}"))
                if not targets.get(top_header):  # the first header naming another path drives the alert
                    top_header = header
        if not found:
            return []
        return _draft(
            self,
            event,
            view,
            found,
            location="header_custom",
            param=top_header,
            extra={
                "override_paths": targets,
                "request_path": clean_label(view.path_clean, 200),
                "gate_action": clean_label((event.labels or {}).get(LABEL_ACTION, ""), 40) or None,
            },
        )


# ---------------------------------------------------------------------------------------------------------
# web.deceptive_unicode (audit #150)
# ---------------------------------------------------------------------------------------------------------

# Every code point below is written as an escape: a literal U+202E in this file would reorder the source itself.
# Embeddings / overrides / isolates reorder what follows them; no path, User-Agent or header needs them.
BIDI_CONTROLS = frozenset([*range(0x202A, 0x202F), *range(0x2066, 0x206A)])
# Invisible in any context (ZERO WIDTH SPACE, WORD JOINER, BOM / ZERO WIDTH NO-BREAK SPACE).
ZERO_WIDTH = frozenset({0x200B, 0x2060, 0xFEFF})
# Part of normal text in some scripts: ZWNJ / ZWJ (Persian, Indic scripts, emoji sequences), LRM / RLM / ALM in
# right-to-left text, MONGOLIAN VOWEL SEPARATOR, Hangul fillers. Flagged only next to an ASCII character or at the
# start / end of the value ("/.e<ZWJ>nv"), never between two letters of such a script.
CONTEXTUAL = frozenset({0x200C, 0x200D, 0x200E, 0x200F, 0x061C, 0x180E, 0x115F, 0x1160, 0x3164, 0xFFA0})
TAG_FIRST, TAG_LAST = 0xE0000, 0xE007F  # tag characters ("ASCII smuggling"); legitimate only in flag emoji
BLACK_FLAG = 0x1F3F4  # subdivision flags are U+1F3F4 + tag characters + U+E007F
# Kept in line with the UI's BIDI_RE (frontend/src/components/common/invisible.ts) for the reordering set.
_CANDIDATES = rx(
    r"[\u061c\u115f\u1160\u180e\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\u3164\ufeff\uffa0"
    r"\U000e0000-\U000e007f]",
    "deceptive_unicode.candidates",
)
MAX_UNICODE_LOCATIONS = 8


def as_received(value: str) -> str:
    """Header values as the client wrote them. The Gate decodes header bytes as latin-1 (HTTP's default), so a
    UTF-8 U+202E arrives as three latin-1 characters; undo that when the value is valid UTF-8."""
    if value.isascii():
        return value
    try:
        return value.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return value  # real code points (another sensor, JSON ingest) or not UTF-8


# Candidates examined per field / per event. Every match costs Python work, and a header full of joiners between
# non-ASCII letters (never flagged) would otherwise cost ~1 us per character on the detection loop. Hitting a cap
# is itself reported (``unicode.excessive``): hundreds of format characters in a path or header are not text.
MAX_FIELD_CANDIDATES = 512
MAX_EVENT_CANDIDATES = 2048
EXCESSIVE = "unicode.excessive"


def _contextual_kind(text: str, i: int, cp: int) -> str | None:
    left = text[i - 1] if i > 0 else ""
    right = text[i + 1] if i + 1 < len(text) else ""
    if not left or not right or left.isascii() or right.isascii():
        return "unicode.bidi_control" if cp in (0x200E, 0x200F, 0x061C) else "unicode.zero_width"
    return None


def deceptive_code_points(text: str, limit: int = MAX_FIELD_CANDIDATES) -> tuple[list[str], list[int], int]:
    """(indicator ids, code points, candidates examined) for ``text``; ids and code points are listed once.

    One forward pass: a run of tag characters is judged once, by the character in front of it (a flag emoji
    starts with U+1F3F4), so the cost stays linear in the number of candidates (at most ``limit``).
    """
    kinds: list[str] = []
    cps: list[int] = []
    run_end, run_is_flag = -1, False
    examined = 0
    for m in _CANDIDATES.finditer(text):
        if examined >= limit:
            kinds.append(EXCESSIVE)
            break
        examined += 1
        i, cp = m.start(), ord(m.group())
        kind: str | None
        if cp in BIDI_CONTROLS:
            kind = "unicode.bidi_control"
        elif cp in ZERO_WIDTH:
            kind = "unicode.zero_width"
        elif TAG_FIRST <= cp <= TAG_LAST:
            if i != run_end:  # a new run of tag characters starts here
                run_is_flag = i > 0 and ord(text[i - 1]) == BLACK_FLAG
            run_end = i + 1
            kind = None if run_is_flag else "unicode.tag_characters"
        else:
            kind = _contextual_kind(text, i, cp)
        if kind is None:
            continue
        if kind not in kinds:
            kinds.append(kind)
        if cp not in cps:
            cps.append(cp)
    return kinds, cps, examined


def code_point_label(cp: int) -> str:
    name = unicodedata.name(chr(cp), "")
    return f"U+{cp:04X}" + (f" {name}" if name else "")


def escape_deceptive(text: str, limit: int = 160) -> str:
    """Printable excerpt around the first candidate, each candidate shown as ``<U+XXXX>``."""
    first = _CANDIDATES.search(text)
    start = max(0, first.start() - 40) if first else 0
    excerpt = text[start : start + limit]
    shown = _CANDIDATES.sub(lambda m: f"<U+{ord(m.group()):04X}>", excerpt)
    return ("..." if start else "") + clean_label(shown, limit + 60)


@register_detector
class DeceptiveUnicodeDetector(Detector):
    id = "web.deceptive_unicode"
    name = "Invisible or bidi control characters"
    description = (
        "Bidirectional controls (U+202A-U+202E, U+2066-U+2069), zero-width characters (U+200B, U+2060, U+FEFF; "
        "ZWNJ / ZWJ / LRM / RLM next to ASCII) or tag characters in the request path, User-Agent or a header "
        "value. Such text is displayed differently from what it is: '/invoice<U+202E>fdp.exe' reads as "
        "'invoiceexe.pdf', '/.e<U+200B>nv' as '/.env'. Clients have no reason to send them there; it is an "
        "attempt to mislead whoever reads the logs (or an LLM reading them). The UI shows them as <U+XXXX>."
    )
    category = AlertCategory.ANOMALY
    kinds = frozenset({EventKind.HTTP})
    mitre = ("T1036.002",)
    default_severity = _L

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        view = get_view(event, ctx)
        if view is None:
            return []
        # (location, param, text). Query strings and bodies are left out: right-to-left and emoji text legitimately
        # carries marks and joiners there.
        fields: list[tuple[str, str | None, str]] = []
        path = next((t for t in view.targets if t.location == PATH), None)
        if path is not None:
            fields.append(("path", None, path.decoded))
        ua = view.headers.get("user-agent")
        if ua:
            fields.append(("header", "user-agent", as_received(ua)))
        fields += [
            ("header", name, as_received(value))
            for name, value in view.headers.items()
            if name != "user-agent" and value and not value.isascii()
        ]
        found: list[tuple[Severity, str, str]] = []
        per_location: dict[str, list[str]] = {}
        excerpts: dict[str, str] = {}
        top: tuple[str, str | None] | None = None
        budget = MAX_EVENT_CANDIDATES
        for location, param, text in fields:
            if text.isascii():
                continue
            cps: list[int]
            if budget <= 0:  # earlier fields used up the event's budget: that alone is abnormal
                kinds, cps = [EXCESSIVE], []
            else:
                kinds, cps, examined = deceptive_code_points(text, min(MAX_FIELD_CANDIDATES, budget))
                budget -= examined
            if not kinds:
                continue
            where = param or location
            per_location[where] = [code_point_label(cp) for cp in cps[:8]]
            excerpts[where] = escape_deceptive(text)
            shown = ", ".join(f"U+{cp:04X}" for cp in cps[:4]) or "hundreds of format characters"
            for kind in kinds:
                found.append((_L, kind, f"{shown} in {where}"))
            top = top or (location, param)
            if len(per_location) >= MAX_UNICODE_LOCATIONS or budget <= 0:
                break
        if not found or top is None:
            return []
        return _draft(
            self,
            event,
            view,
            found,
            location=top[0],
            param=top[1],
            confidence=0.6,
            extra={"code_points": per_location, "excerpts": excerpts},
        )
