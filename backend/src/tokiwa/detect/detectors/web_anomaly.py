"""Request-shape anomalies that the signature detectors cannot see: the request is built to hide from inspection.

These detectors read what the Gate records about a request it could not capture completely (tags / labels set
by ``tokiwa.gate.capture``), plus the parts of the request itself that only make sense as evasion:

* ``web.header_anomaly`` (audit #140) - far more header lines than a client sends (padding to push headers out
  of the sensor's capture), or one of the non-list headers (Host, Content-Length ...) sent twice.
* ``web.uninspectable_body`` (audit #141) - a request body behind a ``Content-Encoding`` the Gate could not undo
  (br / zstd / deeper stacks, or a corrupt gzip / deflate stream): no body detector saw what the application got.
* ``web.route_override`` (audit #147) - ``X-Original-URL`` / ``X-Rewrite-URL`` / ``X-Override-URL``: an upstream
  that honours them serves another path than the request line names (decoys and path-based detection bypassed).

Each alert carries ``details.signatures`` (indicator ids), ``location`` and ``param`` like the ``web.*``
signature alerts, so marking one false positive suppresses that indicator only (``detect.suppress.match_of``).
Severities stay at low / medium: these say "something was hidden or disguised", not what. Rule-based triage
proposes response actions only from high, so none of these alone puts the source IP on a block proposal.
"""

from __future__ import annotations

from typing import Any

from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.web_common import (
    ROUTE_OVERRIDE_HEADERS,
    HttpView,
    clean_label,
    get_view,
    override_path,
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
        present = [h for h in ROUTE_OVERRIDE_HEADERS if h in view.headers and not passed_through(event, h)]
        if not present:
            return []
        rounds = web_settings(ctx.settings).max_decode_rounds
        # Front ends (IIS ARR, App Service, nginx "X-Original-URL $request_uri") set the header to the URL they
        # received, which is the request line again, possibly behind a stripped X-Forwarded-Prefix: not a bypass.
        same = {view.path_clean}
        prefix = override_path(view.headers.get("x-forwarded-prefix", ""), rounds).rstrip("/")
        if prefix:
            same.add(prefix + view.path_clean)
        found: list[tuple[Severity, str, str]] = []
        targets: dict[str, str] = {}
        top_header = ""
        for header in present:
            target = override_path(view.headers[header], rounds)
            if target in same:
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
