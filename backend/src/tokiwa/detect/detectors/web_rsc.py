"""web.rsc_action_abuse - malicious React Server Components "Flight" replies (Next.js Server Actions).

Background (CVE-2025-55182, "React2Shell", disclosed 2025-12-03; react-server-dom-* 19.0.0/19.1.0/19.1.1/19.2.0):
the server-side decoder of RSC replies resolves ``$<id>:<prop>:<prop>`` reference paths. Crafted references
walk into ``__proto__`` / ``constructor`` and fake internal chunk objects, reaching the ``Function``
constructor -> unauthenticated RCE. Public exploits POST ``multipart/form-data`` to any page with a
``Next-Action`` header.

What is matched (structural, version-independent):

* ``rsc.proto_ref`` - a Flight reference path that touches ``__proto__``/``constructor``/``prototype``
  (``"$1:__proto__:then"``, ``"$1:constructor:constructor"``). Legitimate React clients never emit these.
* ``rsc.fake_chunk`` - a hand-made chunk object (``"status":"resolved_model"``).
  TODO(verify): exact internal field names are taken from the publicly circulated PoC (Dec 2025); confirm
  against the patched react-server-dom-webpack source before relying on them alone.
* ``rsc.internal_fields`` / ``rsc.then_ref`` / ``rsc.proto_key`` - weaker indicators (``"_response"``,
  ``"_formData"``, ``"_prefix"``, ``"then":"$..."``, ``"__proto__":``) that only count inside an RSC context
  (Next-Action / RSC header, text/x-component) or next to a strong indicator.
* ``rsc.action_id_probe`` - a ``Next-Action`` header whose value is not a hex action id (scanner probes send
  ``Next-Action: x``). TODO(verify): action-id format differs across Next.js versions (40+ hex chars observed).

Known limitations: the Gate's header allow-list may drop ``Next-Action``; the body-only indicators still fire.
Only the captured body prefix (Gate default 4 KiB) is inspected.
"""

from __future__ import annotations

from tokiwa.detect.base import register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.web_common import (
    BODY,
    BODY_RAW,
    Hit,
    HttpView,
    Signature,
    WebSignatureDetector,
    clean_label,
    get_view,
    rx,
    sig,
)
from tokiwa.schemas.alerts import AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event

_C, _H, _M, _L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

_STRONG = frozenset({"rsc.proto_ref", "rsc.fake_chunk"})
_ACTION_ID = rx(r"[0-9a-f]{40,128}", "rsc.action_id")

_SIG_ACTION_PROBE = Signature(
    id="rsc.action_id_probe",
    pattern=_ACTION_ID,
    severity=_L,
    confidence=0.3,
    view="raw",
    locations=None,
    description="Next-Action header with a non-hex action id (probe)",
    mitre=(),
)


def rsc_context(view: HttpView) -> str | None:
    """Why this request is an RSC/Server Action request (None if it does not look like one)."""
    h = view.headers
    if "next-action" in h:
        return "next-action header"
    if h.get("rsc", "").strip() == "1":
        return "rsc header"
    if "text/x-component" in view.content_type or "text/x-component" in h.get("accept", "").lower():
        return "text/x-component"
    if "next-router-state-tree" in h:
        return "next-router-state-tree header"
    return None


@register_detector
class RscActionAbuseDetector(WebSignatureDetector):
    id = "web.rsc_action_abuse"
    name = "React Server Components / Server Action payload abuse"
    description = (
        "Crafted RSC Flight reply reaching __proto__/constructor through $-reference paths or faking internal "
        "chunk objects, as used against CVE-2025-55182 (React2Shell) via Next.js Server Actions."
    )
    family = "rsc"
    mitre = ("T1190", "T1059.007")
    default_severity = _C
    locations = frozenset({BODY, BODY_RAW})
    signatures = (
        sig(
            "rsc.proto_ref",
            r"\$[@a-z]?\d{0,8}(?::[\w$]{1,64}){0,8}:(?:__proto__|constructor|prototype)\b",
            _H,
            confidence=0.85,
            view="lower",
            description="Flight $-reference path into __proto__/constructor",
        ),
        sig(
            "rsc.fake_chunk",
            r"[\"']status[\"']\s{0,5}:\s{0,5}[\"']resolved_model[\"']",
            _H,
            confidence=0.8,
            view="lower",
            description="hand-crafted Flight chunk object (status: resolved_model)",
        ),
        sig(
            "rsc.internal_fields",
            r"[\"']_(?:response|formdata|prefix|chunks|fromjson|bundlerconfig|tempreferences)[\"']\s{0,5}:",
            _H,
            confidence=0.7,
            view="lower",
            description="internal Flight response fields (_response/_formData/_prefix)",
        ),
        sig(
            "rsc.then_ref",
            r"[\"']then[\"']\s{0,5}:\s{0,5}[\"']\$[@a-z]?\d",
            _M,
            confidence=0.6,
            view="lower",
            description="thenable hijack (then: $-reference)",
        ),
        sig(
            "rsc.proto_key",
            r"[\"']__proto__[\"']\s{0,5}:|[\"']constructor[\"']\s{0,5}:\s{0,5}\{\s{0,5}[\"']prototype[\"']",
            _M,
            confidence=0.6,
            view="lower",
            description="__proto__ key (prototype pollution)",
        ),
    )

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        view = get_view(event, ctx)
        if view is None:
            return []
        context = rsc_context(view)
        hits = self.scan(view)
        strong = any(h.sig.id in _STRONG for h in hits)
        if not context and not strong:
            hits = []
        action = view.headers.get("next-action")
        if action is not None and not _ACTION_ID.fullmatch(action.strip().lower()):
            hits.append(Hit(_SIG_ACTION_PROBE, "header", "next-action", clean_label(action, 200)))
        if not hits:
            return []
        severity = _C if context and strong else None
        return self.build_alert(
            event,
            view,
            hits,
            severity=severity,
            extra_tags=("cve-2025-55182",),
            extra_details={"rsc_context": context},
        )
