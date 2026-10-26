"""web.xxe - XML external entity injection and entity-expansion (billion laughs) payloads.

Legitimate XML APIs essentially never send a DTD with ``<!ENTITY ... SYSTEM>`` declarations, so these hits are
high-fidelity. The W3C XHTML doctype (``http://www.w3.org/...dtd``) is excluded from the external-DTD signature.
Known limitation: only the captured body prefix is visible (Gate default 4 KiB) - a DTD placed after a large
benign prefix is missed.
"""

from __future__ import annotations

from tokiwa.detect.base import register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.web_common import (
    BODY,
    BODY_RAW,
    COOKIE,
    FILENAME,
    QUERY,
    Hit,
    Signature,
    WebSignatureDetector,
    get_view,
    rx,
    sig,
)
from tokiwa.schemas.alerts import AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event

_H, _M = Severity.HIGH, Severity.MEDIUM

_ENTITY_DECL = rx(r"<!entity\s", "xxe.entity_decl_count")
_EXPANSION_MIN_ENTITIES = 5

_SIG_EXPANSION = Signature(
    id="xxe.entity_expansion",
    pattern=_ENTITY_DECL,
    severity=_H,
    confidence=0.85,
    view="lower",
    locations=None,
    description=f"entity expansion DoS (>= {_EXPANSION_MIN_ENTITIES} <!ENTITY> declarations)",
    mitre=("T1499",),
)


@register_detector
class XxeDetector(WebSignatureDetector):
    id = "web.xxe"
    name = "XML external entity (XXE) attempt"
    description = (
        "XML body or parameter declaring external/parameter entities (<!DOCTYPE + <!ENTITY ... SYSTEM>), "
        "external DTDs, XInclude, or many nested entities (billion laughs)."
    )
    family = "xxe"
    mitre = ("T1190",)
    default_severity = _H
    locations = frozenset({BODY, BODY_RAW, QUERY, COOKIE, FILENAME})
    signatures = (
        sig(
            "xxe.external_entity",
            r"<!entity\s{1,10}(?:%\s{1,10})?[\w.:-]{1,64}\s{1,10}(?:system|public)\b",
            _H,
            confidence=0.9,
            view="lower",
            description="<!ENTITY ... SYSTEM/PUBLIC> external entity",
        ),
        sig(
            "xxe.parameter_entity",
            r"<!entity\s{1,10}%\s{1,10}[\w.:-]{1,64}",
            _H,
            confidence=0.85,
            view="lower",
            description="parameter entity (<!ENTITY % ...>, out-of-band XXE)",
        ),
        sig(
            "xxe.external_dtd",
            r"<!doctype\s{1,10}[\w.:-]{1,64}\s{1,10}(?:system|public)\s[^>]{0,200}?['\"]"
            r"(?:https?|ftp|file|php|jar|gopher|netdoc|expect)://(?!(?:www\.)?w3\.org/)",
            _H,
            confidence=0.8,
            view="lower",
            description="external DTD reference",
        ),
        sig(
            "xxe.xinclude",
            r"<xi:include\b|xmlns:xi\s{0,5}=\s{0,5}['\"]https?://www\.w3\.org/2001/xinclude",
            _H,
            confidence=0.85,
            view="lower",
            description="XInclude",
        ),
        sig(
            "xxe.internal_subset",
            r"<!doctype[^>\[]{0,200}\[\s{0,10}<!(?:entity|element|attlist)",
            _M,
            confidence=0.65,
            view="lower",
            description="DOCTYPE with internal subset declaring entities",
        ),
    )

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        view = get_view(event, ctx)
        if view is None:
            return []
        hits = self.scan(view)
        for t in view.targets:
            if t.location in self.locations and t.lower.count("<!entity") >= _EXPANSION_MIN_ENTITIES:
                start = t.lower.find("<!entity")
                hits.append(Hit(_SIG_EXPANSION, t.location, t.param, t.lower[start : start + 200]))
                break
        return self.build_alert(event, view, hits)
