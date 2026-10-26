"""web.xss - cross-site scripting attempts (script/iframe tags, on*= handlers, javascript: URIs, CSTI).

Runs on the ``norm`` view, so ``%3Cscript%3E``, ``&lt;script&gt;``, ``\\u003cscript``, full-width ``＜script＞``
and ``java&#x09;script:`` are covered. Known limitation: applications that legitimately accept rich HTML
(CMS editors) will see medium-severity hits for ``<iframe>`` / ``javascript:void(0)`` - tune via the detector
overrides or a suppression rule.
"""

from __future__ import annotations

from tokiwa.detect.base import register_detector
from tokiwa.detect.web_common import WebSignatureDetector, sig
from tokiwa.schemas.common import Severity

_H, _M = Severity.HIGH, Severity.MEDIUM

_HANDLERS = (
    "error|load|mouseover|mouseenter|mouseleave|mousemove|mousedown|mouseup|focus|focusin|blur|click|dblclick"
    "|keydown|keyup|keypress|input|change|submit|reset|toggle|pageshow|popstate|hashchange|animationstart"
    "|animationend|transitionend|pointerover|pointerenter|pointerdown|wheel|scroll|resize|beforeunload|unload"
    "|message|start|finish|begin|end|repeat|show|copy|cut|paste|drag|dragstart|drop|auxclick|contextmenu"
    "|search|select|invalid|abort|loadstart|loadend|progress|play|playing|canplay|seeked|timeupdate"
)


@register_detector
class XssDetector(WebSignatureDetector):
    id = "web.xss"
    name = "Cross-site scripting attempt"
    description = (
        "HTML/JavaScript injection payload (script/iframe tags, event-handler attributes, javascript: URIs, "
        "client-side template injection) in a parameter, path, cookie or reflected header."
    )
    family = "xss"
    mitre = ("T1190", "T1059.007")
    default_severity = _M
    signatures = (
        sig("xss.script_tag", r"<\/? ?script\b", _H, confidence=0.85, description="<script> tag"),
        sig(
            "xss.event_handler_tag",
            r"<[a-z][\w:-]{0,30}\b[^>]{0,200}?[ /\"'`]on[a-z]{3,25} ?=",
            _H,
            confidence=0.8,
            description="HTML tag with on*= event handler",
        ),
        sig(
            "xss.handler_breakout",
            rf"[\"'`][^<>\"'`]{{0,80}}?[ /]on(?:{_HANDLERS}) ?=|[\"'`] ?/? ?on(?:{_HANDLERS}) ?=",
            _M,
            confidence=0.7,
            description="attribute breakout into on*= handler",
        ),
        sig(
            "xss.javascript_uri",
            r"(?:j ?a ?v ?a|v ?b) ?s ?c ?r ?i ?p ?t ?: ?(?:/ ?/|/ ?\*|alert|confirm|prompt|eval|fetch|import"
            r"|document\.|window\.|top\.|self\.|this\.|parent\.|location|\(|\[|[a-z_$][\w$.]{0,40} ?\()",
            _M,
            confidence=0.7,
            description="javascript: URI with code",
        ),
        sig(
            "xss.dangerous_tag",
            r"<(?:iframe|frame|frameset|object|embed|applet|base|isindex)\b"
            r"|<meta\b[^>]{0,100}?http-equiv|<link\b[^>]{0,100}?rel ?= ?[\"']? ?import",
            _M,
            confidence=0.6,
            description="dangerous HTML tag (iframe/object/embed/base)",
        ),
        sig(
            "xss.js_sink",
            r"\b(?:alert|confirm|prompt) ?(?:\( ?(?:\d|document|window|origin|[\"'`]|/|\))|`)"
            r"|\bdocument ?\. ?(?:cookie|domain|write ?\(|location ?=)|\bstring ?\. ?fromcharcode ?\("
            r"|\beval ?\( ?(?:atob|unescape|string|decodeuri)|\batob ?\( ?[\"'`]"
            r"|\b(?:window|top|self) ?\[ ?[\"'`]|\bconstructor ?\. ?constructor ?\(",
            _M,
            confidence=0.6,
            description="JavaScript sink/probe (alert(1), document.cookie)",
        ),
        sig(
            "xss.csti",
            r"\{\{[^}]{0,100}?(?:constructor|\$on\b|\$eval|\$parent|\$root|alert ?\(|document\.|window\.)",
            _H,
            confidence=0.75,
            description="client-side template injection (AngularJS sandbox escape)",
        ),
        sig(
            "xss.data_uri_html",
            r"\bdata ?: ?(?:text/html|(?:text|application)/(?:x-)?javascript)\b",
            _M,
            confidence=0.6,
            description="data: URI carrying HTML/JS",
        ),
    )
