"""web.ssti - server-side template / expression-language injection.

Covers arithmetic probes (``{{7*7}}``, ``${7*7}``, ``<%= 7*7 %>``, ``#{7*7}``), Python object-graph walking used
for Jinja2/Mako RCE (``__class__.__mro__``, ``__subclasses__()``), config leaks (``{{config}}``), Java EL/SpEL/
FreeMarker/Velocity gadgets and Struts2 OGNL (which also arrives in the Content-Type header, hence
``header_other`` is scanned).
"""

from __future__ import annotations

from tokiwa.detect.base import register_detector
from tokiwa.detect.web_common import HEADER_OTHER, INJECTION_LOCATIONS, WebSignatureDetector, sig
from tokiwa.schemas.common import Severity

_C, _H, _M = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM


@register_detector
class SstiDetector(WebSignatureDetector):
    id = "web.ssti"
    name = "Template/expression injection attempt"
    description = (
        "Server-side template injection (Jinja2/Twig/ERB/FreeMarker/Velocity/Thymeleaf) or expression-language "
        "injection (SpEL/OGNL): arithmetic probes, object-graph traversal, config leaks and RCE gadgets."
    )
    family = "ssti"
    mitre = ("T1190", "T1059")
    default_severity = _H
    locations = INJECTION_LOCATIONS | {HEADER_OTHER}
    signatures = (
        sig(
            "ssti.math_probe",
            r"\{\{ ?\d{1,6} ?\* ?['\"]?\d{1,6}['\"]? ?\}\}|\$\{ ?\d{1,6} ?\* ?\d{1,6} ?\}|#\{ ?\d{1,6} ?\* ?\d{1,6} ?\}"
            r"|<%=? ?\d{1,6} ?\* ?\d{1,6} ?%>|\[\[ ?\d{1,6} ?\* ?\d{1,6} ?\]\]|@\( ?\d{1,6} ?\* ?\d{1,6} ?\)"
            r"|\*\{ ?\d{1,6} ?\* ?\d{1,6} ?\}|\{\d{1,6}\*\d{1,6}\}",
            _M,
            confidence=0.75,
            description="template arithmetic probe ({{7*7}})",
        ),
        sig(
            "ssti.python_object_walk",
            r"__(?:class|mro|base|bases|subclasses|globals|builtins)__|\b__import__ ?\("
            r"|\b(?:lipsum|cycler|joiner|namespace|url_for|get_flashed_messages) ?\. ?__"
            r"|\brequest ?\. ?application ?\. ?__|\bself ?\. ?_templatereference__",
            _H,
            confidence=0.8,
            description="Python object-graph traversal (__class__.__mro__, __globals__)",
        ),
        sig(
            "ssti.config_leak",
            r"\{\{ ?(?:config|settings|self|request|app|session)(?: ?\.[\w]{1,40}(?: ?\( ?\))?| ?\[[^\]]{0,40}\])? ?\}\}"
            r"|\{\{ ?config\b|\{%[^%]{0,80}?\b(?:import|debug)\b[^%]{0,80}?%\}",
            _M,
            confidence=0.7,
            description="template context/config leak ({{config}}, {{self}})",
        ),
        sig(
            "ssti.erb_jsp",
            r"<%=? ?(?:system|exec|spawn|io\.popen|`|file\.read|%x|eval|require|runtime|out\.print|request\.)"
            r"|<%=?[^%>]{1,120}%>",
            _M,
            confidence=0.6,
            description="ERB/JSP scriptlet (<%= ... %>)",
        ),
        sig(
            "ssti.java_el",
            r"\bt ?\( ?java\.lang\.|\bfreemarker\.template\.utility\.(?:execute|objectconstructor|jythonruntime)"
            r"|<#assign\b|\?new ?\(|#set ?\( ?\$|\$class\.inspect|\bnew java\.(?:lang|io|util|net)\."
            r"|\bjava\.lang\.(?:runtime|processbuilder|system)\b|\.getclass ?\( ?\) ?\. ?(?:forname|getclassloader)"
            r"|runtime ?\. ?getruntime ?\( ?\) ?\. ?exec|\bprocessbuilder ?\(|__\$\{[^}]{0,120}\}__"
            r"|\$\{ ?(?:''|\"\")\.getclass",
            _H,
            confidence=0.85,
            description="Java EL/SpEL/FreeMarker/Velocity RCE gadget",
        ),
        sig(
            "ssti.twig_smarty",
            r"\{\{ ?_self\.env\.|\| ?filter ?\( ?['\"](?:system|exec|passthru|shell_exec|popen)|\{php\}|\{system ?\("
            r"|\{\$smarty\.|\{\{ ?#with ?['\"]",
            _H,
            confidence=0.8,
            description="Twig/Smarty/Handlebars RCE gadget",
        ),
        sig(
            "ssti.ognl",
            r"%\{ ?\(? ?#|#_memberaccess|@java\.lang\.runtime@|#context ?\[|\bognlcontext\b|#application ?\["
            r"|\(#[a-z_]{1,30} ?= ?@",
            _C,
            confidence=0.9,
            description="Struts2 OGNL expression (CVE-2017-5638 style)",
        ),
    )
