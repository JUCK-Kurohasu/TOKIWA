"""web.path_traversal and web.lfi_rfi - directory traversal and local/remote file inclusion.

Traversal is checked on two views: ``lower`` (fully decoded: ``../``, ``..\\``, Tomcat ``..;/``) and ``raw``
(still encoded: ``%2e%2e%2f``, ``%252e``, overlong ``%c0%ae``, ``%u002e``). Seeing the encoded form is itself a
strong signal - browsers never send it. Known limitation: sensors that log an already-normalised path (nginx
``$uri``) hide path-located traversal; query/body traversal is still visible.
"""

from __future__ import annotations

import re

from tokiwa.detect.base import register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.web_common import (
    BODY,
    COOKIE,
    FILENAME,
    PATH,
    QUERY,
    Hit,
    HttpView,
    Signature,
    WebSignatureDetector,
    get_view,
    rx,
    sig,
    snippet,
)
from tokiwa.schemas.alerts import AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event

_H, _M = Severity.HIGH, Severity.MEDIUM

_TRAVERSAL_LOCATIONS = frozenset({PATH, QUERY, BODY, COOKIE, FILENAME})
_NO_BODY = frozenset({PATH, QUERY, COOKIE, FILENAME})  # NUL bytes are normal in uploaded binaries

_DOT = r"(?:%(?:25){0,2}2e|%c0%ae|%e0%80%ae|%c0%2e|%u002e|%uff0e)"
_SLASH = r"(?:%(?:25){0,2}(?:2f|5c)|%c0%af|%c1%9c|%c0%5c|%e0%80%af|%u2215|%u2216|%uff0f|%uefc8|%uf025)"


@register_detector
class PathTraversalDetector(WebSignatureDetector):
    id = "web.path_traversal"
    name = "Path traversal attempt"
    description = (
        "Directory traversal sequences (../, encoded/overlong variants, Tomcat ..;/), references to well-known "
        "OS files (/etc/passwd, win.ini, /proc/self/environ) or NUL-byte truncation."
    )
    family = "path_traversal"
    mitre = ("T1190", "T1083")
    default_severity = _H
    locations = _TRAVERSAL_LOCATIONS
    signatures = (
        sig(
            "traversal.dotdot_multi",
            r"\.\.[/\\]{1,2}\.\.(?:[/\\]|$)",
            _H,
            confidence=0.85,
            view="lower",
            description="repeated ../ sequences",
        ),
        sig(
            "traversal.tomcat_semicolon",
            r"\.\.;[/\\]",
            _H,
            confidence=0.85,
            view="lower",
            description="Tomcat/Spring ..;/ path-parameter traversal",
        ),
        sig(
            "traversal.encoded",
            rf"{_DOT}(?:{_DOT}|\.)(?:{_SLASH}|[/\\])|\.{_DOT}(?:{_SLASH}|[/\\])|\.\.{_SLASH}",
            _H,
            confidence=0.85,
            view="raw",
            description="encoded/overlong traversal sequence (%2e%2e%2f, %c0%ae)",
        ),
        sig(
            "traversal.os_file",
            r"(?:^|[/\\=:])(?:etc[/\\](?:passwd|shadow|group|hosts|issue|crontab|sudoers|master\.passwd|hostname"
            r"|resolv\.conf|os-release|fstab)\b|proc[/\\](?:self|\d{1,7})[/\\](?:environ|cmdline|maps|status|mounts"
            r"|cwd|exe|fd[/\\])|(?:boot|win|system)\.ini\b|windows[/\\](?:win\.ini|system32)\b|winnt[/\\]"
            r"|system32[/\\](?:drivers[/\\]etc|config[/\\]sam|cmd\.exe)|var[/\\]log[/\\][\w./-]{1,60}\.log\b"
            r"|web-inf[/\\]web\.xml)",
            _H,
            confidence=0.8,
            view="lower",
            description="reference to a well-known OS/config file",
        ),
        sig(
            "traversal.null_byte_ext",
            r"\x00[\w./-]{0,20}\.(?:php\d?|jpe?g|png|gif|html?|txt|pdf|jsp|aspx?)\b",
            _H,
            confidence=0.8,
            view="decoded",
            locations=_NO_BODY,
            description="NUL byte before a file extension (extension check bypass)",
        ),
        sig(
            "traversal.null_byte",
            r"\x00",
            _M,
            confidence=0.55,
            view="decoded",
            locations=_NO_BODY,
            description="NUL byte in request",
        ),
        sig(
            "traversal.dotdot_single",
            r"(?:^|[/\\=:'\"])\.\.[/\\]",
            _M,
            confidence=0.45,
            view="lower",
            description="single ../ sequence",
        ),
    )


# Parameter names that typically feed include()/require()/template loaders.
_INCLUDE_PARAMS = frozenset(
    [
        "file",
        "filename",
        "page",
        "include",
        "inc",
        "path",
        "template",
        "tpl",
        "view",
        "doc",
        "document",
        "folder",
        "dir",
        "lang",
        "language",
        "module",
        "mod",
        "load",
        "show",
        "content",
        "cat",
        "layout",
        "style",
        "pg",
        "site",
        "conf",
        "config",
        "require",
        "read",
        "src",
        "source",
    ]
)
_REMOTE_VALUE = rx(r"^(?:https?|ftps?|smb)://[^\s]{1,500}$|^\\\\[\w.-]{1,100}\\", "lfi.remote_value")
# Classic RFI tail: the attacker appends ?, NUL or # so the app's own ".php" suffix becomes inert.
_RFI_TERMINATED = rx(r"^(?:https?|ftps?)://[^\s]{1,500}?(?:\?|\x00|#)$", "lfi.rfi_terminated")
_RFI_SCRIPT = rx(
    r"^(?:https?|ftps?)://[^\s?#]{1,500}?\.(?:txt|php\d?|phtml|inc|sh|pl|py|jsp|asp)$", "lfi.rfi_script"
)


def _pseudo(
    sig_id: str, pattern: re.Pattern[str], severity: Severity, confidence: float, desc: str
) -> Signature:
    """Signature object for the parameter-aware checks below (keeps alert details uniform)."""
    return Signature(sig_id, pattern, severity, confidence, "value", None, desc, ())


_SIG_RFI_TERMINATED = _pseudo(
    "rfi.terminated_url", _RFI_TERMINATED, _H, 0.7, "remote URL terminated by ?/NUL (RFI suffix bypass)"
)
_SIG_RFI_SCRIPT = _pseudo(
    "rfi.script_url", _RFI_SCRIPT, _H, 0.75, "remote script URL in include-style parameter"
)
_SIG_RFI_PARAM = _pseudo(
    "rfi.include_param_url", _REMOTE_VALUE, _M, 0.55, "remote URL in include-style parameter"
)


def remote_include_hits(view: HttpView) -> list[Hit]:
    for t in view.targets:
        if t.location not in (QUERY, BODY) or not t.param:
            continue
        value = t.value
        if "://" not in value and not value.startswith("\\\\"):
            continue
        frag = snippet(value, 0, len(value))
        if _RFI_TERMINATED.match(value):
            return [Hit(_SIG_RFI_TERMINATED, t.location, t.param, frag)]
        name = t.param.lower().split("[", 1)[0].rsplit(".", 1)[-1]
        if name not in _INCLUDE_PARAMS:
            continue
        if _RFI_SCRIPT.match(value):
            return [Hit(_SIG_RFI_SCRIPT, t.location, t.param, frag)]
        if _REMOTE_VALUE.match(value):
            return [Hit(_SIG_RFI_PARAM, t.location, t.param, frag)]
    return []


@register_detector
class LfiRfiDetector(WebSignatureDetector):
    id = "web.lfi_rfi"
    name = "Local/remote file inclusion attempt"
    description = (
        "Stream-wrapper abuse (php://filter, php://input, data://, expect://, phar://, file://) or an external URL "
        "passed to an include-style parameter (?page=http://evil/shell.txt?)."
    )
    family = "lfi_rfi"
    mitre = ("T1190", "T1105")
    default_severity = _H
    signatures = (
        sig(
            "lfi.php_wrapper",
            r"\bphp://(?:filter|input|fd|memory|temp|stdin)\b",
            _H,
            confidence=0.9,
            view="lower",
            description="php:// stream wrapper",
        ),
        sig(
            "lfi.other_wrapper",
            r"\b(?:expect|phar|zip|glob|compress\.(?:zlib|bzip2)|ogg|rar|ssh2\.(?:shell|exec|tunnel|sftp|scp))://",
            _H,
            confidence=0.85,
            view="lower",
            description="dangerous stream wrapper (expect://, phar://, zip://)",
        ),
        sig(
            "lfi.file_scheme",
            r"\bfile:/{2}",
            _H,
            confidence=0.75,
            view="lower",
            description="file:// URL",
        ),
        sig(
            "lfi.data_wrapper",
            r"\bdata://|\bdata:(?:text/plain|text/x-php|application/x-httpd-php|application/(?:x-)?php)[;,]",
            _H,
            confidence=0.8,
            view="lower",
            description="data:// wrapper with text/PHP payload",
        ),
        sig(
            "lfi.php_code",
            r"<\?(?:php\b|=)",
            _H,
            confidence=0.75,
            view="lower",
            description="PHP code in request (log poisoning / webshell upload)",
        ),
    )

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        view = get_view(event, ctx)
        if view is None:
            return []
        return self.build_alert(event, view, self.scan(view) + remote_include_hits(view))
