"""Web reconnaissance detectors: sensitive file probes, known scanner fingerprints, rare HTTP methods.

* ``web.sensitive_file_probe`` - requests for secrets/VCS metadata/backups/debug endpoints. A 2xx answer for a
  secret is escalated (possible *exposure*, not just an attempt) unless the response is HTML, which usually means
  an SPA catch-all route. Fingerprint = rule|source|signature so a wordlist run is one alert per file class.
* ``web.scanner_ua`` - offensive tool User-Agents, scanner marker headers/paths and out-of-band (OAST)
  callback domains such as Burp Collaborator / interactsh anywhere in the request.
* ``web.rare_method`` - TRACE/TRACK/DEBUG/CONNECT, WebDAV verbs, unknown or malformed methods, and
  X-HTTP-Method-Override smuggling of those.

AI/LLM client fingerprints (python-httpx, Claude-User, ...) belong to ``ai.llm_client_fingerprint`` (detect-ai),
not here.
"""

from __future__ import annotations

from typing import ClassVar

from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.web_common import (
    ALL_LOCATIONS,
    PATH,
    Hit,
    HttpView,
    Plan,
    WebSignatureDetector,
    build_plan,
    clean_label,
    get_view,
    rx,
    scan_targets,
    scan_text,
    sig,
    snippet,
    web_settings,
)
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind

_C, _H, _M, _L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW

_END = r"(?:$|[/;])"

# ---------------------------------------------------------------------------------------------------------
# web.sensitive_file_probe
# ---------------------------------------------------------------------------------------------------------


@register_detector
class SensitiveFileProbeDetector(WebSignatureDetector):
    id = "web.sensitive_file_probe"
    name = "Sensitive file probe"
    description = (
        "Request for credentials/config files (.env, .aws/credentials, id_rsa, wp-config.php), VCS metadata "
        "(.git/config), backups (backup.zip, *.sql), debug/admin endpoints (actuator, server-status) or webshells."
    )
    category = AlertCategory.RECON
    family = "sensitive_file"
    mitre = ("T1595.003", "T1083", "T1552.001")
    default_severity = _M
    locations = frozenset({PATH})
    signatures = (
        sig(
            "file.secrets",
            r"(?:^|/)(?:\.env(?:\.[\w-]{1,30})?|\.aws/(?:credentials|config)|\.ssh/(?:id_\w{2,10}|authorized_keys"
            r"|known_hosts)|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|\.htpasswd|\.npmrc|\.pypirc|\.netrc|\.pgpass"
            r"|\.git-credentials|\.dockercfg|\.docker/config\.json|\.kube/config|\.s3cfg|\.boto|credentials\.json"
            r"|secrets?\.(?:ya?ml|json|txt)|wp-config\.php(?:[.~][\w~]{0,10})?|config\.php\.(?:bak|old|save|swp|orig|txt)"
            r"|localsettings\.php(?:\.bak)?|database\.yml|settings\.py|appsettings(?:\.\w{1,20})?\.json|web\.config"
            r"|\.bash_history|\.zsh_history|\.mysql_history|\.psql_history)" + _END,
            _M,
            confidence=0.75,
            view="lower",
            description="credential/config file (.env, .aws/credentials, id_rsa, wp-config.php)",
        ),
        sig(
            "file.vcs",
            r"(?:^|/)(?:\.git(?:/(?:config|head|index|description|packed-refs|fetch_head|orig_head|logs/head"
            r"|refs/heads(?:/[\w.-]{1,60})?|objects/[\w/]{0,60}))?|\.gitignore|\.gitlab-ci\.yml|\.travis\.yml"
            r"|\.svn(?:/(?:entries|wc\.db))?|\.hg(?:/(?:hgrc|store|requires))?|\.bzr|cvs/(?:root|entries))"
            + _END,
            _M,
            confidence=0.75,
            view="lower",
            description="version-control metadata (.git/config, .svn/entries)",
        ),
        sig(
            "file.debug_endpoint",
            r"(?:^|/)(?:actuator/(?:env|heapdump|configprops|mappings|beans|threaddump|loggers|jolokia|gateway/routes"
            r"|shutdown|httptrace|trace)|jolokia|heapdump|_profiler|debug/(?:pprof|vars)|__debug__"
            r"|_ignition/execute-solution|vendor/phpunit/(?:[\w.-]{1,40}/){0,6}eval-stdin\.php|jmx-console"
            r"|invoker/(?:jmxinvokerservlet|ejbinvokerservlet))" + _END,
            _H,
            confidence=0.8,
            view="lower",
            description="debug/management endpoint or known RCE path (actuator/env, phpunit eval-stdin)",
        ),
        sig(
            "file.webshell",
            r"(?:^|/)(?:c99|r57|wso|b374k|webshell|backdoor|shell|cmd)\.(?:php\d?|phtml|aspx?|jsp)" + _END,
            _H,
            confidence=0.7,
            view="lower",
            description="common webshell file name",
        ),
        sig(
            "file.backup",
            r"(?:^|/)(?:backup|backups|bak|db|database|dump|site|www|wwwroot|htdocs|html|web|webroot|public_html|data"
            r"|sql|mysql|archive|old|src|source|app|admin|home|root|export|\d{4}-?\d{2}-?\d{2})[\w.-]{0,30}"
            r"\.(?:zip|rar|7z|tar|tar\.gz|tgz|tar\.bz2|sql|sql\.gz|bak|dump)(?:$|;)"
            r"|\.(?:bak|backup|old|orig|swp|swo|sql|sql\.gz|dump|save)(?:$|;)|~$",
            _M,
            confidence=0.65,
            view="lower",
            description="backup/archive/dump file",
        ),
        sig(
            "file.admin_console",
            r"(?:^|/)(?:actuator|manager/html|phpmyadmin|adminer(?:-[\d.]{1,10})?\.php|solr/admin)" + _END,
            _M,
            confidence=0.6,
            view="lower",
            description="admin console (Tomcat manager, phpMyAdmin, Spring actuator)",
        ),
        sig(
            "file.info_disclosure",
            r"(?:^|/)(?:server-status|server-info|phpinfo\.php|info\.php|php_info\.php|test\.php|\.ds_store|thumbs\.db"
            r"|web-inf|meta-inf|actuator/health|composer\.(?:json|lock)|package(?:-lock)?\.json|yarn\.lock"
            r"|gemfile\.lock|requirements\.txt|docker-compose\.ya?ml|dockerfile|\.dockerignore"
            r"|\.vscode/(?:sftp|settings)\.json|\.idea/(?:workspace\.xml|datasources\.xml)|sftp-config\.json"
            r"|elmah\.axd|trace\.axd)" + _END,
            _L,
            confidence=0.6,
            view="lower",
            description="information-disclosure file/endpoint (server-status, phpinfo, .DS_Store)",
        ),
    )

    # Severity when the server answered 2xx with a non-HTML body (likely real exposure).
    _EXPOSED: ClassVar[dict[str, Severity]] = {
        "file.secrets": _C,
        "file.vcs": _C,
        "file.debug_endpoint": _C,
        "file.webshell": _C,
        "file.backup": _H,
        "file.admin_console": _H,
        "file.info_disclosure": _M,
    }

    def scan(self, view: HttpView) -> list[Hit]:
        return scan_text(view.path_clean, self._plan, PATH, max_hits=3)

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        view = get_view(event, ctx)
        if view is None or not view.path_clean:
            return []
        hits = self.scan(view)
        if not hits:
            return []
        hits.sort(key=lambda h: h.sig.severity.rank, reverse=True)
        top = hits[0]
        severity = top.sig.severity
        exposure = "none"
        status = view.status or 0
        if 200 <= status < 300:
            rct = ((event.http.response_content_type if event.http else None) or "").lower()
            exposed = self._EXPOSED.get(top.sig.id, severity)
            if "html" in rct:
                exposure = "html_response_probably_spa_fallback"
            elif rct:
                exposure = "suspected"
                severity = Severity.max(severity, exposed)
            else:
                exposure = "possible_unknown_content_type"
                severity = Severity.max(severity, min(exposed, _H, key=lambda s: s.rank))
        return self.build_alert(
            event,
            view,
            hits,
            severity=severity,
            fingerprint=f"{self.id}|{event.source_ip or '-'}|{top.sig.id}",
            extra_tags=("exposure_suspected",)
            if exposure in ("suspected", "possible_unknown_content_type")
            else (),
            extra_details={"exposure": exposure},
        )


# ---------------------------------------------------------------------------------------------------------
# web.scanner_ua
# ---------------------------------------------------------------------------------------------------------

# (group name, UA regex, severity). Exploitation tools are HIGH, scanners MEDIUM, research crawlers LOW.
_TOOLS: tuple[tuple[str, str, Severity], ...] = (
    ("sqlmap", r"\bsqlmap\b", _H),
    ("commix", r"\bcommix\b", _H),
    ("havij", r"\bhavij\b", _H),
    ("xsstrike", r"\bxsstrike\b", _H),
    ("hydra", r"\bhydra\b", _H),
    ("nikto", r"\bnikto\b", _M),
    ("nuclei", r"\bnuclei\b|projectdiscovery", _M),
    ("ffuf", r"\bffuf\b|fuzz faster u fool", _M),
    ("gobuster", r"\bgobuster\b", _M),
    ("dirbuster", r"\bdirbuster\b", _M),
    ("dirsearch", r"\bdirsearch\b", _M),
    ("feroxbuster", r"\bferoxbuster\b", _M),
    ("wfuzz", r"\bwfuzz\b", _M),
    ("wpscan", r"\bwpscan\b", _M),
    ("joomscan", r"\bjoomscan\b", _M),
    ("masscan", r"\bmasscan\b", _M),
    ("zgrab", r"\bzgrab", _M),
    ("nmap", r"nmap scripting engine|\bnmap\b", _M),
    ("acunetix", r"\bacunetix\b", _M),
    ("netsparker", r"\bnetsparker\b|\binvicti\b", _M),
    ("w3af", r"\bw3af\b", _M),
    ("arachni", r"\barachni\b", _M),
    ("skipfish", r"\bskipfish\b", _M),
    ("openvas", r"\bopenvas\b", _M),
    ("nessus", r"\bnessus\b", _M),
    ("qualys", r"\bqualys", _M),
    ("whatweb", r"\bwhatweb\b", _M),
    ("owasp_zap", r"\bzaproxy\b|\bowasp[ _-]?zap\b", _M),
    ("appscan", r"\bappscan\b", _M),
    ("webinspect", r"\bwebinspect\b", _M),
    ("paros", r"\bparos\b", _M),
    ("jaeles", r"\bjaeles\b", _M),
    ("fimap", r"\bfimap\b", _M),
    ("morfeus", r"\bmorfeus\b", _M),
    ("zmeu", r"\bzmeu\b", _M),
    ("jorgee", r"\bjorgee\b", _M),
    ("censys", r"\bcensysinspect\b", _L),
)
_TOOL_RE = rx("|".join(f"(?P<{name}>{pat})" for name, pat, _ in _TOOLS), "scanner.tools")
_TOOL_SEVERITY = {name: sev for name, _, sev in _TOOLS}

# TODO(verify): scanner marker header names below are from vendor docs/community lists, not re-checked.
_MARKER_HEADERS = {
    "acunetix-aspect": "acunetix",
    "acunetix-aspect-password": "acunetix",
    "acunetix-aspect-queries": "acunetix",
    "acunetix-product": "acunetix",
    "x-wipp": "webinspect",
    "x-scan-memo": "webinspect",
    "x-requestmanager-memo": "webinspect",
    "x-request-memo": "webinspect",
}

_SCANNER_SIGS = (
    sig(
        "scanner.oast_domain",
        r"\.(?:burpcollaborator\.net|oastify\.com|oast\.(?:pro|live|site|online|fun|me)|interact\.sh|interactsh\.com"
        r"|dnslog\.cn|ceye\.io)\b",
        _H,
        confidence=0.85,
        view="lower",
        locations=ALL_LOCATIONS,
        description="out-of-band interaction (OAST) domain - blind injection testing",
    ),
    sig(
        "scanner.marker_path",
        r"acunetix-wvs-test-for-some-inexistent-file|/nice ports,/trin(?:i|%69)ty\.txt\.bak"
        r"|/w00tw00t\.at\.isc\.sans\.|nessus_is_probing_you",  # TODO(verify): nessus marker string
        _M,
        confidence=0.85,
        view="lower",
        locations=ALL_LOCATIONS,
        description="scanner marker request",
    ),
)
_SCANNER_PLAN: Plan = build_plan(_SCANNER_SIGS, "web.scanner_ua")


@register_detector
class ScannerUaDetector(Detector):
    id = "web.scanner_ua"
    name = "Known attack tool / scanner"
    description = (
        "User-Agent, marker header or marker path of an offensive scanner (sqlmap, nikto, nuclei, ffuf, gobuster, "
        "wpscan, masscan, zgrab, Nmap NSE, Acunetix ...) or an out-of-band callback domain (Burp Collaborator, "
        "interactsh) in the request."
    )
    category = AlertCategory.SCAN
    kinds = frozenset({EventKind.HTTP})
    mitre = ("T1595", "T1595.002")
    default_severity = _M

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        view = get_view(event, ctx)
        if view is None:
            return []
        found: list[tuple[Severity, str, str, str]] = []  # (severity, tool, evidence kind, fragment)
        ua = view.headers.get("user-agent", "")
        if ua:
            m = _TOOL_RE.search(ua.lower())
            if m and m.lastgroup:
                found.append(
                    (_TOOL_SEVERITY[m.lastgroup], m.lastgroup, "user_agent", snippet(ua, m.start(), m.end()))
                )
        for header, tool in _MARKER_HEADERS.items():
            if header in view.headers:
                found.append((_M, tool, f"header:{header}", clean_label(view.headers[header], 200)))
                break
        for h in scan_targets(view.targets, _SCANNER_PLAN, ALL_LOCATIONS, ALL_LOCATIONS, max_hits=2):
            kind = "oast" if h.sig.id == "scanner.oast_domain" else "marker_path"
            found.append((h.sig.severity, kind, f"{h.location}:{h.sig.id}", h.fragment))
        if not found:
            return []
        found.sort(key=lambda f: f[0].rank, reverse=True)
        severity, tool, kind, fragment = found[0]
        return [
            self.draft(
                event,
                title=f"{self.name}: {tool} ({kind.split(':', 1)[0]})",
                description=self.description,
                severity=severity,
                confidence=0.9 if kind == "user_agent" else 0.8,
                entities=view.entities(),
                tags=list(dict.fromkeys(["web", "scanner", tool, *(f[1] for f in found)])),
                fingerprint=f"{self.id}|{event.source_ip or '-'}|{tool}",
                details={
                    "tool": tool,
                    "matched": fragment,
                    "evidence": [{"tool": f[1], "kind": f[2], "fragment": f[3]} for f in found[:5]],
                    "user_agent": clean_label(ua, 200),
                },
            )
        ]


# ---------------------------------------------------------------------------------------------------------
# web.rare_method
# ---------------------------------------------------------------------------------------------------------

_RISKY_METHODS: dict[str, tuple[Severity, str]] = {
    "TRACE": (_M, "TRACE (cross-site tracing probe)"),
    "TRACK": (_M, "TRACK (IIS cross-site tracing probe)"),
    "DEBUG": (_M, "DEBUG (ASP.NET debug verb)"),
    "CONNECT": (_M, "CONNECT (proxy tunnelling attempt)"),
}
_WEBDAV_METHODS = frozenset(
    [
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "COPY",
        "MOVE",
        "LOCK",
        "UNLOCK",
        "SEARCH",
        "REPORT",
        "MKCALENDAR",
        "ACL",
        "BIND",
        "REBIND",
        "UNBIND",
        "VERSION-CONTROL",
        "CHECKOUT",
        "CHECKIN",
        "UNCHECKOUT",
        "MKWORKSPACE",
        "UPDATE",
        "LABEL",
        "MERGE",
        "BASELINE-CONTROL",
        "MKACTIVITY",
        "ORDERPATCH",
    ]
)
_METHOD_TOKEN = rx(r"[A-Z][A-Z0-9_-]{0,23}", "rare_method.token")
_OVERRIDE_HEADERS = ("x-http-method-override", "x-http-method", "x-method-override")


def classify_method(method: str, allowed: frozenset[str]) -> tuple[Severity, str] | None:
    if method in allowed:
        return None
    if method in _RISKY_METHODS:
        return _RISKY_METHODS[method]
    if method in _WEBDAV_METHODS:
        return (_L, f"{method} (WebDAV)")
    if _METHOD_TOKEN.fullmatch(method):
        return (_L, f"{method} (non-standard method)")
    return (_M, "malformed method token")


@register_detector
class RareMethodDetector(Detector):
    id = "web.rare_method"
    name = "Rare HTTP method"
    description = (
        "HTTP methods outside the configured allow-list: TRACE/TRACK/DEBUG/CONNECT, WebDAV verbs, unknown or "
        "malformed methods, and X-HTTP-Method-Override headers smuggling them."
    )
    category = AlertCategory.RECON
    kinds = frozenset({EventKind.HTTP})
    mitre = ("T1595",)
    default_severity = _L

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        view = get_view(event, ctx)
        if view is None or not view.method:
            return []
        allowed = frozenset(m.upper() for m in web_settings(ctx.settings).allowed_methods)
        method, via = view.method, "method"
        verdict = classify_method(method, allowed)
        if verdict is None:
            for header in _OVERRIDE_HEADERS:
                value = view.headers.get(header, "").strip().upper()[:32]
                if value:
                    verdict = classify_method(value, allowed)
                    method, via = value, f"header:{header}"
                    break
        if verdict is None:
            return []
        severity, label = verdict
        shown = clean_label(method, 32)
        return [
            self.draft(
                event,
                title=f"{self.name}: {clean_label(label, 80)}"
                + (" via override header" if via != "method" else ""),
                description=self.description,
                severity=severity,
                confidence=0.6,
                entities=view.entities(),
                tags=["web", "rare_method", shown.lower()],
                fingerprint=f"{self.id}|{event.source_ip or '-'}|{shown}",
                details={"matched": shown, "method": shown, "via": via, "status": view.status},
            )
        ]
