"""web.log4shell - Log4j JNDI lookup injection (CVE-2021-44228 / CVE-2021-45046), including obfuscation.

Attackers spray ``${jndi:ldap://...}`` into every header because any logged field is a sink, so this detector
inspects *all* locations (including uncommon headers such as X-Api-Version). Obfuscated forms such as
``${${lower:j}ndi:...}``, ``${${::-j}${::-n}di:...}``, ``${${env:NaN:-j}ndi...}`` and ``${date:'j'}`` are
collapsed by a bounded rewrite loop before matching.
"""

from __future__ import annotations

from tokiwa.detect.base import register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.web_common import (
    ALL_LOCATIONS,
    Hit,
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

_C, _H = Severity.CRITICAL, Severity.HIGH

# ${lower:x} ${upper:x} ${anything:anything:-x} ${::-x} ${date:'x'}  ->  x
_INNER_LOOKUP = rx(
    r"\$\{(?:(?:lower|upper)\s{0,3}:\s{0,3}([^${}]{0,20})|[^${}:]{0,40}:[^${}:]{0,40}:-([^${}]{0,20})"
    r"|date\s{0,3}:\s{0,3}'([^'${}]{0,20})')\}",
    "log4shell.inner_lookup",
)
_JNDI_PLAIN = r"\$\{\s{0,5}jndi\s{0,5}:"
_JNDI_DEOBF = rx(_JNDI_PLAIN, "log4shell.jndi_deobf")


def deobfuscate(text: str, rounds: int = 6) -> str:
    """Collapse nested Log4j lookups that only produce literal characters (bounded, linear per round)."""
    for _ in range(rounds):
        new = _INNER_LOOKUP.sub(lambda m: m.group(1) or m.group(2) or m.group(3) or "", text)
        if new == text:
            break
        text = new
    return text


_SIG_OBFUSCATED = Signature(
    id="log4shell.jndi_obfuscated",
    pattern=_JNDI_DEOBF,
    severity=_C,
    confidence=0.95,
    view="lower",
    locations=None,
    description="obfuscated ${jndi:} lookup (nested ${lower:}/${::-} tricks)",
    mitre=(),
)


@register_detector
class Log4ShellDetector(WebSignatureDetector):
    id = "web.log4shell"
    name = "Log4Shell (JNDI lookup) injection attempt"
    description = (
        "Log4j2 lookup expressions in any request field: ${jndi:ldap://...} (CVE-2021-44228), obfuscated nested "
        "lookups, and ${env:...}/${sys:...} style data exfiltration."
    )
    family = "log4shell"
    mitre = ("T1190",)
    default_severity = _C
    locations = ALL_LOCATIONS
    signatures = (
        sig("log4shell.jndi", _JNDI_PLAIN, _C, confidence=0.95, view="lower", description="${jndi:} lookup"),
        sig(
            "log4shell.lookup_exfil",
            r"\$\{\s{0,3}(?:env|sys)\s{0,3}:\s{0,3}[\w.]{0,40}(?:key|secret|pass|token|aws_|user)",
            _H,
            confidence=0.8,
            view="lower",
            description="${env:}/${sys:} lookup of a secret (exfiltration)",
        ),
        sig(
            "log4shell.lookup",
            r"\$\{\s{0,3}(?:lower|upper|env|sys|java|ctx|main|bundle|jvmrunargs|k8s|docker|spring|web|log4j|marker"
            r"|sd|event|base64)\s{0,3}:",
            _H,
            confidence=0.7,
            view="lower",
            description="Log4j lookup expression (${java:version}, ${lower:...})",
        ),
    )

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        view = get_view(event, ctx)
        if view is None:
            return []
        hits = self.scan(view)
        if not any(h.sig.id == "log4shell.jndi" for h in hits):
            for t in view.targets:
                if "${" not in t.lower:
                    continue
                flat = deobfuscate(t.lower)
                m = _JNDI_DEOBF.search(flat) if flat != t.lower else None
                if m:
                    start = t.lower.find("${")
                    frag = snippet(t.lower, start, min(len(t.lower), start + 200))
                    hits.append(Hit(_SIG_OBFUSCATED, t.location, t.param, frag))
                    break
        return self.build_alert(event, view, hits, extra_tags=("cve-2021-44228",))
