"""Pure scoring helpers for incidents: severity boosts, actor attribution, primary category (FR-09).

Kept free of DB / bus access so every rule is unit-testable. ``correlate.service`` gathers the facts and calls
these functions; tune boosts and attribution here.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from tokiwa.schemas.alerts import AlertCategory
from tokiwa.schemas.common import ActorType, Severity

_SEV_BY_RANK = sorted(Severity, key=lambda s: s.rank)

TAG_KEV = "kev"
TAG_AI_AGENT = "ai_agent"
TAG_PORT_REQUEST = "correlated:port_request"

# Detectors / rules whose firing means "automated scanner" unless stronger AI evidence exists.
SCANNER_RULES = frozenset({"web.scanner_ua", "net.port_scan", "web.error_burst"})

# When severities tie, the more specific / higher-fidelity category represents the incident.
_CATEGORY_PRIORITY: tuple[str, ...] = (
    AlertCategory.DECEPTION,
    AlertCategory.AI_AGENT,
    AlertCategory.PROMPT_INJECTION,
    AlertCategory.EXPLOIT_ATTEMPT,
    AlertCategory.CREDENTIAL_ATTACK,
    AlertCategory.VULN_EXPOSURE,
    AlertCategory.PORT_DEVIATION,
    AlertCategory.IDS,
    AlertCategory.SCAN,
    AlertCategory.RECON,
    AlertCategory.POLICY,
    AlertCategory.ANOMALY,
    AlertCategory.OTHER,
)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def bump(severity: Severity | str, levels: int = 1) -> Severity:
    """Raise a severity by ``levels`` steps, capped at critical."""
    rank = min(Severity(severity).rank + max(0, levels), len(_SEV_BY_RANK) - 1)
    return _SEV_BY_RANK[rank]


@dataclass
class BoostResult:
    severity: Severity
    reasons: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


def boosted_severity(
    base: Severity | str,
    *,
    ai_score: float | None,
    ai_threshold: float,
    kev_cves: Sequence[str] = (),
    port_request: bool = False,
) -> BoostResult:
    """Apply the correlation boosts. Each applicable boost raises severity by one level (capped).

    (a) AI-agent attribution (``ai_score >= ai_threshold``), (b) a referenced CVE is in CISA KEV,
    (c) a request hit a port right after an unexpected listener appeared on it.
    Boosts are recomputed from facts every time, so they never accumulate across updates.
    """
    levels = 0
    out = BoostResult(severity=Severity(base))
    if ai_score is not None and ai_score >= ai_threshold:
        levels += 1
        out.reasons.append(f"ai_score {ai_score:.2f} >= {ai_threshold:.2f}")
        out.tags.append(TAG_AI_AGENT)
    if kev_cves:
        levels += 1
        out.reasons.append("KEV: " + ", ".join(sorted(kev_cves)))
        out.tags.append(TAG_KEV)
    if port_request:
        levels += 1
        out.reasons.append("request to a newly opened listener port")
        out.tags.append(TAG_PORT_REQUEST)
    out.severity = bump(base, levels)
    return out


def max_severity(values: Iterable[Severity | str]) -> Severity:
    sevs = [Severity(v) for v in values]
    return Severity.max(*sevs) if sevs else Severity.INFO


def max_score(values: Iterable[float | None]) -> float | None:
    scores = [v for v in values if v is not None]
    return max(scores) if scores else None


# Audit #59: where a CVE id may come from. Entity values such as ``path`` / ``user_agent`` / ``endpoint`` are written
# by the client, so scanning every value let an attacker put "CVE-2021-44228" in its User-Agent and join (or pull
# a third party into) another source's incident -- whose triage may then propose blocking that third party.
# Only fields a detector or rule author sets are read: the CVE keys, and an IDS ``signature`` (the rule's message,
# which the traffic cannot choose).
_CVE_FIELDS = ("cve", "cves", "vuln_id", "vuln_ids")
_CVE_TEXT_FIELDS = ("signature",)
# A tag that is itself a CVE id: detector "cve-2021-44228", Sigma "cve.2021-44228", "cve:CVE-2021-44228".
_CVE_TAG_RE = re.compile(r"^cve(?:[.-]|:cve-)(\d{4}-\d{4,7})$", re.IGNORECASE)


def _cve_values(source: dict[str, Any], keys: Iterable[str]) -> list[str]:
    out: list[str] = []
    for key in keys:
        val = source.get(key)
        if isinstance(val, str):
            out.append(val)
        elif isinstance(val, list | tuple):
            out.extend(str(v) for v in val)
    return out


def extract_cves(
    entities: dict[str, str], tags: Iterable[str] = (), details: dict[str, Any] | None = None
) -> set[str]:
    """CVE ids an alert's detector / rule asserted (never ids found in client-written text, audit #59).

    Read from the CVE keys of ``entities`` and ``details``, an IDS ``signature``, and tags that *are* a CVE id.
    """
    texts = _cve_values(entities, (*_CVE_FIELDS, *_CVE_TEXT_FIELDS))
    if details:
        texts.extend(_cve_values(details, _CVE_FIELDS))
    found = {m.upper() for t in texts for m in _CVE_RE.findall(t)}
    for tag in tags:
        m = _CVE_TAG_RE.match(str(tag).strip())
        if m:
            found.add(f"CVE-{m.group(1)}")
    return found


@dataclass
class AlertFacts:
    """The subset of an alert that attribution needs (decoupled from the ORM row)."""

    rule_id: str
    category: str
    severity: str
    ai_score: float | None = None
    tags: list[str] = field(default_factory=list)
    entities: dict[str, str] = field(default_factory=dict)


def _is_ai_canary(a: AlertFacts) -> bool:
    if any("ai_canary" in t for t in a.tags):
        return True
    return any(str(v) == "ai_canary" for v in a.entities.values())


def _is_scanner(a: AlertFacts) -> bool:
    return (
        a.category == AlertCategory.SCAN
        or a.rule_id in SCANNER_RULES
        or "scanner" in a.rule_id
        or any(t == "scanner" or t.startswith("scanner:") for t in a.tags)
    )


def infer_actor_type(
    alerts: Sequence[AlertFacts],
    *,
    ai_score: float | None,
    ai_threshold: float,
    session_classifications: Sequence[str] = (),
) -> ActorType:
    """Rule-based attribution (requirements §6-8: the LLM never decides this alone).

    Priority: behavioural AI score / AI-canary trip (decisive) > sessionizer classification > scanner
    detectors > unknown.
    """
    if ai_score is not None and ai_score >= ai_threshold:
        return ActorType.AI_AGENT
    if any(_is_ai_canary(a) for a in alerts):
        return ActorType.AI_AGENT
    classes = set(session_classifications)
    for candidate in (ActorType.AI_AGENT, ActorType.AUTOMATED_SCANNER, ActorType.HUMAN):
        if candidate in classes:
            return candidate
    if any(_is_scanner(a) for a in alerts):
        return ActorType.AUTOMATED_SCANNER
    return ActorType.UNKNOWN


def primary_category(alerts: Sequence[AlertFacts]) -> AlertCategory:
    """Category of the most severe alert; ties broken by ``_CATEGORY_PRIORITY``."""
    if not alerts:
        return AlertCategory.OTHER

    def key(a: AlertFacts) -> tuple[int, int]:
        cat = str(a.category)
        prio = _CATEGORY_PRIORITY.index(cat) if cat in _CATEGORY_PRIORITY else len(_CATEGORY_PRIORITY)
        return (-Severity(a.severity).rank, prio)

    best = min(alerts, key=key)
    try:
        return AlertCategory(best.category)
    except ValueError:
        return AlertCategory.OTHER
