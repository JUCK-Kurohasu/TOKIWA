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


def extract_cves(
    entities: dict[str, str], tags: Iterable[str] = (), details: dict[str, Any] | None = None
) -> set[str]:
    """CVE ids referenced by an alert (entity values, tags, ``details.cve``/``details.cves``)."""
    texts: list[str] = [str(v) for v in entities.values()]
    texts.extend(str(t) for t in tags)
    if details:
        for key in ("cve", "cves", "vuln_id", "vuln_ids"):
            val = details.get(key)
            if isinstance(val, str):
                texts.append(val)
            elif isinstance(val, list | tuple):
                texts.extend(str(v) for v in val)
    return {m.upper() for t in texts for m in _CVE_RE.findall(t)}


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
