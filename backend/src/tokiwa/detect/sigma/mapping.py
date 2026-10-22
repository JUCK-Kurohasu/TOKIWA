"""Sigma rule metadata -> TOKIWA alert attributes (severity, confidence, category, MITRE, AI score).

TOKIWA-specific tags (optional, ignored by other Sigma tooling):

* ``tokiwa.category.<AlertCategory>`` - force the alert category (e.g. ``tokiwa.category.ai_agent``);
* ``tokiwa.ai_score.<0-100>``         - AI-agent likelihood hint for correlation (``tokiwa.ai_score.60`` = 0.6).
"""

from __future__ import annotations

import re
from typing import Any

from tokiwa.detect.sigma.evaluator import SigmaRule
from tokiwa.schemas.alerts import AlertCategory
from tokiwa.schemas.common import Severity

LEVEL_SEVERITY: dict[str, Severity] = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

# Rule maturity -> how much we trust a hit (the triage LLM sees this as alert confidence).
STATUS_CONFIDENCE: dict[str | None, float] = {
    "stable": 0.85,
    "test": 0.75,
    "experimental": 0.65,
    "deprecated": 0.5,
    "unsupported": 0.5,
    None: 0.65,
}

# First matching ATT&CK tactic tag decides the category when no explicit tokiwa.category.* tag exists.
TACTIC_CATEGORY: dict[str, AlertCategory] = {
    "reconnaissance": AlertCategory.RECON,
    "discovery": AlertCategory.RECON,
    "initial_access": AlertCategory.EXPLOIT_ATTEMPT,
    "execution": AlertCategory.EXPLOIT_ATTEMPT,
    "persistence": AlertCategory.EXPLOIT_ATTEMPT,
    "privilege_escalation": AlertCategory.EXPLOIT_ATTEMPT,
    "credential_access": AlertCategory.CREDENTIAL_ATTACK,
    "collection": AlertCategory.EXPLOIT_ATTEMPT,
    "exfiltration": AlertCategory.EXPLOIT_ATTEMPT,
    "defense_evasion": AlertCategory.EXPLOIT_ATTEMPT,
    "lateral_movement": AlertCategory.EXPLOIT_ATTEMPT,
    "command_and_control": AlertCategory.EXPLOIT_ATTEMPT,
    "impact": AlertCategory.EXPLOIT_ATTEMPT,
}

LOGSOURCE_CATEGORY: dict[str, AlertCategory] = {
    "llm_app": AlertCategory.PROMPT_INJECTION,
    "llm": AlertCategory.PROMPT_INJECTION,
    "deception": AlertCategory.DECEPTION,
    "ids": AlertCategory.IDS,
    "port_change": AlertCategory.PORT_DEVIATION,
}

_TECHNIQUE_RE = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)
_AI_SCORE_RE = re.compile(r"^tokiwa\.ai_score\.(\d{1,3})$", re.IGNORECASE)
_CATEGORY_RE = re.compile(r"^tokiwa\.category\.([a-z_]+)$", re.IGNORECASE)


def severity_for(rule: SigmaRule) -> Severity:
    return LEVEL_SEVERITY.get(rule.level, Severity.MEDIUM)


def confidence_for(rule: SigmaRule) -> float:
    return STATUS_CONFIDENCE.get(rule.status, STATUS_CONFIDENCE[None])


def mitre_from_tags(tags: tuple[str, ...] | list[str]) -> list[str]:
    """``attack.t1190`` -> ``T1190``, ``attack.t1059.007`` -> ``T1059.007`` (order kept, de-duplicated)."""
    out: list[str] = []
    for t in tags:
        m = _TECHNIQUE_RE.match(t.strip())
        if m:
            tid = f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")
            if tid not in out:
                out.append(tid)
    return out


def category_for(rule: SigmaRule) -> AlertCategory:
    for t in rule.tags:
        m = _CATEGORY_RE.match(t.strip())
        if m:
            try:
                return AlertCategory(m.group(1).lower())
            except ValueError:
                pass
    by_source = LOGSOURCE_CATEGORY.get(rule.logsource.get("category", "").lower())
    if by_source is not None:
        return by_source
    for t in rule.tags:
        low = t.strip().lower()
        if low.startswith("attack.") and not _TECHNIQUE_RE.match(low):
            cat = TACTIC_CATEGORY.get(low[len("attack.") :].replace("-", "_"))
            if cat is not None:
                return cat
    return AlertCategory.OTHER


def ai_score_for(rule: SigmaRule) -> float | None:
    for t in rule.tags:
        m = _AI_SCORE_RE.match(t.strip())
        if m:
            return max(0.0, min(1.0, int(m.group(1)) / 100.0))
    return None


def rule_meta(rule: SigmaRule) -> dict[str, Any]:
    """Denormalized metadata stored in ``RuleRow.meta`` so the UI can list rules without parsing YAML."""
    return {
        "sigma_id": rule.id,
        "level": rule.level,
        "status": rule.status,
        "author": rule.author,
        "tags": list(rule.tags),
        "mitre": mitre_from_tags(rule.tags),
        "category": category_for(rule).value,
        "logsource": dict(rule.logsource),
        "kinds": sorted(k.value for k in rule.kinds),
        "falsepositives": list(rule.falsepositives),
    }
