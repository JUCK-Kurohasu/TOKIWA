"""ATT&CK technique -> tactic mapping and kill-chain ordering (FR-09).

Why a hand-written table instead of the full STIX bundle: TOKIWA only sees network / web / host-port telemetry,
so the detectors emit a small, predictable set of techniques. A compact table keeps correlation dependency-free
and deterministic. Techniques that belong to several tactics are mapped to the tactic that best describes how
they show up in *our* telemetry (e.g. ``T1078`` valid accounts -> initial_access at the web edge).

Tune here: add techniques to ``_TECHNIQUE_TACTIC`` or change the per-category fallback in ``_CATEGORY_TACTIC``.
"""

from __future__ import annotations

from collections.abc import Iterable

from tokiwa.schemas.alerts import AlertCategory
from tokiwa.schemas.triage import AttackStage

# Canonical enterprise kill-chain order (same order as the ATT&CK matrix columns).
TACTIC_ORDER: tuple[str, ...] = (
    AttackStage.RECONNAISSANCE,
    AttackStage.RESOURCE_DEVELOPMENT,
    AttackStage.INITIAL_ACCESS,
    AttackStage.EXECUTION,
    AttackStage.PERSISTENCE,
    AttackStage.PRIVILEGE_ESCALATION,
    AttackStage.DEFENSE_EVASION,
    AttackStage.CREDENTIAL_ACCESS,
    AttackStage.DISCOVERY,
    AttackStage.LATERAL_MOVEMENT,
    AttackStage.COLLECTION,
    AttackStage.COMMAND_AND_CONTROL,
    AttackStage.EXFILTRATION,
    AttackStage.IMPACT,
)
_RANK = {t: i for i, t in enumerate(TACTIC_ORDER)}

# Tactic ids (TA00xx) may appear directly in a detector's ``mitre`` list.
_TACTIC_IDS: dict[str, str] = {
    "TA0043": AttackStage.RECONNAISSANCE,
    "TA0042": AttackStage.RESOURCE_DEVELOPMENT,
    "TA0001": AttackStage.INITIAL_ACCESS,
    "TA0002": AttackStage.EXECUTION,
    "TA0003": AttackStage.PERSISTENCE,
    "TA0004": AttackStage.PRIVILEGE_ESCALATION,
    "TA0005": AttackStage.DEFENSE_EVASION,
    "TA0006": AttackStage.CREDENTIAL_ACCESS,
    "TA0007": AttackStage.DISCOVERY,
    "TA0008": AttackStage.LATERAL_MOVEMENT,
    "TA0009": AttackStage.COLLECTION,
    "TA0011": AttackStage.COMMAND_AND_CONTROL,
    "TA0010": AttackStage.EXFILTRATION,
    "TA0040": AttackStage.IMPACT,
}


def _m(tactic: str, *techniques: str) -> dict[str, str]:
    return dict.fromkeys(techniques, tactic)


# Parent technique ids only; sub-techniques (T1595.002) resolve through their parent.
_TECHNIQUE_TACTIC: dict[str, str] = {
    **_m(AttackStage.RECONNAISSANCE, "T1595", "T1592", "T1590", "T1589", "T1591", "T1593", "T1594", "T1596"),
    **_m(AttackStage.RECONNAISSANCE, "T1597", "T1598"),
    **_m(AttackStage.RESOURCE_DEVELOPMENT, "T1583", "T1584", "T1585", "T1586", "T1587", "T1588", "T1608"),
    **_m(AttackStage.INITIAL_ACCESS, "T1190", "T1133", "T1078", "T1189", "T1566", "T1195", "T1199"),
    **_m(AttackStage.EXECUTION, "T1059", "T1203", "T1047", "T1204", "T1609", "T1610", "T1648", "T1053"),
    **_m(AttackStage.PERSISTENCE, "T1505", "T1136", "T1098", "T1543", "T1546", "T1547", "T1554"),
    **_m(AttackStage.PRIVILEGE_ESCALATION, "T1068", "T1548", "T1611", "T1134"),
    **_m(AttackStage.DEFENSE_EVASION, "T1027", "T1140", "T1562", "T1070", "T1036", "T1202", "T1550"),
    **_m(AttackStage.CREDENTIAL_ACCESS, "T1110", "T1552", "T1555", "T1212", "T1003", "T1539", "T1528"),
    **_m(AttackStage.CREDENTIAL_ACCESS, "T1557", "T1606", "T1621"),
    **_m(AttackStage.DISCOVERY, "T1046", "T1083", "T1087", "T1082", "T1018", "T1580", "T1526", "T1049"),
    **_m(AttackStage.DISCOVERY, "T1057", "T1069", "T1135", "T1613", "T1619", "T1518"),
    **_m(AttackStage.LATERAL_MOVEMENT, "T1021", "T1210", "T1570", "T1534"),
    **_m(AttackStage.COLLECTION, "T1005", "T1213", "T1530", "T1119", "T1114", "T1560", "T1602"),
    **_m(AttackStage.COMMAND_AND_CONTROL, "T1071", "T1090", "T1105", "T1571", "T1572", "T1573", "T1095"),
    **_m(AttackStage.COMMAND_AND_CONTROL, "T1102", "T1219", "T1001", "T1132", "T1568"),
    **_m(AttackStage.EXFILTRATION, "T1041", "T1048", "T1567", "T1020", "T1030", "T1537"),
    **_m(AttackStage.IMPACT, "T1498", "T1499", "T1485", "T1486", "T1490", "T1491", "T1496", "T1565"),
    # MITRE ATLAS (attacks on LLM applications).
    # TODO(verify): ATLAS lists LLM prompt injection / jailbreak under several tactics; the mapping below is a
    # pragmatic choice for kill-chain display, not an authoritative ATLAS -> ATT&CK conversion.
    "AML.T0051": AttackStage.INITIAL_ACCESS,  # LLM Prompt Injection
    "AML.T0054": AttackStage.DEFENSE_EVASION,  # LLM Jailbreak
    "AML.T0057": AttackStage.EXFILTRATION,  # LLM Data Leakage
}

# Used when no technique of an alert maps to a tactic.
_CATEGORY_TACTIC: dict[str, str] = {
    AlertCategory.RECON: AttackStage.RECONNAISSANCE,
    AlertCategory.SCAN: AttackStage.RECONNAISSANCE,
    AlertCategory.EXPLOIT_ATTEMPT: AttackStage.INITIAL_ACCESS,
    AlertCategory.CREDENTIAL_ATTACK: AttackStage.CREDENTIAL_ACCESS,
    AlertCategory.PROMPT_INJECTION: AttackStage.INITIAL_ACCESS,
    AlertCategory.DECEPTION: AttackStage.DISCOVERY,
    # An unexpected new listener is most often a backdoor / implant (persistence) in our threat model.
    AlertCategory.PORT_DEVIATION: AttackStage.PERSISTENCE,
}


def technique_tactic(technique: str) -> str | None:
    """Tactic for one technique / tactic id (``T1595.002`` -> reconnaissance), or None if unknown."""
    tid = technique.strip().upper()
    if not tid:
        return None
    if tid in _TACTIC_IDS:
        return _TACTIC_IDS[tid]
    if tid in _TECHNIQUE_TACTIC:
        return _TECHNIQUE_TACTIC[tid]
    parent = tid.split(".")[0] if tid.startswith("T") else tid.rsplit(".", 1)[0]
    return _TECHNIQUE_TACTIC.get(parent)


def tactics_for_alert(mitre: Iterable[str], category: str | None = None) -> list[str]:
    """Tactics for one alert: from its techniques, falling back to its category."""
    found = {t for t in (technique_tactic(m) for m in mitre) if t}
    if not found and category is not None:
        fallback = _CATEGORY_TACTIC.get(str(category))
        if fallback:
            found.add(fallback)
    return order_tactics(found)


def order_tactics(tactics: Iterable[str]) -> list[str]:
    """Ordered set in kill-chain order (unknown values are dropped)."""
    return sorted({str(t) for t in tactics if str(t) in _RANK}, key=lambda t: _RANK[t])


def most_advanced(tactics: Iterable[str]) -> AttackStage:
    ordered = order_tactics(tactics)
    return AttackStage(ordered[-1]) if ordered else AttackStage.NONE
