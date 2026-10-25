"""Pure correlation rules: kill-chain mapping, severity boosts, attribution, category choice."""

from __future__ import annotations

from tokiwa.correlate import killchain
from tokiwa.correlate.scoring import (
    AlertFacts,
    boosted_severity,
    bump,
    extract_cves,
    infer_actor_type,
    primary_category,
)
from tokiwa.schemas.alerts import AlertCategory
from tokiwa.schemas.common import ActorType, Severity
from tokiwa.schemas.triage import AttackStage


def test_technique_tactic_lookup() -> None:
    assert killchain.technique_tactic("T1595.002") == AttackStage.RECONNAISSANCE
    assert killchain.technique_tactic("t1190") == AttackStage.INITIAL_ACCESS
    assert killchain.technique_tactic("TA0006") == AttackStage.CREDENTIAL_ACCESS
    assert killchain.technique_tactic("T9999") is None
    assert killchain.technique_tactic("") is None


def test_kill_chain_is_ordered_set() -> None:
    tactics = killchain.tactics_for_alert(["T1190", "T1595", "T1110.004", "T1595.001"])
    assert tactics == ["reconnaissance", "initial_access", "credential_access"]
    assert killchain.most_advanced(tactics) == AttackStage.CREDENTIAL_ACCESS
    assert killchain.most_advanced([]) == AttackStage.NONE


def test_category_fallback_tactic() -> None:
    assert killchain.tactics_for_alert([], AlertCategory.PORT_DEVIATION) == ["persistence"]
    assert killchain.tactics_for_alert(["T1046"], AlertCategory.PORT_DEVIATION) == ["discovery"]
    assert killchain.tactics_for_alert([], AlertCategory.OTHER) == []


def test_bump_caps_at_critical() -> None:
    assert bump(Severity.MEDIUM) == Severity.HIGH
    assert bump(Severity.HIGH, 3) == Severity.CRITICAL
    assert bump("low", 0) == Severity.LOW


def test_boosts_are_independent_and_capped() -> None:
    none = boosted_severity(Severity.MEDIUM, ai_score=0.2, ai_threshold=0.7)
    assert none.severity == Severity.MEDIUM and not none.tags

    ai = boosted_severity(Severity.MEDIUM, ai_score=0.7, ai_threshold=0.7)
    assert ai.severity == Severity.HIGH and ai.tags == ["ai_agent"]

    kev = boosted_severity(Severity.LOW, ai_score=None, ai_threshold=0.7, kev_cves=["CVE-2021-44228"])
    assert kev.severity == Severity.MEDIUM and "kev" in kev.tags

    everything = boosted_severity(
        Severity.MEDIUM, ai_score=0.95, ai_threshold=0.7, kev_cves=["CVE-1"], port_request=True
    )
    assert everything.severity == Severity.CRITICAL
    assert set(everything.tags) == {"ai_agent", "kev", "correlated:port_request"}
    assert len(everything.reasons) == 3


def test_extract_cves() -> None:
    found = extract_cves(
        {"cve": "cve-2021-44228", "path": "/x"},
        ["cve:CVE-2025-55182"],
        {"cves": ["CVE-2024-3400", "nope"]},
    )
    assert found == {"CVE-2021-44228", "CVE-2025-55182", "CVE-2024-3400"}


def _facts(rule: str, cat: str, sev: str = "medium", **kw: object) -> AlertFacts:
    return AlertFacts(rule_id=rule, category=cat, severity=sev, **kw)  # type: ignore[arg-type]


def test_actor_attribution_priority() -> None:
    scanner = [_facts("web.scanner_ua", "recon")]
    assert infer_actor_type(scanner, ai_score=None, ai_threshold=0.7) == ActorType.AUTOMATED_SCANNER
    # behavioural AI score beats the scanner signal
    assert infer_actor_type(scanner, ai_score=0.8, ai_threshold=0.7) == ActorType.AI_AGENT
    # AI canary trip is decisive even without a score
    canary = [_facts("deception.trip", "deception", tags=["ai_canary"])]
    assert infer_actor_type(canary, ai_score=None, ai_threshold=0.7) == ActorType.AI_AGENT
    # sessionizer classification beats detector heuristics
    assert (
        infer_actor_type(scanner, ai_score=0.1, ai_threshold=0.7, session_classifications=["human"])
        == ActorType.HUMAN
    )
    assert infer_actor_type([_facts("web.sqli", "exploit_attempt")], ai_score=None, ai_threshold=0.7) == (
        ActorType.UNKNOWN
    )


def test_primary_category() -> None:
    alerts = [
        _facts("web.scanner_ua", "recon", "high"),
        _facts("web.sqli", "exploit_attempt", "high"),
        _facts("port.unexpected_listener", "port_deviation", "medium"),
    ]
    assert primary_category(alerts) == AlertCategory.EXPLOIT_ATTEMPT
    assert primary_category([]) == AlertCategory.OTHER
