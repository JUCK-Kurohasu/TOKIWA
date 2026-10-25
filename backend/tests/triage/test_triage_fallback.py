"""Rule-based fallback verdicts and the mock-LLM responder built on them."""

from __future__ import annotations

import pytest

from tokiwa.config import Settings
from tokiwa.llm.mock import _RESPONDERS
from tokiwa.schemas.common import ActorType, Severity
from tokiwa.schemas.triage import ActionType, AttackStage, TriageResult
from tokiwa.triage.evidence import SubjectAlert, TriageContext, TriageSubject
from tokiwa.triage.fallback import mock_triage_responder, rule_based_triage
from tokiwa.triage.prompts import TRIAGE_ALERT, build_user_prompt, system_prompt

pytestmark = pytest.mark.usefixtures("settings")


def _subject(**kw: object) -> TriageSubject:
    base: dict[str, object] = {
        "kind": "alert",
        "id": "a1",
        "title": "SQL injection attempt",
        "severity": Severity.MEDIUM,
        "category": "exploit_attempt",
        "rule_ids": ["web.sqli"],
        "mitre": ["T1190"],
        "source_ips": ["203.0.113.10"],
    }
    base.update(kw)
    return TriageSubject.model_validate(base)


def test_basic_rule_verdict() -> None:
    r = rule_based_triage(_subject(confidence=0.8), ["e1", "e2"], ["203.0.113.10"], lang="en")
    assert r.severity == Severity.MEDIUM
    assert r.category == "sqli"
    assert r.confidence == pytest.approx(0.8)
    assert r.actor_type == ActorType.UNKNOWN
    assert r.attack_stage == AttackStage.INITIAL_ACCESS
    assert r.mitre_techniques == ["T1190"]
    assert r.evidence_ids == ["e1", "e2"]
    assert r.recommended_actions == []  # medium -> no proposals
    assert r.next_steps and "Rule-based" in r.summary


def test_ai_agent_verdict_and_deceive_proposal() -> None:
    r = rule_based_triage(
        _subject(severity=Severity.HIGH, ai_score=0.9, rule_ids=["ai.agent_session"], category="ai_agent"),
        ["e1"],
        ["203.0.113.10"],
        lang="ja",
    )
    assert r.actor_type == ActorType.AI_AGENT
    assert r.ai_agent_likelihood == pytest.approx(0.9)
    assert r.category == "ai_agent_session"
    assert any("detector:ai.agent_session" in i for i in r.ai_agent_indicators)
    assert [a.action_type for a in r.recommended_actions] == [ActionType.DECEIVE]
    assert r.recommended_actions[0].target == "203.0.113.10"
    assert "AI" in r.summary


def test_actions_need_evidenced_ip_and_scale_with_severity() -> None:
    crit = rule_based_triage(_subject(severity=Severity.CRITICAL), ["e1"], ["203.0.113.10"])
    assert [a.action_type for a in crit.recommended_actions] == [ActionType.BLOCK_IP]
    high = rule_based_triage(_subject(severity=Severity.HIGH), ["e1"], ["203.0.113.10"])
    assert [a.action_type for a in high.recommended_actions] == [ActionType.RATE_LIMIT]
    # the subject's IP never appears as a source in the evidence -> nothing proposed
    none = rule_based_triage(_subject(severity=Severity.CRITICAL), ["e1"], ["198.51.100.1"])
    assert none.recommended_actions == []


def test_ai_canary_is_decisive() -> None:
    r = rule_based_triage(
        _subject(category="deception", rule_ids=["deception.canary"], tags=["ai_canary"], confidence=0.6),
        ["e1"],
    )
    assert r.actor_type == ActorType.AI_AGENT
    assert r.ai_agent_likelihood >= 0.95
    assert r.confidence >= 0.95


def test_incident_subject_uses_rule_attribution_and_kill_chain(settings: Settings) -> None:
    s = _subject(
        kind="incident",
        actor_type="automated_scanner",
        kill_chain=["reconnaissance", "initial_access", "credential_access"],
        rule_ids=["web.scanner_ua", "web.sqli"],
        alerts=[
            SubjectAlert(
                id="x", rule_id="web.scanner_ua", title="t", severity=Severity.LOW, category="recon"
            ),
            SubjectAlert(
                id="y", rule_id="web.sqli", title="t", severity=Severity.MEDIUM, category="exploit_attempt"
            ),
        ],
    )
    r = rule_based_triage(s, ["e1"])
    assert r.actor_type == ActorType.AUTOMATED_SCANNER
    assert r.attack_stage == AttackStage.CREDENTIAL_ACCESS
    assert r.category == "exploit_attempt"  # several rules -> the incident category


def test_mock_responder_registered_and_roundtrips(make_http_event) -> None:
    assert _RESPONDERS["TriageResult"] is mock_triage_responder
    ev = make_http_event("/x", ip="203.0.113.10")
    subject = _subject(severity=Severity.HIGH)
    ctx = TriageContext(evidence_ids=[ev.id], events=[ev])
    out = mock_triage_responder(system_prompt(TRIAGE_ALERT, "en"), build_user_prompt(subject, ctx))
    result = TriageResult.model_validate(out)
    assert result.evidence_ids == [ev.id]
    assert result.severity == Severity.HIGH
    assert [a.target for a in result.recommended_actions] == ["203.0.113.10"]
    # same answer as the in-process fallback for the same input
    assert result == rule_based_triage(subject, [ev.id], ["203.0.113.10"], lang="en")


def test_mock_responder_tolerates_garbage() -> None:
    out = mock_triage_responder("sys", "no blocks here")
    result = TriageResult.model_validate(out)
    assert result.evidence_ids == []
