"""Triage service: tiering, escalation, evidence validation + retry, fallbacks, proposals, concurrency."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, ClassVar

import pytest
from pydantic import BaseModel

from tokiwa.bus import bus
from tokiwa.config import Settings, TriageSettings
from tokiwa.correlate.service import correlate_alert
from tokiwa.db.models.detection import AlertRow
from tokiwa.db.session import session_scope
from tokiwa.llm import gateway as gw
from tokiwa.llm.base import LLMTier, ProviderResponse
from tokiwa.llm.gateway import BudgetExceededError, get_gateway
from tokiwa.llm.mock import MockProvider
from tokiwa.respond import service as respond_service
from tokiwa.schemas.common import Severity
from tokiwa.schemas.response import ActionProposal
from tokiwa.schemas.triage import TriageRecord, TriageResult
from tokiwa.triage.fallback import mock_triage_responder, parse_untrusted_blocks
from tokiwa.triage.prompts import RETRY_NOTE
from tokiwa.triage.service import (
    get_triage_service,
    incident_signature,
    should_escalate,
    wants_llm,
)

pytestmark = pytest.mark.usefixtures("db")

AddAlert = Callable[..., Awaitable[Any]]
FAST = "claude-haiku-5-5"
DEEP = "claude-opus-5-5"


def _verdict(**kw: Any) -> TriageResult:
    base: dict[str, Any] = {
        "severity": "medium",
        "category": "sqli",
        "confidence": 0.9,
        "actor_type": "human",
        "ai_agent_likelihood": 0.1,
        "attack_stage": "initial_access",
        "summary": "s",
        "rationale": "r",
        "evidence_ids": [],
    }
    base.update(kw)
    return TriageResult.model_validate(base)


def _shown_ids(user: str) -> list[str]:
    return list(parse_untrusted_blocks(user)["evidence_ids"])


async def _seeded_alert(add_alert: AddAlert, add_events: Any, make_http_event: Any, **kw: Any) -> Any:
    ip = kw.pop("ip", "203.0.113.10")
    events = [make_http_event(f"/p{i}", ip=ip) for i in range(3)]
    ids = await add_events(*events)
    return await add_alert(source_ip=ip, evidence=ids, **kw)


async def _stored(alert_id: str) -> tuple[str, TriageRecord]:
    async with session_scope() as s:
        row = await s.get(AlertRow, alert_id)
        assert row is not None and row.triage is not None
        return row.status, TriageRecord.model_validate(row.triage)


# ------------------------------------------------------------------ pure decisions


def test_wants_llm_and_escalation_rules() -> None:
    cfg = TriageSettings()  # min medium, escalate < 0.6 or >= high
    assert not wants_llm(Severity.LOW, cfg)
    assert wants_llm(Severity.MEDIUM, cfg) and wants_llm("critical", cfg)
    assert not should_escalate(_verdict(confidence=0.9), Severity.MEDIUM, cfg)
    assert should_escalate(_verdict(confidence=0.5), Severity.MEDIUM, cfg)  # unsure
    assert should_escalate(_verdict(severity="high"), Severity.MEDIUM, cfg)  # verdict severity
    assert should_escalate(_verdict(severity="low"), Severity.HIGH, cfg)  # rule severity counts too
    strict = TriageSettings(escalate_severity="critical", escalate_confidence_below=0.3)
    assert not should_escalate(_verdict(severity="high", confidence=0.5), Severity.HIGH, strict)


# ------------------------------------------------------------------ tiers


async def test_below_threshold_uses_rules_without_llm(
    mock_llm: MockProvider, add_alert, add_events, make_http_event
) -> None:
    a = await _seeded_alert(add_alert, add_events, make_http_event, severity="low")
    out = await get_triage_service().triage_alert(a.id)
    assert out is not None and out.status == "triaged"
    assert mock_llm.calls == []
    status, rec = await _stored(a.id)
    assert status == "triaged" and rec.tier == "rules" and rec.model is None
    assert rec.prompt_version == "triage.rules@1"


async def test_fast_tier_verdict(mock_llm: MockProvider, add_alert, add_events, make_http_event) -> None:
    a = await _seeded_alert(add_alert, add_events, make_http_event, severity="medium", confidence=0.8)
    await get_triage_service().triage_alert(a.id)
    assert [c["model"] for c in mock_llm.calls] == [FAST]
    call = mock_llm.calls[0]
    assert "SECURITY POLICY FOR DATA HANDLING" in call["system"]
    assert '<untrusted_data name="evidence_events">' in call["user"]
    status, rec = await _stored(a.id)
    assert status == "triaged"
    assert rec.tier == "fast" and rec.model == FAST and not rec.escalated
    assert rec.prompt_version == "triage.alert@1" and rec.llm_call_id
    assert set(rec.result.evidence_ids) <= set(a.evidence_event_ids)


async def test_escalates_on_high_severity(
    mock_llm: MockProvider, add_alert, add_events, make_http_event
) -> None:
    a = await _seeded_alert(add_alert, add_events, make_http_event, severity="high")
    await get_triage_service().triage_alert(a.id)
    assert [c["model"] for c in mock_llm.calls] == [FAST, DEEP]
    _, rec = await _stored(a.id)
    assert rec.tier == "deep" and rec.model == DEEP and rec.escalated


async def test_escalates_on_low_confidence(
    mock_llm: MockProvider, add_alert, add_events, make_http_event
) -> None:
    a = await _seeded_alert(add_alert, add_events, make_http_event, severity="medium", confidence=0.4)
    await get_triage_service().triage_alert(a.id)
    assert [c["model"] for c in mock_llm.calls] == [FAST, DEEP]


async def test_deep_failure_keeps_fast_verdict(
    mock_llm: MockProvider, add_alert, add_events, make_http_event
) -> None:
    calls = {"n": 0}

    def responder(system: str, user: str) -> dict[str, Any]:
        calls["n"] += 1
        if calls["n"] == 1:
            return _verdict(severity="high", evidence_ids=_shown_ids(user)[:1]).model_dump(mode="json")
        return {"severity": "bogus"}  # deep tier returns invalid output

    mock_llm._local["TriageResult"] = responder
    a = await _seeded_alert(add_alert, add_events, make_http_event, severity="medium")
    await get_triage_service().triage_alert(a.id)
    _, rec = await _stored(a.id)
    assert rec.tier == "fast" and rec.escalated


async def test_forced_tier_and_force_bypasses_threshold(
    mock_llm: MockProvider, add_alert, add_events, make_http_event
) -> None:
    a = await _seeded_alert(add_alert, add_events, make_http_event, severity="low")
    await get_triage_service().triage_alert(a.id, tier=LLMTier.DEEP, force=True)
    assert [c["model"] for c in mock_llm.calls] == [DEEP]
    mock_llm.calls.clear()
    b = await _seeded_alert(add_alert, add_events, make_http_event, severity="critical")
    await get_triage_service().triage_alert(b.id, tier=LLMTier.FAST, force=True)
    assert [c["model"] for c in mock_llm.calls] == [FAST]  # pinned tier: no escalation


async def test_no_evidence_means_rules(mock_llm: MockProvider, add_alert) -> None:
    a = await add_alert(severity="high", evidence=["does-not-exist"])
    await get_triage_service().triage_alert(a.id)
    assert mock_llm.calls == []
    _, rec = await _stored(a.id)
    assert rec.tier == "rules"


# ------------------------------------------------------------------ evidence validation


async def test_invalid_ids_are_dropped_and_recorded(
    mock_llm: MockProvider, add_alert, add_events, make_http_event
) -> None:
    mock_llm._local["TriageResult"] = lambda s, u: _verdict(
        evidence_ids=["forged-id", _shown_ids(u)[0]]
    ).model_dump(mode="json")
    a = await _seeded_alert(add_alert, add_events, make_http_event)
    await get_triage_service().triage_alert(a.id)
    assert len(mock_llm.calls) == 1
    _, rec = await _stored(a.id)
    assert rec.tier == "fast"
    assert rec.result.evidence_ids == [a.evidence_event_ids[0]]
    assert rec.rejected_evidence_ids == ["forged-id"]


async def test_retry_once_when_no_valid_evidence(
    mock_llm: MockProvider, add_alert, add_events, make_http_event
) -> None:
    def responder(system: str, user: str) -> dict[str, Any]:
        ids = ["forged-1"] if RETRY_NOTE not in user else _shown_ids(user)[:1]
        return _verdict(evidence_ids=ids).model_dump(mode="json")

    mock_llm._local["TriageResult"] = responder
    a = await _seeded_alert(add_alert, add_events, make_http_event)
    await get_triage_service().triage_alert(a.id)
    assert len(mock_llm.calls) == 2
    assert RETRY_NOTE in mock_llm.calls[1]["user"]
    _, rec = await _stored(a.id)
    assert rec.tier == "fast" and rec.rejected_evidence_ids == ["forged-1"]


async def test_still_invalid_after_retry_falls_back(
    mock_llm: MockProvider, add_alert, add_events, make_http_event
) -> None:
    mock_llm._local["TriageResult"] = lambda s, u: _verdict(evidence_ids=["nope"]).model_dump(mode="json")
    a = await _seeded_alert(add_alert, add_events, make_http_event)
    await get_triage_service().triage_alert(a.id)
    assert len(mock_llm.calls) == 2  # one retry only
    status, rec = await _stored(a.id)
    assert status == "triaged" and rec.tier == "rules"
    assert rec.rejected_evidence_ids == ["nope"]


# ------------------------------------------------------------------ failure modes -> rules


async def test_budget_exceeded_falls_back(
    mock_llm: MockProvider, monkeypatch, add_alert, add_events, make_http_event
) -> None:
    async def over_budget() -> None:
        raise BudgetExceededError("daily LLM budget reached")

    monkeypatch.setattr(get_gateway(), "check_budget", over_budget)
    a = await _seeded_alert(add_alert, add_events, make_http_event, severity="high")
    await get_triage_service().triage_alert(a.id)
    assert mock_llm.calls == []
    status, rec = await _stored(a.id)
    assert status == "triaged" and rec.tier == "rules"


async def test_refusal_falls_back(refusing_llm, add_alert, add_events, make_http_event) -> None:
    a = await _seeded_alert(add_alert, add_events, make_http_event, severity="high")
    await get_triage_service().triage_alert(a.id)
    assert len(refusing_llm.calls) == 1  # refusal is final: no deep retry
    status, rec = await _stored(a.id)
    assert status == "triaged" and rec.tier == "rules"


async def test_invalid_output_falls_back(
    mock_llm: MockProvider, add_alert, add_events, make_http_event
) -> None:
    mock_llm._local["TriageResult"] = lambda s, u: {"severity": "apocalyptic"}
    a = await _seeded_alert(add_alert, add_events, make_http_event)
    await get_triage_service().triage_alert(a.id)
    status, rec = await _stored(a.id)
    assert status == "triaged" and rec.tier == "rules"


async def test_provider_exception_falls_back(
    settings: Settings, add_alert, add_events, make_http_event
) -> None:
    class Boom(MockProvider):
        name: ClassVar[str] = "mock"

        async def complete_structured(self, **kw: Any) -> ProviderResponse:
            raise RuntimeError("connection reset")

    gw.set_gateway(gw.LLMGateway(provider=Boom(), settings=settings))
    a = await _seeded_alert(add_alert, add_events, make_http_event)
    await get_triage_service().triage_alert(a.id)
    _, rec = await _stored(a.id)
    assert rec.tier == "rules"


# ------------------------------------------------------------------ response proposals


async def test_only_evidenced_targets_are_proposed(
    mock_llm: MockProvider, monkeypatch, add_alert, add_events, make_http_event
) -> None:
    proposals: list[ActionProposal] = []

    async def fake_propose(p: ActionProposal) -> None:
        proposals.append(p)

    monkeypatch.setattr(respond_service, "propose_action", fake_propose)
    actions = [
        {"action_type": "block_ip", "target": "203.0.113.10", "reason": "attacker", "ttl_minutes": 30},
        {"action_type": "block_ip", "target": "203.0.113.10", "reason": "dup"},
        {"action_type": "block_ip", "target": "10.0.0.5", "reason": "destination = our own server"},
        {"action_type": "rate_limit", "target": "203.0.113.0/24", "reason": "cidr widening"},
        {"action_type": "webhook", "target": "http://169.254.169.254/", "reason": "ssrf"},
    ]  # (schema caps the list at 5; "IP not in evidence" is covered in test_triage_evidence)
    mock_llm._local["TriageResult"] = lambda s, u: _verdict(
        evidence_ids=_shown_ids(u), recommended_actions=actions
    ).model_dump(mode="json")
    a = await _seeded_alert(add_alert, add_events, make_http_event)
    await get_triage_service().triage_alert(a.id)
    assert len(proposals) == 1
    p = proposals[0]
    assert (p.action_type, p.target, p.ttl_minutes) == ("block_ip", "203.0.113.10", 30)
    assert p.proposed_by == "llm" and p.alert_id == a.id


async def test_rule_proposals_marked_rule(
    mock_llm: MockProvider, monkeypatch, add_alert, add_events, make_http_event
) -> None:
    proposals: list[ActionProposal] = []

    async def fake_propose(p: ActionProposal) -> None:
        proposals.append(p)

    monkeypatch.setattr(respond_service, "propose_action", fake_propose)
    mock_llm._local["TriageResult"] = lambda s, u: {"severity": "bogus"}  # force the rule path
    a = await _seeded_alert(add_alert, add_events, make_http_event, severity="critical")
    await get_triage_service().triage_alert(a.id)
    assert [(p.action_type, p.proposed_by) for p in proposals] == [("block_ip", "rule")]


async def test_respond_not_implemented_is_tolerated(
    mock_llm: MockProvider, monkeypatch, add_alert, add_events, make_http_event
) -> None:
    calls: list[ActionProposal] = []

    async def not_yet(p: ActionProposal) -> None:  # behaves like the respond stub
        calls.append(p)
        raise NotImplementedError

    monkeypatch.setattr(respond_service, "propose_action", not_yet)
    a = await _seeded_alert(add_alert, add_events, make_http_event, severity="critical")
    out = await get_triage_service().triage_alert(a.id)
    assert calls  # a proposal was attempted and the failure swallowed
    assert out is not None and out.status == "triaged"
    assert out.triage is not None and out.triage.result.recommended_actions


# ------------------------------------------------------------------ incidents & concurrency


async def test_incident_triage_and_resignature_gate(
    mock_llm: MockProvider, add_alert, add_events, make_http_event
) -> None:
    a = await _seeded_alert(add_alert, add_events, make_http_event, severity="medium", confidence=0.9)
    inc = await correlate_alert(a.id)
    assert inc is not None
    published: list[Any] = []

    async def on_update(i: Any) -> None:
        published.append(i)

    bus.subscribe("incident.updated", on_update)
    svc = get_triage_service()
    await svc.handle_incident_event(inc)
    await bus.drain()
    assert len(mock_llm.calls) == 1
    assert mock_llm.calls[0]["system"].startswith("You are the SOC incident analyst")
    assert published and published[-1].triage is not None
    triaged = published[-1]
    assert triaged.summary == triaged.triage.result.summary

    # same material state -> no second LLM call
    await svc.handle_incident_event(triaged)
    assert len(mock_llm.calls) == 1
    # severity changed -> re-triage
    b = await _seeded_alert(add_alert, add_events, make_http_event, severity="high", rule_id="web.log4shell")
    inc2 = await correlate_alert(b.id)
    assert inc2 is not None and inc2.id == inc.id
    assert incident_signature(inc2) != incident_signature(triaged)
    await svc.handle_incident_event(inc2)
    assert len(mock_llm.calls) == 3  # fast + deep (high severity escalates)


async def test_auto_triage_disabled(
    mock_llm: MockProvider, monkeypatch, add_alert, add_events, make_http_event, settings: Settings
) -> None:
    monkeypatch.setattr(settings.triage, "auto_triage", False)
    a = await _seeded_alert(add_alert, add_events, make_http_event)
    await get_triage_service().handle_alert_created(a)
    assert mock_llm.calls == []
    async with session_scope() as s:
        row = await s.get(AlertRow, a.id)
        assert row is not None and row.triage is None and row.status == "new"


class _SlowProvider(MockProvider):
    name: ClassVar[str] = "mock"

    def __init__(self) -> None:
        super().__init__()
        self.active = 0
        self.peak = 0

    async def complete_structured(
        self, *, model: str, system: str, user: str, schema: type[BaseModel], **kw: Any
    ) -> ProviderResponse:
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            await asyncio.sleep(0.05)
            self.calls.append({"model": model, "user": user})
            parsed = mock_triage_responder(system, user)
            return ProviderResponse(model=model, parsed=parsed, stop_reason="end_turn")
        finally:
            self.active -= 1


async def test_concurrency_limit_and_no_duplicate_triage(
    settings: Settings, monkeypatch, add_alert, add_events, make_http_event
) -> None:
    monkeypatch.setattr(settings.triage, "max_concurrent", 2)
    provider = _SlowProvider()
    gw.set_gateway(gw.LLMGateway(provider=provider, settings=settings))
    alerts = [
        await _seeded_alert(add_alert, add_events, make_http_event, ip=f"203.0.113.{i}", confidence=0.9)
        for i in range(1, 6)
    ]
    svc = get_triage_service()
    # each alert announced twice (e.g. duplicate bus delivery): must be triaged once
    await asyncio.gather(*(svc.handle_alert_created(a) for a in alerts for _ in range(2)))
    assert provider.peak <= 2
    assert len(provider.calls) == len(alerts)
