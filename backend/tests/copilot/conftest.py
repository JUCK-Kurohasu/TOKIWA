"""Copilot test helpers: a scripted fake LLM provider and seed data for the read-only tools."""

from __future__ import annotations

import copy
from collections.abc import Callable
from datetime import timedelta
from typing import Any, ClassVar

import pytest
from pydantic import BaseModel

from tokiwa.config import Settings
from tokiwa.db.models.detection import AlertRow, IncidentRow
from tokiwa.db.models.intel import AssetRow, VulnMatchRow, VulnRow
from tokiwa.db.models.response import ResponseActionRow
from tokiwa.db.models.telemetry import ActorSessionRow
from tokiwa.db.session import session_scope
from tokiwa.llm import gateway as gw
from tokiwa.llm.base import ChatTurn, LLMProvider, LLMUsage, ProviderResponse, ToolCall, ToolSpec
from tokiwa.pipeline.store import store_events
from tokiwa.schemas.events import Event
from tokiwa.schemas.system import Role, User
from tokiwa.util import utcnow

Step = ChatTurn | Exception | Callable[[list[dict[str, Any]]], ChatTurn]


class ScriptedProvider(LLMProvider):
    """Returns pre-scripted assistant turns in order and records every request it receives."""

    name: ClassVar[str] = "scripted"

    def __init__(self, script: list[Step]) -> None:
        self.script = list(script)
        self.requests: list[dict[str, Any]] = []

    def available(self) -> bool:
        return True

    async def complete_structured(  # pragma: no cover - copilot only uses chat()
        self,
        *,
        model: str,
        system: str,
        user: str,
        schema: type[BaseModel],
        max_tokens: int,
        effort: str | None,
        cache: bool,
        web_search: bool = False,
        web_search_max_uses: int = 5,
        allowed_domains: list[str] | None = None,
    ) -> ProviderResponse:
        raise NotImplementedError

    async def chat(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec],
        max_tokens: int,
        effort: str | None,
        cache: bool,
    ) -> ChatTurn:
        self.requests.append(
            {
                "model": model,
                "system": system,
                "messages": copy.deepcopy(messages),
                "tools": [t.name for t in tools],
            }
        )
        if not self.script:
            raise AssertionError("unexpected extra LLM call")
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        if callable(step):
            return step(messages)
        return step


def tool_turn(
    *calls: tuple[str, str, dict[str, Any]], text: str = "Let me check.", thinking: bool = False
) -> ChatTurn:
    raw: list[dict[str, Any]] = []
    if thinking:
        raw.append({"type": "thinking", "thinking": "", "signature": "sig-tool"})
    if text:
        raw.append({"type": "text", "text": text})
    raw += [{"type": "tool_use", "id": cid, "name": name, "input": inp} for cid, name, inp in calls]
    return ChatTurn(
        model="claude-test",
        text=text,
        tool_calls=[ToolCall(id=cid, name=name, input=inp) for cid, name, inp in calls],
        raw_content=raw,
        usage=LLMUsage(input_tokens=100, output_tokens=20),
        stop_reason="tool_use",
    )


def text_turn(text: str, *, thinking: bool = False) -> ChatTurn:
    raw: list[dict[str, Any]] = []
    if thinking:
        raw.append({"type": "thinking", "thinking": "", "signature": "sig-text"})
    raw.append({"type": "text", "text": text})
    return ChatTurn(
        model="claude-test",
        text=text,
        raw_content=raw,
        usage=LLMUsage(input_tokens=120, output_tokens=40),
        stop_reason="end_turn",
    )


@pytest.fixture
def scripted(settings: Settings) -> Callable[[list[Step]], ScriptedProvider]:
    def install(script: list[Step]) -> ScriptedProvider:
        provider = ScriptedProvider(script)
        gw.set_gateway(gw.LLMGateway(provider=provider, settings=settings))
        return provider

    return install


@pytest.fixture
def analyst() -> User:
    return User(id="user-analyst-1", username="alice", role=Role.ANALYST, created_at=utcnow())


ATTACKER_IP = "203.0.113.10"
OTHER_IP = "198.51.100.7"


@pytest.fixture
async def seeded(db: None, make_http_event: Callable[..., Event]) -> dict[str, Any]:
    """A small, realistic dataset: an AI-agent-like session, alerts, an incident, a KEV match, an action."""
    now = utcnow()
    session_id = "sess-ai-1"
    events = [
        make_http_event("/robots.txt", ts=now - timedelta(minutes=10), session_id=session_id),
        make_http_event("/api/v1/users", ts=now - timedelta(minutes=9), status=401, session_id=session_id),
        make_http_event(
            "/api/v1/users",
            query="id=1' OR '1'='1",
            ts=now - timedelta(minutes=8),
            status=500,
            session_id=session_id,
        ),
        make_http_event("/index.html", ip=OTHER_IP, ts=now - timedelta(minutes=5)),
    ]
    async with session_scope() as s:
        await store_events(s, events)
        s.add(
            ActorSessionRow(
                id=session_id,
                source_ip=ATTACKER_IP,
                client_fingerprint="fp-1",
                user_agent="python-httpx/0.28",
                first_seen=now - timedelta(minutes=10),
                last_seen=now - timedelta(minutes=8),
                request_count=3,
                error_count=2,
                unique_paths=2,
                features={"mean_gap_ms": 4200.0, "mutation_rate": 0.6},
                ai_score=0.87,
                classification="ai_agent",
            )
        )
        s.add(
            IncidentRow(
                id="inc-1",
                title="AI agent reconnaissance and SQLi against app.lab",
                summary="Autonomous agent enumerated the API then attempted SQL injection.",
                severity="high",
                status="open",
                category="ai_agent",
                actor_type="ai_agent",
                ai_score=0.87,
                source_ips=[ATTACKER_IP],
                alert_count=2,
                kill_chain=["reconnaissance", "initial_access"],
            )
        )
        s.add(
            AlertRow(
                id="alert-sqli",
                fingerprint="fp-sqli",
                rule_id="web.sqli",
                detector="web.sqli",
                title="SQL injection attempt",
                severity="high",
                category="exploit_attempt",
                source_ip=ATTACKER_IP,
                ai_score=0.8,
                evidence_event_ids=[events[2].id],
                incident_id="inc-1",
                triage={
                    "tier": "fast",
                    "prompt_version": "triage@1",
                    "result": {
                        "summary": "SQLi probe by an AI agent",
                        "severity": "high",
                        "confidence": 0.8,
                        "actor_type": "ai_agent",
                        "ai_agent_likelihood": 0.85,
                        "attack_stage": "initial_access",
                        "recommended_actions": [
                            {
                                "action_type": "block_ip",
                                "target": ATTACKER_IP,
                                "reason": "SQLi",
                                "ttl_minutes": 60,
                            }
                        ],
                    },
                },
            )
        )
        s.add(
            AlertRow(
                id="alert-recon",
                fingerprint="fp-recon",
                rule_id="ai.recon",
                detector="ai.recon",
                title="AI-agent style API discovery",
                severity="medium",
                category="ai_agent",
                source_ip=ATTACKER_IP,
                ai_score=0.9,
                incident_id="inc-1",
            )
        )
        s.add(
            ResponseActionRow(
                id="act-1",
                action_type="block_ip",
                target=ATTACKER_IP,
                reason="SQLi from AI agent",
                proposed_by="llm",
                incident_id="inc-1",
                status="proposed",
                ttl_minutes=60,
            )
        )
        s.add(
            AssetRow(
                id="asset-web",
                name="web-frontend",
                kind="web_app",
                hostname="app.lab",
                ips=["10.0.0.5"],
                software=[{"vendor": "nginx", "product": "nginx", "version": "1.25.0"}],
                criticality="high",
            )
        )
        s.add(
            VulnRow(
                id="CVE-2025-0001",
                title="nginx request smuggling",
                description="A request smuggling flaw.",
                cvss_score=9.1,
                severity="critical",
                epss=0.42,
                kev=True,
            )
        )
        s.add(VulnRow(id="CVE-2025-0002", title="minor issue", cvss_score=3.1, epss=0.01, kev=False))
        s.add(
            VulnMatchRow(
                id="match-1",
                vuln_id="CVE-2025-0001",
                asset_id="asset-web",
                reason="nginx 1.25.0 in affected range",
                confidence=0.9,
            )
        )
        s.add(
            VulnMatchRow(
                id="match-2",
                vuln_id="CVE-2025-0002",
                asset_id="asset-web",
                reason="nginx minor",
                confidence=0.5,
            )
        )
    return {"events": events, "session_id": session_id}
