"""Factories and LLM test doubles for triage tests."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any, ClassVar

import pytest
from pydantic import BaseModel

from tokiwa.config import Settings
from tokiwa.db.models.detection import AlertRow
from tokiwa.db.session import session_scope
from tokiwa.llm import gateway as gw
from tokiwa.llm.base import ProviderResponse
from tokiwa.llm.mock import MockProvider
from tokiwa.pipeline.store import store_events
from tokiwa.schemas.alerts import Alert
from tokiwa.schemas.events import Event
from tokiwa.util import new_id, utcnow

AddAlert = Callable[..., Awaitable[Alert]]


@pytest.fixture
def add_alert() -> AddAlert:
    async def _add(
        *,
        rule_id: str = "web.sqli",
        title: str = "SQL injection attempt",
        severity: str = "medium",
        category: str = "exploit_attempt",
        source_ip: str | None = "203.0.113.10",
        ai_score: float | None = None,
        mitre: list[str] | None = None,
        entities: dict[str, str] | None = None,
        tags: list[str] | None = None,
        evidence: list[str] | None = None,
        confidence: float = 0.7,
        status: str = "new",
        first_seen: datetime | None = None,
    ) -> Alert:
        now = first_seen or utcnow()
        row = AlertRow(
            id=new_id(),
            created_at=now,
            updated_at=now,
            first_seen=now,
            last_seen=now,
            count=1,
            fingerprint=f"{rule_id}|{source_ip}|{new_id()}",
            rule_id=rule_id,
            detector=rule_id,
            title=title,
            description="",
            severity=severity,
            confidence=confidence,
            category=category,
            mitre=mitre if mitre is not None else ["T1190"],
            ai_score=ai_score,
            source_ip=source_ip,
            entities=entities or {},
            evidence_event_ids=evidence or [],
            tags=tags or [],
            details={},
            status=status,
        )
        async with session_scope() as s:
            s.add(row)
            await s.flush()
            return Alert.model_validate(row)

    return _add


@pytest.fixture
def add_events() -> Callable[..., Awaitable[list[str]]]:
    async def _add(*events: Event) -> list[str]:
        async with session_scope() as s:
            await store_events(s, list(events))
        return [e.id for e in events]

    return _add


class RefusingProvider(MockProvider):
    """Simulates a safety-classifier refusal (stop_reason == "refusal")."""

    name: ClassVar[str] = "mock"

    async def complete_structured(
        self, *, model: str, schema: type[BaseModel], **kw: Any
    ) -> ProviderResponse:
        self.calls.append({"model": model, "schema": schema.__name__, **kw})
        return ProviderResponse(
            model=model, text="I can't help with that.", refused=True, stop_reason="refusal"
        )


@pytest.fixture
def refusing_llm(settings: Settings) -> RefusingProvider:
    provider = RefusingProvider()
    gw.set_gateway(gw.LLMGateway(provider=provider, settings=settings))
    return provider
