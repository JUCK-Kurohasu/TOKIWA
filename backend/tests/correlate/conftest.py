"""Factories for correlation tests (rows are inserted directly; no detectors involved)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any

import pytest

from tokiwa.db.models.detection import AlertRow
from tokiwa.db.session import session_scope
from tokiwa.pipeline.store import store_events
from tokiwa.schemas.alerts import Alert
from tokiwa.schemas.events import Event
from tokiwa.util import new_id, utcnow

AddAlert = Callable[..., Awaitable[Alert]]
AddEvents = Callable[..., Awaitable[list[str]]]


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
        last_seen: datetime | None = None,
        details: dict[str, Any] | None = None,
    ) -> Alert:
        now = utcnow()
        first = first_seen or now
        row = AlertRow(
            id=new_id(),
            created_at=first,
            updated_at=first,
            first_seen=first,
            last_seen=last_seen or first,
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
            details=details or {},
            status=status,
        )
        async with session_scope() as s:
            s.add(row)
            await s.flush()
            return Alert.model_validate(row)

    return _add


@pytest.fixture
def add_events() -> AddEvents:
    async def _add(*events: Event) -> list[str]:
        async with session_scope() as s:
            await store_events(s, list(events))
        return [e.id for e in events]

    return _add
