"""Fixtures for notify tests: no DNS / network (resolver stub + respx), fresh in-memory state."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest

from tokiwa.notify import outbound
from tokiwa.notify import service as notify_service
from tokiwa.schemas.alerts import Alert, AlertCategory, AlertStatus, Incident, IncidentStatus
from tokiwa.schemas.common import ActorType, Severity
from tokiwa.util import new_id, utcnow

# Fake DNS: hostnames used in tests -> addresses. Anything else resolves to a public address.
FAKE_DNS: dict[str, list[str]] = {
    "internal.example.com": ["10.1.2.3"],
    "rebind.example.com": ["93.184.215.14", "127.0.0.1"],
    "metadata.example.com": ["169.254.169.254"],
}


@pytest.fixture(autouse=True)
def _no_dns_and_fresh_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    async def fake_resolve(host: str, port: int) -> list[str]:
        return FAKE_DNS.get(host, ["93.184.215.14"])

    monkeypatch.setattr(outbound, "_resolve", fake_resolve)
    notify_service.reset_notify_state()
    yield
    notify_service.reset_notify_state()


@pytest.fixture
def make_alert() -> Callable[..., Alert]:
    def _make(**kw: Any) -> Alert:
        now = utcnow()
        data: dict[str, Any] = {
            "id": new_id(),
            "created_at": now,
            "updated_at": now,
            "first_seen": now,
            "last_seen": now,
            "count": 1,
            "fingerprint": "fp-1",
            "rule_id": "web.sqli",
            "detector": "web.sqli",
            "title": "SQL injection attempt",
            "description": "union select in query",
            "severity": Severity.HIGH,
            "confidence": 0.8,
            "category": AlertCategory.EXPLOIT_ATTEMPT,
            "mitre": ["T1190"],
            "ai_score": 0.4,
            "source_ip": "203.0.113.10",
            "entities": {},
            "evidence_event_ids": [],
            "tags": [],
            "details": {},
            "status": AlertStatus.NEW,
            "incident_id": None,
            "triage": None,
        }
        data.update(kw)
        return Alert(**data)

    return _make


@pytest.fixture
def make_incident() -> Callable[..., Incident]:
    def _make(**kw: Any) -> Incident:
        now = utcnow()
        data: dict[str, Any] = {
            "id": new_id(),
            "created_at": now,
            "updated_at": now,
            "first_seen": now,
            "last_seen": now,
            "title": "AI agent recon against app.lab",
            "summary": "",
            "severity": Severity.MEDIUM,
            "status": IncidentStatus.OPEN,
            "category": AlertCategory.AI_AGENT,
            "actor_type": ActorType.AI_AGENT,
            "ai_score": 0.9,
            "source_ips": ["203.0.113.10"],
            "alert_count": 3,
            "kill_chain": ["reconnaissance", "discovery"],
            "mitre": [],
            "triage": None,
            "assignee": None,
            "tags": [],
        }
        data.update(kw)
        return Incident(**data)

    return _make
