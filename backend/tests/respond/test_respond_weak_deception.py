"""Audit #133 (respond side): a block that rests only on passive / browser-induced canary trips is never
auto-approved. A third party can make any visitor's browser fetch a decoy (``<img src=...>``); rule triage no
longer proposes blocks from such trips, but an LLM verdict still might, and auto-approval would then execute it.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from tokiwa.db.models.core import AuditRow
from tokiwa.db.models.detection import AlertRow
from tokiwa.db.session import session_scope
from tokiwa.respond.service import propose_action
from tokiwa.schemas.response import ActionProposal, ActionProposer, ActionStatus
from tokiwa.schemas.triage import ActionType
from tokiwa.util import new_id

pytestmark = pytest.mark.usefixtures("db")

IP = "198.51.100.23"


async def _alert(incident_id: str, *, detector: str, provenance: str | None) -> str:
    aid = new_id()
    details = {"provenance": provenance} if provenance else {}
    async with session_scope() as s:
        s.add(
            AlertRow(
                id=aid,
                fingerprint=aid,
                rule_id=detector,
                detector=detector,
                title="t",
                severity="medium",
                category="deception" if detector.startswith("deception.") else "sqli",
                source_ip=IP,
                details=details,
                incident_id=incident_id,
            )
        )
    return aid


def _llm(incident_id: str) -> ActionProposal:
    return ActionProposal(
        action_type=ActionType.BLOCK_IP,
        target=IP,
        reason="LLM: canary tripped",
        proposed_by=ActionProposer.LLM,
        incident_id=incident_id,
    )


async def _withheld() -> int:
    async with session_scope() as s:
        rows = (
            await s.execute(select(AuditRow).where(AuditRow.action == "response.auto_approve_withheld"))
        ).scalars()
        return len(list(rows))


@pytest.mark.parametrize("provenance", ["passive", "induced"])
async def test_weak_canary_evidence_is_not_auto_approved(spy, configure, provenance: str) -> None:  # type: ignore[no-untyped-def]
    configure(auto_approve_enabled=True, auto_approve_actions=["block_ip"])
    inc = new_id()
    await _alert(inc, detector="deception.trip", provenance=provenance)
    action = await propose_action(_llm(inc))
    assert action is not None and action.status == ActionStatus.PROPOSED
    assert spy.applied == []
    assert await _withheld() == 1


async def test_direct_canary_follow_is_still_auto_approved(spy, configure) -> None:  # type: ignore[no-untyped-def]
    configure(auto_approve_enabled=True, auto_approve_actions=["block_ip"])
    inc = new_id()
    await _alert(inc, detector="deception.trip", provenance="direct")
    action = await propose_action(_llm(inc))
    assert action is not None and action.status != ActionStatus.PROPOSED
    assert len(spy.applied) == 1


async def test_other_evidence_in_the_incident_allows_auto_approve(spy, configure) -> None:  # type: ignore[no-untyped-def]
    configure(auto_approve_enabled=True, auto_approve_actions=["block_ip"])
    inc = new_id()
    await _alert(inc, detector="deception.trip", provenance="induced")
    await _alert(inc, detector="web.sqli", provenance=None)
    action = await propose_action(_llm(inc))
    assert action is not None and action.status != ActionStatus.PROPOSED
    assert len(spy.applied) == 1 and await _withheld() == 0
