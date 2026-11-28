"""Audit #23: a network action on an address many people share (carrier-grade NAT, corporate NAT, an internal
proxy) is never auto-approved. One attacker behind a CGNAT exit would otherwise get everyone behind it blocked
within seconds. A human can still approve it: ``shared_cidrs`` warns, unlike ``protected_cidrs`` which refuses.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from tokiwa.config import ResponseSettings
from tokiwa.db.models.core import AuditRow
from tokiwa.db.session import session_scope
from tokiwa.respond.service import approve_action, propose_action
from tokiwa.respond.validate import shared_network
from tokiwa.schemas.response import ActionProposal, ActionProposer, ActionStatus
from tokiwa.schemas.triage import ActionType

pytestmark = pytest.mark.usefixtures("db")


def _proposal(target: str, action: ActionType = ActionType.BLOCK_IP) -> ActionProposal:
    return ActionProposal(
        action_type=action, target=target, reason="rule: critical", proposed_by=ActionProposer.RULE
    )


async def _withheld_details() -> list[dict[str, object]]:
    async with session_scope() as s:
        rows = (
            await s.execute(select(AuditRow).where(AuditRow.action == "response.auto_approve_withheld"))
        ).scalars()
        return [r.details or {} for r in rows]


@pytest.mark.parametrize(
    ("target", "action"),
    [
        ("100.64.12.34", ActionType.BLOCK_IP),  # RFC 6598 CGNAT: neither is_private nor is_global
        ("10.20.30.40", ActionType.RATE_LIMIT),
        ("192.168.1.0/24", ActionType.DECEIVE),
        ("fd00::1", ActionType.TARPIT),
    ],
)
async def test_shared_address_is_not_auto_approved(spy, configure, target: str, action: ActionType) -> None:  # type: ignore[no-untyped-def]
    configure(auto_approve_enabled=True, auto_approve_actions=[action.value])
    created = await propose_action(_proposal(target, action))
    assert created is not None and created.status == ActionStatus.PROPOSED
    assert spy.applied == []
    assert created.result["shared_address"]
    assert any("shared_cidrs" in n for n in created.result["validation_notes"])
    (details,) = await _withheld_details()
    assert details["reason"] == "shared_address"


async def test_human_can_still_approve_shared_address(spy, configure) -> None:  # type: ignore[no-untyped-def]
    configure(auto_approve_enabled=True, auto_approve_actions=["block_ip"])
    created = await propose_action(_proposal("100.64.12.34"))
    assert created is not None
    approved = await approve_action(created.id, actor="alice")
    assert approved.status != ActionStatus.PROPOSED
    assert len(spy.applied) == 1


async def test_public_address_still_auto_approved(spy, configure) -> None:  # type: ignore[no-untyped-def]
    configure(auto_approve_enabled=True, auto_approve_actions=["block_ip"])
    created = await propose_action(_proposal("198.51.100.77"))
    assert created is not None and created.status != ActionStatus.PROPOSED
    assert len(spy.applied) == 1
    assert "shared_address" not in created.result


def test_shared_network_overlap_and_config() -> None:
    s = ResponseSettings()
    assert shared_network("100.127.255.1", s) == "100.64.0.0/10"
    assert shared_network("100.128.0.1", s) is None  # just outside RFC 6598
    assert shared_network("10.0.0.0/7", s) == "10.0.0.0/8"  # overlap, not containment
    assert (
        shared_network("203.0.113.9", ResponseSettings(shared_cidrs=["203.0.113.0/24"])) == "203.0.113.0/24"
    )
    assert shared_network("10.1.1.1", ResponseSettings(shared_cidrs=[])) is None
    assert (
        shared_network("10.1.1.1", ResponseSettings(shared_cidrs=["nonsense", "10.0.0.0/8"])) == "10.0.0.0/8"
    )
