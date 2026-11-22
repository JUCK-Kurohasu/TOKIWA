"""Audit #63: a human reject / revert is remembered, so the same (type, target) is not re-proposed and, above all,
never auto-approved again right after a human lifted it (AGENTS.md §2-3: human approval is the default)."""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select

from tokiwa.bus import bus
from tokiwa.db.models.core import AuditRow
from tokiwa.db.models.response import ResponseActionRow
from tokiwa.db.models.response_suppression import ResponseSuppressionRow
from tokiwa.db.session import session_scope
from tokiwa.respond import suppress
from tokiwa.respond.service import create_proposal, propose_action, reject_action, revert_action
from tokiwa.schemas.response import ActionProposal, ActionProposer, ActionStatus
from tokiwa.schemas.suppressions import ResponseSuppressionIn, SuppressOptions
from tokiwa.schemas.triage import ActionType
from tokiwa.util import new_id, utcnow

pytestmark = pytest.mark.usefixtures("db")

IP = "203.0.113.9"


def _llm(target: str = IP, t: ActionType = ActionType.BLOCK_IP) -> ActionProposal:
    return ActionProposal(
        action_type=t, target=target, reason="LLM: block it", proposed_by=ActionProposer.LLM
    )


async def _count_actions() -> int:
    async with session_scope() as s:
        return int((await s.execute(select(func.count()).select_from(ResponseActionRow))).scalar_one())


async def _audit(action: str) -> list[AuditRow]:
    async with session_scope() as s:
        return list((await s.execute(select(AuditRow).where(AuditRow.action == action))).scalars().all())


async def _active_auto_block(spy, configure):  # type: ignore[no-untyped-def]
    configure(auto_approve_enabled=True, auto_approve_actions=["block_ip"])
    first = await propose_action(_llm())
    assert first is not None and first.status is ActionStatus.ACTIVE and first.approved_by == "policy"
    assert len(spy.applied) == 1
    return first


async def test_revert_with_suppression_drops_reproposal_even_with_auto_approve(spy, configure) -> None:  # type: ignore[no-untyped-def]
    first = await _active_auto_block(spy, configure)
    reverted = await revert_action(
        first.id, actor="alice", reason="shared NAT", suppress_options=SuppressOptions(suppress_hours=24)
    )
    assert reverted.status is ActionStatus.REVERTED
    assert reverted.result["revert_reason"] == "shared NAT" and reverted.result["suppression_id"]

    q = bus.listen()
    again = await propose_action(_llm())
    assert again is None  # dropped: no row, no approval request, no execution
    assert await _count_actions() == 1
    assert q.empty()
    bus.unlisten(q)
    assert len(spy.applied) == 1
    dropped = await _audit("response.propose_suppressed")
    assert len(dropped) == 1 and dropped[0].actor == "llm"
    async with session_scope() as s:
        row = await s.get(ResponseSuppressionRow, reverted.result["suppression_id"])
        assert row is not None and row.mode == "suppress" and row.hits == 1 and row.created_by == "alice"


async def test_plain_revert_still_blocks_auto_approve(spy, configure) -> None:  # type: ignore[no-untyped-def]
    """No option ticked in the UI: the proposal comes back, but only as a proposal (cooldown)."""
    first = await _active_auto_block(spy, configure)
    await revert_action(first.id, actor="alice")
    again = await propose_action(_llm())
    assert again is not None and again.id != first.id
    assert again.status is ActionStatus.PROPOSED and again.approved_by is None
    assert again.result["suppression"]["mode"] == "manual_only"
    assert len(spy.applied) == 1  # the reverted block was NOT re-applied
    assert len(await _audit("response.auto_approve_suppressed")) == 1


async def test_reject_then_enabling_auto_approve_does_not_approve_it(spy, configure) -> None:  # type: ignore[no-untyped-def]
    proposed = await propose_action(_llm())
    assert proposed is not None and proposed.status is ActionStatus.PROPOSED
    rejected = await reject_action(proposed.id, actor="bob", reason="monitoring host")
    assert rejected.result["suppression_id"]
    configure(auto_approve_enabled=True, auto_approve_actions=["block_ip"])
    again = await propose_action(_llm())
    assert again is not None and again.status is ActionStatus.PROPOSED
    assert spy.applied == []


async def test_cooldown_can_be_disabled(spy, configure) -> None:  # type: ignore[no-untyped-def]
    first = await _active_auto_block(spy, configure)
    configure(auto_approve_cooldown_minutes=0)
    await revert_action(first.id, actor="alice")
    again = await propose_action(_llm())
    assert (
        again is not None and again.status is ActionStatus.ACTIVE
    )  # explicit opt-out restores old behaviour
    assert len(spy.applied) == 2


async def _insert(
    target: str, *, mode: str = "suppress", expires_delta: timedelta | None = None, **kw
) -> str:  # type: ignore[no-untyped-def]
    now = utcnow()
    sid = new_id()
    async with session_scope() as s:
        s.add(
            ResponseSuppressionRow(
                id=sid,
                created_at=now,
                updated_at=now,
                action_type=kw.pop("action_type", "block_ip"),
                target=target,
                mode=mode,
                reason="",
                created_by="alice",
                expires_at=now + expires_delta if expires_delta is not None else None,
                **kw,
            )
        )
    return sid


async def test_expired_and_lifted_suppressions_are_ignored(spy, configure) -> None:  # type: ignore[no-untyped-def]
    configure(auto_approve_enabled=True, auto_approve_actions=["block_ip"])
    await _insert(IP, expires_delta=timedelta(minutes=-1))
    await _insert(IP, lifted_at=utcnow(), lifted_by="bob")
    action = await propose_action(_llm())
    assert action is not None and action.status is ActionStatus.ACTIVE


async def test_lift_restores_normal_behaviour(spy, configure) -> None:  # type: ignore[no-untyped-def]
    configure(auto_approve_enabled=True, auto_approve_actions=["block_ip"])
    held = await suppress.create_suppression(
        ResponseSuppressionIn(action_type=ActionType.BLOCK_IP, target=f"{IP}/32", suppress_permanent=True),
        actor="alice",
    )
    assert held.active and held.expires_at is None and held.target == IP
    assert await propose_action(_llm()) is None
    lifted = await suppress.lift_suppression(held.id, actor="bob")
    assert not lifted.active and lifted.lifted_by == "bob"
    action = await propose_action(_llm())
    assert action is not None and action.status is ActionStatus.ACTIVE


async def test_matching_is_by_type_and_overlapping_network(spy, configure) -> None:  # type: ignore[no-untyped-def]
    configure(auto_approve_enabled=True, auto_approve_actions=["block_ip", "rate_limit"])
    await _insert("203.0.113.0/24", expires_delta=timedelta(hours=1))
    assert await propose_action(_llm("203.0.113.77")) is None  # host inside the suppressed /24
    assert await propose_action(_llm("203.0.112.0/23")) is None  # broader CIDR would re-block it
    other = await propose_action(_llm("198.51.100.1"))
    assert other is not None and other.status is ActionStatus.ACTIVE
    rl = await propose_action(_llm("203.0.113.77", ActionType.RATE_LIMIT))  # another type is not suppressed
    assert rl is not None and rl.status is ActionStatus.ACTIVE


async def test_manual_only_does_not_drop_but_suppress_wins(spy, configure) -> None:  # type: ignore[no-untyped-def]
    configure(auto_approve_enabled=True, auto_approve_actions=["block_ip"])
    await _insert(IP, mode="manual_only", expires_delta=timedelta(hours=1))
    proposed = await propose_action(_llm())
    assert proposed is not None and proposed.status is ActionStatus.PROPOSED
    await _insert(IP, mode="suppress", expires_delta=timedelta(hours=1))
    assert await propose_action(_llm()) is None


async def test_human_proposal_under_suppression_is_created_but_never_auto_approved(spy, configure) -> None:  # type: ignore[no-untyped-def]
    configure(auto_approve_enabled=True, auto_approve_actions=["block_ip"])
    await _insert(IP, expires_delta=timedelta(hours=1))
    user = ActionProposal(
        action_type=ActionType.BLOCK_IP, target=IP, reason="I checked it", proposed_by=ActionProposer.USER
    )
    action = await create_proposal(user, actor="carol")
    assert action.status is ActionStatus.PROPOSED and action.result["suppression"]["mode"] == "suppress"
    assert spy.applied == []


async def test_api_reject_suppress_list_lift(client: httpx.AsyncClient, make_user, spy) -> None:  # type: ignore[no-untyped-def]
    analyst = await make_user("analyst")
    viewer = await make_user("viewer")
    created = await client.post(
        "/api/v1/response/actions",
        json={"action_type": "block_ip", "target": IP, "reason": "x"},
        headers=analyst,
    )
    action_id = created.json()["id"]
    bad = await client.post(
        f"/api/v1/response/actions/{action_id}/reject", json={"suppress_hours": 0}, headers=analyst
    )
    assert bad.status_code == 422
    r = await client.post(
        f"/api/v1/response/actions/{action_id}/reject",
        json={"reason": "shared NAT", "suppress_permanent": True},
        headers=analyst,
    )
    assert r.status_code == 200, r.text
    listed = await client.get("/api/v1/response/suppressions", headers=viewer)
    assert listed.status_code == 200
    items = listed.json()["items"]
    assert len(items) == 1 and items[0]["mode"] == "suppress" and items[0]["expires_at"] is None
    assert (
        items[0]["active"]
        and items[0]["source_action_id"] == action_id
        and items[0]["reason"] == "shared NAT"
    )
    sid = items[0]["id"]
    assert (await client.post(f"/api/v1/response/suppressions/{sid}/lift", headers=viewer)).status_code == 403
    lifted = await client.post(f"/api/v1/response/suppressions/{sid}/lift", headers=analyst)
    assert lifted.status_code == 200 and lifted.json()["active"] is False
    again = await client.post(f"/api/v1/response/suppressions/{sid}/lift", headers=analyst)
    assert again.status_code == 409
    assert (await client.get("/api/v1/response/suppressions", headers=viewer)).json()["items"] == []
    history = await client.get("/api/v1/response/suppressions?active=false", headers=viewer)
    assert len(history.json()["items"]) == 1
    missing = await client.post("/api/v1/response/suppressions/nope/lift", headers=analyst)
    assert missing.status_code == 404


async def test_api_create_suppression_validates_target(client: httpx.AsyncClient, make_user) -> None:  # type: ignore[no-untyped-def]
    analyst = await make_user("analyst")
    viewer = await make_user("viewer")
    body = {"action_type": "block_ip", "target": "198.51.100.7", "suppress_hours": 48, "reason": "monitor"}
    assert (await client.post("/api/v1/response/suppressions", json=body, headers=viewer)).status_code == 403
    ok = await client.post("/api/v1/response/suppressions", json=body, headers=analyst)
    assert ok.status_code == 200, ok.text
    assert ok.json()["mode"] == "suppress" and ok.json()["expires_at"]
    bad = await client.post(
        "/api/v1/response/suppressions",
        json={"action_type": "block_ip", "target": "a b; rm -rf"},
        headers=analyst,
    )
    assert bad.status_code == 422
