"""Workflow: propose (dedup) -> approve -> active (TTL) -> expire / revert, reject, failures, audit, bus."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import func, select

from tokiwa import runtime
from tokiwa.bus import bus
from tokiwa.db.models.core import AuditRow
from tokiwa.db.models.response import ResponseActionRow
from tokiwa.db.session import session_scope
from tokiwa.respond import service
from tokiwa.respond.service import (
    ActionExecutionError,
    ActionStateError,
    ActionValidationError,
    approve_action,
    create_proposal,
    expire_due_actions,
    get_action,
    list_actions,
    propose_action,
    reject_action,
    revert_action,
)
from tokiwa.schemas.response import ActionProposal, ActionProposer, ActionStatus
from tokiwa.schemas.triage import ActionType
from tokiwa.util import utcnow

pytestmark = pytest.mark.usefixtures("db")


def _p(action_type: ActionType = ActionType.BLOCK_IP, target: str = "203.0.113.9", **kw) -> ActionProposal:  # type: ignore[no-untyped-def]
    return ActionProposal(
        action_type=action_type, target=target, reason=kw.pop("reason", "recon burst"), **kw
    )


async def _audit_actions(target: str) -> list[str]:
    async with session_scope() as s:
        rows = (
            (await s.execute(select(AuditRow).where(AuditRow.target == target).order_by(AuditRow.created_at)))
            .scalars()
            .all()
        )
        return [r.action for r in rows]


async def test_propose_creates_proposed_action_and_publishes(spy) -> None:  # type: ignore[no-untyped-def]
    q = bus.listen()
    action = await propose_action(_p(target="203.0.113.9/32", proposed_by=ActionProposer.LLM))
    assert action is not None
    assert action.status is ActionStatus.PROPOSED
    assert action.target == "203.0.113.9"
    assert action.ttl_minutes == 60 and action.reversible
    assert action.proposed_by is ActionProposer.LLM
    assert action.approved_by is None and action.executed_at is None
    topic, payload = q.get_nowait()
    assert topic == "action.proposed" and payload.id == action.id
    assert spy.applied == []
    assert await _audit_actions(action.id) == ["response.propose"]
    bus.unlisten(q)


async def test_duplicate_proposals_merge_reasons(spy) -> None:  # type: ignore[no-untyped-def]
    first = await propose_action(_p(reason="burst of 404s"))
    second = await propose_action(
        _p(target="203.0.113.9/32", reason="AI canary followed", incident_id="inc1")
    )
    third = await propose_action(_p(reason="burst of 404s"))
    assert first and second and third
    assert first.id == second.id == third.id
    assert second.reason == "burst of 404s\n---\nAI canary followed"
    assert third.reason == second.reason  # identical reason is not appended twice
    assert second.incident_id == "inc1"
    async with session_scope() as s:
        assert (await s.execute(select(func.count()).select_from(ResponseActionRow))).scalar_one() == 1
    # A different type for the same target is a separate proposal.
    other = await propose_action(_p(action_type=ActionType.TARPIT))
    assert other is not None and other.id != first.id


async def test_dedup_also_covers_active_and_reopens_after_expiry(spy) -> None:  # type: ignore[no-untyped-def]
    a = await propose_action(_p())
    assert a is not None
    active = await approve_action(a.id, actor="alice")
    assert active.status is ActionStatus.ACTIVE
    again = await propose_action(_p(reason="still scanning"))
    assert again is not None and again.id == a.id and again.status is ActionStatus.ACTIVE
    await expire_due_actions(now=utcnow() + timedelta(hours=2))
    fresh = await propose_action(_p(reason="came back"))
    assert fresh is not None and fresh.id != a.id and fresh.status is ActionStatus.PROPOSED


async def test_validation_failure_returns_none_and_is_audited(spy) -> None:  # type: ignore[no-untyped-def]
    assert await propose_action(_p(target="127.0.0.1")) is None
    assert await propose_action(_p(target="not-an-ip")) is None
    with pytest.raises(ActionValidationError):
        await create_proposal(_p(target="0.0.0.0/0"))
    async with session_scope() as s:
        assert (await s.execute(select(func.count()).select_from(ResponseActionRow))).scalar_one() == 0
        rejected = (
            (await s.execute(select(AuditRow).where(AuditRow.action == "response.propose_rejected")))
            .scalars()
            .all()
        )
    assert len(rejected) == 2


async def test_approve_executes_and_sets_ttl(spy) -> None:  # type: ignore[no-untyped-def]
    a = await propose_action(_p(ttl_minutes=30))
    assert a is not None
    done = await approve_action(a.id, actor="alice")
    assert done.status is ActionStatus.ACTIVE
    assert done.approved_by == "alice" and done.approved_at is not None
    assert done.executed_at is not None and done.expires_at is not None
    assert done.expires_at - done.executed_at == timedelta(minutes=30)
    assert done.result["spy"] == "applied"
    [req] = spy.applied
    assert req.target == "203.0.113.9" and req.ttl_seconds == 1800
    assert not hasattr(req, "reason")  # executors never see free text
    assert await _audit_actions(a.id) == ["response.propose", "response.approve", "response.execute"]


async def test_executor_failure_marks_failed(spy) -> None:  # type: ignore[no-untyped-def]
    spy.fail_apply = "upstream said no"
    a = await propose_action(_p())
    assert a is not None
    done = await approve_action(a.id, actor="alice")
    assert done.status is ActionStatus.FAILED
    assert done.result["error"] == "upstream said no"
    assert done.expires_at is None
    assert "response.execute_failed" in await _audit_actions(a.id)


async def test_revalidation_before_execution(spy, configure) -> None:  # type: ignore[no-untyped-def]
    a = await propose_action(_p(target="198.51.100.20"))
    assert a is not None
    configure(protected_cidrs=["127.0.0.0/8", "198.51.100.0/24"])  # config changed after proposal
    done = await approve_action(a.id, actor="alice")
    assert done.status is ActionStatus.FAILED
    assert "protected" in done.result["error"]
    assert spy.applied == []


async def test_reject(spy) -> None:  # type: ignore[no-untyped-def]
    a = await propose_action(_p())
    assert a is not None
    rejected = await reject_action(a.id, actor="bob", reason="known partner scanner")
    assert rejected.status is ActionStatus.REJECTED
    assert rejected.result["rejection_reason"] == "known partner scanner"
    with pytest.raises(ActionStateError):
        await approve_action(a.id, actor="bob")
    with pytest.raises(ActionStateError):
        await reject_action(a.id, actor="bob")
    assert spy.applied == []


async def test_revert_active(spy) -> None:  # type: ignore[no-untyped-def]
    a = await propose_action(_p())
    assert a is not None
    with pytest.raises(ActionStateError):
        await revert_action(a.id, actor="alice")  # not active yet
    await approve_action(a.id, actor="alice")
    reverted = await revert_action(a.id, actor="carol")
    assert reverted.status is ActionStatus.REVERTED and reverted.reverted_at is not None
    assert reverted.result["revert"] == {"spy": "reverted"}
    assert len(spy.reverted) == 1
    with pytest.raises(ActionStateError):
        await revert_action(a.id, actor="carol")


async def test_revert_failure_keeps_action_active(spy) -> None:  # type: ignore[no-untyped-def]
    a = await propose_action(_p(action_type=ActionType.NFTABLES_BLOCK))
    assert a is not None
    await approve_action(a.id, actor="alice")
    spy.fail_revert = "nft exited with 1"
    with pytest.raises(ActionExecutionError, match="nft exited"):
        await revert_action(a.id, actor="alice")
    current = await get_action(a.id)
    assert current.status is ActionStatus.ACTIVE and current.reverted_at is None
    assert current.result["revert_error"] == "nft exited with 1"


async def test_one_shot_actions_complete_immediately(spy) -> None:  # type: ignore[no-untyped-def]
    a = await propose_action(_p(action_type=ActionType.NOTIFY, target="incident-42", ttl_minutes=5))
    assert a is not None and a.ttl_minutes is None and not a.reversible
    done = await approve_action(a.id, actor="alice")
    assert done.status is ActionStatus.EXPIRED and done.result["one_shot"] is True
    with pytest.raises(ActionStateError, match="cannot be reverted"):
        await revert_action(a.id, actor="alice")


async def test_expiry_reverts_only_due_actions(spy) -> None:  # type: ignore[no-untyped-def]
    short = await propose_action(_p(target="203.0.113.1", ttl_minutes=5))
    long = await propose_action(_p(target="203.0.113.2", ttl_minutes=120))
    pending = await propose_action(_p(target="203.0.113.3", ttl_minutes=1))
    assert short and long and pending
    await approve_action(short.id, actor="alice")
    await approve_action(long.id, actor="alice")
    assert await expire_due_actions() == 0
    count = await expire_due_actions(now=utcnow() + timedelta(minutes=10))
    assert count == 1
    assert (await get_action(short.id)).status is ActionStatus.EXPIRED
    assert (await get_action(long.id)).status is ActionStatus.ACTIVE
    assert (await get_action(pending.id)).status is ActionStatus.PROPOSED  # never executed by expiry
    assert [r.action_id for r in spy.reverted] == [short.id]
    assert [r.action_id for r in spy.applied] == [short.id, long.id]
    assert "response.expire" in await _audit_actions(short.id)


async def test_expiry_marks_expired_even_if_revert_fails(spy) -> None:  # type: ignore[no-untyped-def]
    a = await propose_action(_p(ttl_minutes=1))
    assert a is not None
    await approve_action(a.id, actor="alice")
    spy.fail_revert = "temporary"
    assert await expire_due_actions(now=utcnow() + timedelta(minutes=5)) == 1
    current = await get_action(a.id)
    assert current.status is ActionStatus.EXPIRED and current.result["revert_error"] == "temporary"


def test_expiry_job_registered() -> None:
    import tokiwa.respond.expiry  # noqa: F401

    job = runtime.jobs()["response.expiry"]
    assert job.interval(None) == 30  # type: ignore[arg-type]


async def test_list_actions_filters(spy) -> None:  # type: ignore[no-untyped-def]
    a = await propose_action(_p(target="203.0.113.1", incident_id="incA"))
    b = await propose_action(_p(target="203.0.113.2"))
    assert a and b
    await approve_action(b.id, actor="alice")
    page = await list_actions()
    assert page.total == 2 and [x.id for x in page.items] == [b.id, a.id]  # newest first
    assert [x.id for x in (await list_actions(status=ActionStatus.ACTIVE)).items] == [b.id]
    assert [x.id for x in (await list_actions(incident_id="incA")).items] == [a.id]
    assert (await list_actions(limit=1, offset=1)).items[0].id == a.id


async def test_startup_recovery_fails_interrupted_without_executing(spy) -> None:  # type: ignore[no-untyped-def]
    from sqlalchemy import update

    a = await propose_action(_p())
    assert a is not None
    async with session_scope() as s:  # simulate a crash between approval and execution
        await s.execute(
            update(ResponseActionRow)
            .where(ResponseActionRow.id == a.id)
            .values(status="approved", approved_by="alice", approved_at=utcnow())
        )
    await service._fail_interrupted_actions()
    current = await get_action(a.id)
    assert current.status is ActionStatus.FAILED and "interrupted" in current.result["error"]
    assert spy.applied == []
