"""Audit #64: safety settings changed after approval apply to already-active actions, and every Gate policy
entry carries its expiry so a Gate that lost the server does not enforce it past the TTL."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from tokiwa.db.models.core import AuditRow
from tokiwa.db.models.response import ResponseActionRow
from tokiwa.db.session import session_scope
from tokiwa.gate.policy import PolicyManager
from tokiwa.respond.policy import build_gate_policy
from tokiwa.respond.service import approve_action, create_proposal, revoke_disallowed_actions
from tokiwa.schemas.response import ActionProposal, ActionStatus, GatePolicy
from tokiwa.schemas.triage import ActionType
from tokiwa.util import new_id, utcnow

PROTECT_LB = ["127.0.0.0/8", "::1/128", "198.51.100.0/24"]


async def _row(action_type: str, target: str, *, expires_at: datetime | None, **kw: Any) -> str:
    now = utcnow()
    rid = new_id()
    async with session_scope() as s:
        s.add(
            ResponseActionRow(
                id=rid,
                created_at=now,
                updated_at=now,
                action_type=action_type,
                target=target,
                params=kw.pop("params", {}),
                reason="",
                proposed_by="user",
                status="active",
                reversible=True,
                ttl_minutes=60,
                expires_at=expires_at,
                result={},
            )
        )
    return rid


@pytest.mark.usefixtures("db")
async def test_policy_drops_rows_refused_by_current_settings(configure) -> None:  # type: ignore[no-untyped-def]
    later = utcnow() + timedelta(hours=1)
    await _row("block_ip", "198.51.100.7", expires_at=later)
    await _row("rate_limit", "198.51.100.8", expires_at=later, params={"requests_per_minute": 5})
    await _row("block_ip", "203.0.113.7", expires_at=later)
    before = await build_gate_policy()
    assert before.blocked == ["198.51.100.7", "203.0.113.7"] and before.rate_limited == {"198.51.100.8": 5}
    configure(protected_cidrs=PROTECT_LB)  # e.g. the upstream LB range, added after the false positive
    after = await build_gate_policy()
    assert after.blocked == ["203.0.113.7"] and after.rate_limited == {}
    assert after.version != before.version
    configure(protected_cidrs=["127.0.0.0/8"], min_prefix_v4=32)  # broader than allowed now
    await _row("block_ip", "203.0.112.0/24", expires_at=later)
    assert (await build_gate_policy()).blocked == ["198.51.100.7", "203.0.113.7"]


@pytest.mark.usefixtures("db")
async def test_revoke_reverts_audits_and_runs_the_executor(spy, configure) -> None:  # type: ignore[no-untyped-def]
    ids = []
    for t, target in ((ActionType.BLOCK_IP, "198.51.100.7"), (ActionType.NFTABLES_BLOCK, "198.51.100.9")):
        p = await create_proposal(ActionProposal(action_type=t, target=target, reason="burst"))
        ids.append((await approve_action(p.id, actor="alice")).id)
    keep = await create_proposal(
        ActionProposal(action_type=ActionType.BLOCK_IP, target="203.0.113.7", reason="x")
    )
    await approve_action(keep.id, actor="alice")
    assert await revoke_disallowed_actions() == 0  # nothing refused yet

    configure(protected_cidrs=PROTECT_LB)
    assert await revoke_disallowed_actions() == 2
    async with session_scope() as s:
        for rid in ids:
            row = await s.get(ResponseActionRow, rid)
            assert row is not None and row.status == ActionStatus.REVERTED.value and row.reverted_at
            assert "protected network 198.51.100.0/24" in row.result["auto_reverted"]["reason"]
            assert row.result["revert"] == {"spy": "reverted"}
        kept = await s.get(ResponseActionRow, keep.id)
        assert kept is not None and kept.status == ActionStatus.ACTIVE.value
        audits = (
            (await s.execute(select(AuditRow).where(AuditRow.action == "response.auto_revert")))
            .scalars()
            .all()
        )
    assert sorted(a.target for a in audits) == sorted(ids) and {a.actor for a in audits} == {
        "system:settings"
    }
    assert sorted(r.target for r in spy.reverted) == [
        "198.51.100.7",
        "198.51.100.9",
    ]  # nft element removed too
    assert await revoke_disallowed_actions() == 0  # idempotent


async def test_gate_status_does_not_count_refused_rows(  # type: ignore[no-untyped-def]
    client: httpx.AsyncClient, make_user, configure
) -> None:
    viewer = await make_user("viewer")
    rid = await _row("block_ip", "198.51.100.7", expires_at=utcnow() + timedelta(hours=1))
    status = (await client.get("/api/v1/gate/status", headers=viewer)).json()
    assert [a["action_id"] for a in status["actions"]] == [rid]
    configure(protected_cidrs=PROTECT_LB)
    assert (await client.get("/api/v1/gate/status", headers=viewer)).json()["actions"] == []


@pytest.mark.usefixtures("db")
async def test_entries_carry_their_expiry() -> None:
    now = utcnow()
    h1, h2, h3 = (now + timedelta(hours=n) for n in (1, 2, 3))
    await _row("block_ip", "198.51.100.0/25", expires_at=h1)
    await _row("block_ip", "198.51.100.128/25", expires_at=h2)  # collapsed with the one above -> latest wins
    await _row("block_ip", "203.0.113.5", expires_at=None)  # no expiry -> absent
    await _row("rate_limit", "192.0.2.10", expires_at=h1)
    await _row("rate_limit", "192.0.2.10", expires_at=h3)
    await _row("deceive", "192.0.2.30", expires_at=h2)
    policy = await build_gate_policy(now)
    assert policy.blocked == ["198.51.100.0/24", "203.0.113.5"]
    assert policy.entry_expires_at == {
        "blocked": {"198.51.100.0/24": h2},
        "rate_limited": {"192.0.2.10": h3},
        "deceive": {"192.0.2.30": h2},
    }
    # Renewing a block (same entry, later expiry) changes the version, so the Gate picks up the new expiry.
    await _row("deceive", "192.0.2.30", expires_at=h3)
    renewed = await build_gate_policy(now)
    assert renewed.deceive == policy.deceive and renewed.version != policy.version


async def test_gate_lifts_entries_at_their_expiry_without_the_server() -> None:
    clock = [1000.0]
    # The Gate's wall clock is irrelevant: deadlines are relative to generated_at, on the monotonic clock.
    generated = datetime(2001, 1, 1, tzinfo=UTC)
    policy = GatePolicy(
        version="v1",
        generated_at=generated,
        blocked=["198.51.100.7", "203.0.113.5"],
        rate_limited={"192.0.2.10": 5},
        entry_expires_at={
            "blocked": {"198.51.100.7": generated + timedelta(seconds=60)},
            "rate_limited": {"192.0.2.10": generated + timedelta(seconds=120)},
        },
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(503))) as client:
        manager = PolicyManager(client, "http://tokiwa.test", "tkw", clock=lambda: clock[0])
        assert manager.apply(policy) is True
        clock[0] = 1059.0
        assert "198.51.100.7" in manager.current.blocked
        assert await manager.refresh() is False  # server unreachable: fail-static...
        clock[0] = 1061.0
        current = manager.current  # ...but not past the entry's expiry
        assert "198.51.100.7" not in current.blocked and "203.0.113.5" in current.blocked
        assert "192.0.2.10" in current.rate_limited and current.version == "v1"
        clock[0] = 1200.0
        assert "192.0.2.10" not in manager.current.rate_limited
        assert manager.stats()["expired_locally"] == 2
        assert manager.apply(policy) is False  # same version from the server: nothing re-added


async def test_gate_drops_already_expired_entries_on_install() -> None:
    generated = datetime(2001, 1, 1, tzinfo=UTC)
    policy = GatePolicy(
        version="v2",
        generated_at=generated,
        blocked=["198.51.100.7"],
        entry_expires_at={"blocked": {"198.51.100.7": generated - timedelta(seconds=1)}},
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(503))) as client:
        manager = PolicyManager(client, "http://tokiwa.test", "tkw", clock=lambda: 5.0)
        manager.apply(policy)
        assert "198.51.100.7" not in manager.current.blocked
