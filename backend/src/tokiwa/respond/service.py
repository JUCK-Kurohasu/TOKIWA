"""Response action service. OWNER: respond module.

Public API used by other modules (keep signatures stable):

- ``propose_action(proposal) -> ResponseAction | None``  create a proposal (deduplicated); may auto-approve
  only when policy allows (``response.auto_approve_enabled`` + type allow-list). Returns None if rejected by
  validation (e.g. protected CIDR, invalid target).

Lifecycle::

    proposed --approve--> approved --executor ok--> active --(expires_at)--> expired
        |                     |                       \\--revert--> reverted
        \\--reject--> rejected  \\--executor error--> failed
    (one-shot notify/webhook: approved --executor ok--> expired, result.one_shot = true)

Safety invariant (FR-12): :func:`_execute` is the only caller of ``Executor.apply`` and it refuses to run
unless the stored row is ``approved`` with ``approved_by`` / ``approved_at`` set. The only code that moves a
row to ``approved`` is :func:`approve_action`, reached from a human (API, analyst role) or from
:func:`create_proposal` when :func:`tokiwa.respond.policy.auto_approve_allowed` is true
(``approved_by="policy"``). Tests in ``tests/respond/test_safety.py`` enforce this, including an AST check.
"""

from __future__ import annotations

import asyncio
import logging
import weakref
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select, update

from tokiwa.audit import record_audit
from tokiwa.bus import bus
from tokiwa.config import get_settings
from tokiwa.db.models.response import ResponseActionRow
from tokiwa.db.session import session_scope
from tokiwa.respond.executors import ExecutionRequest, ExecutorError, get_executor
from tokiwa.respond.policy import auto_approve_allowed
from tokiwa.respond.validate import (
    ONE_SHOT_ACTIONS,
    ActionValidationError,
    ValidatedAction,
    validate_action,
)
from tokiwa.runtime import on_startup
from tokiwa.schemas.common import Page
from tokiwa.schemas.response import ActionProposal, ActionStatus, ResponseAction
from tokiwa.schemas.triage import ActionType
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

POLICY_ACTOR = "policy"
EXPIRY_ACTOR = "system:expiry"
OPEN_STATUSES = (ActionStatus.PROPOSED.value, ActionStatus.APPROVED.value, ActionStatus.ACTIVE.value)
MAX_REASON_CHARS = 8000

__all__ = [
    "ActionExecutionError",
    "ActionNotFound",
    "ActionStateError",
    "ActionValidationError",
    "approve_action",
    "create_proposal",
    "expire_due_actions",
    "get_action",
    "list_actions",
    "propose_action",
    "reject_action",
    "revert_action",
]


class ActionNotFound(LookupError):
    pass


class ActionStateError(RuntimeError):
    """The requested transition is not allowed from the current status (HTTP 409)."""


class ActionExecutionError(RuntimeError):
    """An executor failed during revert (HTTP 502). The message is safe to show."""


# One lock per event loop: serializes propose (dedup check + insert) inside this process.
_locks: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = weakref.WeakKeyDictionary()


def _propose_lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    lock = _locks.get(loop)
    if lock is None:
        lock = _locks[loop] = asyncio.Lock()
    return lock


def _schema(row: ResponseActionRow) -> ResponseAction:
    return ResponseAction.model_validate(row)


def _clean_reason(reason: str) -> str:
    return reason.strip()[:MAX_REASON_CHARS]


def _append_reason(existing: str, new: str) -> str:
    if not new or new in existing:
        return existing
    combined = f"{existing}\n---\n{new}" if existing else new
    return combined[:MAX_REASON_CHARS]


# ---------------------------------------------------------------- propose


async def propose_action(proposal: ActionProposal) -> ResponseAction | None:
    """Create (or merge into) a proposal. Returns None when validation rejects it."""
    try:
        return await create_proposal(proposal)
    except ActionValidationError as exc:
        log.info("response proposal rejected (%s %r): %s", proposal.action_type, proposal.target, exc)
        await record_audit(
            proposal.proposed_by.value,
            "response.propose_rejected",
            target=proposal.target[:256],
            details={"action_type": proposal.action_type.value, "error": str(exc)},
        )
        return None


async def create_proposal(proposal: ActionProposal, *, actor: str | None = None) -> ResponseAction:
    """Validate and store a proposal. Raises :class:`ActionValidationError` (used by the API for 422)."""
    settings = get_settings().response
    v = validate_action(
        proposal.action_type,
        proposal.target,
        proposal.params,
        proposal.ttl_minutes,
        incident_id=proposal.incident_id,
        alert_id=proposal.alert_id,
        settings=settings,
    )
    who = actor or proposal.proposed_by.value
    reason = _clean_reason(proposal.reason)
    now = utcnow()
    async with _propose_lock(), session_scope() as session:
        existing = (
            await session.execute(
                select(ResponseActionRow)
                .where(
                    ResponseActionRow.action_type == v.action_type.value,
                    ResponseActionRow.target == v.target,
                    ResponseActionRow.status.in_(OPEN_STATUSES),
                )
                .order_by(ResponseActionRow.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if existing is not None:
            existing.reason = _append_reason(existing.reason, reason)
            existing.incident_id = existing.incident_id or v.incident_id
            existing.alert_id = existing.alert_id or v.alert_id
            existing.updated_at = now
            await record_audit(
                who,
                "response.propose_duplicate",
                target=existing.id,
                details={"action_type": v.action_type.value, "target": v.target},
                session=session,
            )
            merged = _schema(existing)
            created = None
        else:
            row = ResponseActionRow(
                id=new_id(),
                created_at=now,
                updated_at=now,
                action_type=v.action_type.value,
                target=v.target,
                params=dict(v.params),
                reason=reason,
                proposed_by=proposal.proposed_by.value,
                incident_id=v.incident_id,
                alert_id=v.alert_id,
                status=ActionStatus.PROPOSED.value,
                reversible=v.reversible,
                ttl_minutes=v.ttl_minutes,
                result={"validation_notes": list(v.notes)} if v.notes else {},
            )
            session.add(row)
            await record_audit(
                who,
                "response.propose",
                target=row.id,
                details={
                    "action_type": v.action_type.value,
                    "target": v.target,
                    "proposed_by": proposal.proposed_by.value,
                    "ttl_minutes": v.ttl_minutes,
                },
                session=session,
            )
            created = _schema(row)
            merged = None
    if created is None:
        assert merged is not None
        await bus.publish("action.updated", merged)
        return merged
    await bus.publish("action.proposed", created)
    if auto_approve_allowed(v.action_type, settings):
        log.info("auto-approving %s %s by policy", v.action_type.value, v.target)
        return await approve_action(created.id, actor=POLICY_ACTOR)
    return created


# ---------------------------------------------------------------- approve / execute


async def approve_action(action_id: str, *, actor: str) -> ResponseAction:
    """Record the approval (atomically, only from ``proposed``), then execute."""
    now = utcnow()
    async with session_scope() as session:
        res = await session.execute(
            update(ResponseActionRow)
            .where(ResponseActionRow.id == action_id, ResponseActionRow.status == ActionStatus.PROPOSED.value)
            .values(
                status=ActionStatus.APPROVED.value,
                approved_by=actor[:64],
                approved_at=now,
                updated_at=now,
            )
            .execution_options(synchronize_session=False)
        )
        if res.rowcount != 1:  # type: ignore[attr-defined]
            row = await session.get(ResponseActionRow, action_id)
            if row is None:
                raise ActionNotFound(action_id)
            raise ActionStateError(f"action is {row.status}; only proposed actions can be approved")
        await record_audit(actor, "response.approve", target=action_id, session=session)
        row = await session.get(ResponseActionRow, action_id, populate_existing=True)
        assert row is not None
        approved = _schema(row)
    await bus.publish("action.updated", approved)
    return await _execute(action_id)


@dataclass(frozen=True)
class _Snapshot:
    """Plain copy of the stored fields an executor request is built from (no live ORM object)."""

    id: str
    action_type: str
    target: str
    params: dict[str, Any]
    ttl_minutes: int | None
    incident_id: str | None
    alert_id: str | None
    result: dict[str, Any]

    @classmethod
    def of(cls, row: ResponseActionRow) -> _Snapshot:
        return cls(
            id=row.id,
            action_type=row.action_type,
            target=row.target,
            params=dict(row.params or {}),
            ttl_minutes=row.ttl_minutes,
            incident_id=row.incident_id,
            alert_id=row.alert_id,
            result=dict(row.result or {}),
        )


def _request(snap: _Snapshot, v: ValidatedAction | None = None) -> ExecutionRequest:
    """Executor input. For apply() it comes from a fresh validation; revert() uses the stored (already
    validated) values - removing enforcement is always safe."""
    ttl = v.ttl_minutes if v is not None else snap.ttl_minutes
    return ExecutionRequest(
        action_id=snap.id,
        action_type=v.action_type if v is not None else ActionType(snap.action_type),
        target=v.target if v is not None else snap.target,
        params=dict(v.params) if v is not None else dict(snap.params),
        ttl_seconds=ttl * 60 if ttl else None,
        incident_id=snap.incident_id,
        alert_id=snap.alert_id,
        state=dict(snap.result),
    )


async def _execute(action_id: str) -> ResponseAction:
    """Run the executor for an APPROVED action. The single call site of ``Executor.apply``."""
    async with session_scope() as session:
        row = await session.get(ResponseActionRow, action_id)
        if row is None:
            raise ActionNotFound(action_id)
        if row.status != ActionStatus.APPROVED.value or not row.approved_by or row.approved_at is None:
            raise ActionStateError("refusing to execute an action that has not been approved")
        snapshot = _Snapshot.of(row)

    outcome: dict[str, Any] = {}
    error: str | None = None
    v: ValidatedAction | None = None
    try:
        # Re-validate under the *current* config (e.g. protected CIDRs added since the proposal).
        v = validate_action(
            snapshot.action_type,
            snapshot.target,
            snapshot.params,
            snapshot.ttl_minutes,
            incident_id=snapshot.incident_id,
            alert_id=snapshot.alert_id,
        )
        outcome = await get_executor(v.action_type).apply(_request(snapshot, v))
    except (ActionValidationError, ExecutorError) as exc:
        error = str(exc)
    except Exception as exc:
        log.exception("executor for action %s crashed", action_id)
        error = f"executor error: {type(exc).__name__}"

    now = utcnow()
    async with session_scope() as session:
        row = await session.get(ResponseActionRow, action_id)
        assert row is not None
        result = dict(row.result or {})
        if error is not None or v is None:
            row.status = ActionStatus.FAILED.value
            result["error"] = error
            audit_action = "response.execute_failed"
        else:
            result.update(outcome)
            row.executed_at = now
            if v.action_type in ONE_SHOT_ACTIONS:
                row.status = ActionStatus.EXPIRED.value
                result["one_shot"] = True
            else:
                row.status = ActionStatus.ACTIVE.value
                row.expires_at = now + timedelta(minutes=v.ttl_minutes) if v.ttl_minutes else None
            audit_action = "response.execute"
        row.result = result
        row.updated_at = now
        await record_audit(
            row.approved_by or "unknown",
            audit_action,
            target=row.id,
            details={"action_type": row.action_type, "target": row.target, "error": error},
            session=session,
        )
        final = _schema(row)
    await bus.publish("action.updated", final)
    return final


# ---------------------------------------------------------------- reject / revert / expire


async def reject_action(action_id: str, *, actor: str, reason: str | None = None) -> ResponseAction:
    now = utcnow()
    async with session_scope() as session:
        res = await session.execute(
            update(ResponseActionRow)
            .where(ResponseActionRow.id == action_id, ResponseActionRow.status == ActionStatus.PROPOSED.value)
            .values(status=ActionStatus.REJECTED.value, updated_at=now)
            .execution_options(synchronize_session=False)
        )
        row = await session.get(ResponseActionRow, action_id, populate_existing=True)
        if row is None:
            raise ActionNotFound(action_id)
        if res.rowcount != 1:  # type: ignore[attr-defined]
            raise ActionStateError(f"action is {row.status}; only proposed actions can be rejected")
        result = dict(row.result or {})
        result["rejected_by"] = actor[:64]
        if reason:
            result["rejection_reason"] = reason.strip()[:2000]
        row.result = result
        await record_audit(
            actor, "response.reject", target=action_id, details={"reason": reason or ""}, session=session
        )
        rejected = _schema(row)
    await bus.publish("action.updated", rejected)
    return rejected


async def _set_result(action_id: str, **values: Any) -> ResponseAction:
    async with session_scope() as session:
        row = await session.get(ResponseActionRow, action_id)
        assert row is not None
        result = dict(row.result or {})
        result.update(values)
        row.result = result
        row.updated_at = utcnow()
        return _schema(row)


async def revert_action(action_id: str, *, actor: str) -> ResponseAction:
    """Undo an active action. Status flips to ``reverted`` first, so the Gate stops enforcing immediately."""
    now = utcnow()
    async with session_scope() as session:
        row = await session.get(ResponseActionRow, action_id)
        if row is None:
            raise ActionNotFound(action_id)
        if not row.reversible:
            raise ActionStateError(f"{row.action_type} actions cannot be reverted")
        res = await session.execute(
            update(ResponseActionRow)
            .where(ResponseActionRow.id == action_id, ResponseActionRow.status == ActionStatus.ACTIVE.value)
            .values(status=ActionStatus.REVERTED.value, reverted_at=now, updated_at=now)
            .execution_options(synchronize_session=False)
        )
        if res.rowcount != 1:  # type: ignore[attr-defined]
            raise ActionStateError(f"action is {row.status}; only active actions can be reverted")
        await record_audit(actor, "response.revert", target=action_id, session=session)
        row = await session.get(ResponseActionRow, action_id, populate_existing=True)
        assert row is not None
        req = _request(_Snapshot.of(row))
    try:
        outcome = await get_executor(req.action_type).revert(req)
    except Exception as exc:
        message = str(exc) if isinstance(exc, ExecutorError) else f"revert error: {type(exc).__name__}"
        if not isinstance(exc, ExecutorError):
            log.exception("revert of action %s crashed", action_id)
        async with session_scope() as session:
            await session.execute(
                update(ResponseActionRow)
                .where(
                    ResponseActionRow.id == action_id,
                    ResponseActionRow.status == ActionStatus.REVERTED.value,
                )
                .values(status=ActionStatus.ACTIVE.value, reverted_at=None)
                .execution_options(synchronize_session=False)
            )
            await record_audit(
                actor, "response.revert_failed", target=action_id, details={"error": message}, session=session
            )
        restored = await _set_result(action_id, revert_error=message)
        await bus.publish("action.updated", restored)
        raise ActionExecutionError(message) from None
    reverted = await _set_result(action_id, revert=outcome)
    await bus.publish("action.updated", reverted)
    return reverted


async def expire_due_actions(now: datetime | None = None) -> int:
    """Expire active actions past ``expires_at``: flip to ``expired`` (atomically), then revert."""
    now = now or utcnow()
    async with session_scope() as session:
        due = list(
            (
                await session.execute(
                    select(ResponseActionRow.id).where(
                        ResponseActionRow.status == ActionStatus.ACTIVE.value,
                        ResponseActionRow.expires_at.is_not(None),
                        ResponseActionRow.expires_at <= now,
                    )
                )
            )
            .scalars()
            .all()
        )
    expired = 0
    for action_id in due:
        async with session_scope() as session:
            res = await session.execute(
                update(ResponseActionRow)
                .where(
                    ResponseActionRow.id == action_id, ResponseActionRow.status == ActionStatus.ACTIVE.value
                )
                .values(status=ActionStatus.EXPIRED.value, updated_at=utcnow())
                .execution_options(synchronize_session=False)
            )
            if res.rowcount != 1:  # type: ignore[attr-defined]
                continue  # reverted concurrently
            await record_audit(EXPIRY_ACTOR, "response.expire", target=action_id, session=session)
            row = await session.get(ResponseActionRow, action_id, populate_existing=True)
            assert row is not None
            req = _request(_Snapshot.of(row))
        try:
            outcome = await get_executor(req.action_type).revert(req)
            final = await _set_result(action_id, revert=outcome)
        except Exception as exc:
            message = str(exc) if isinstance(exc, ExecutorError) else type(exc).__name__
            log.warning("revert on expiry failed for action %s: %s", action_id, message)
            final = await _set_result(action_id, revert_error=message)
        expired += 1
        await bus.publish("action.updated", final)
    return expired


# ---------------------------------------------------------------- queries


async def get_action(action_id: str) -> ResponseAction:
    async with session_scope() as session:
        row = await session.get(ResponseActionRow, action_id)
        if row is None:
            raise ActionNotFound(action_id)
        return _schema(row)


async def list_actions(
    *,
    status: ActionStatus | None = None,
    incident_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[ResponseAction]:
    conds = []
    if status is not None:
        conds.append(ResponseActionRow.status == status.value)
    if incident_id is not None:
        conds.append(ResponseActionRow.incident_id == incident_id)
    async with session_scope() as session:
        total = int(
            (
                await session.execute(select(func.count()).select_from(ResponseActionRow).where(*conds))
            ).scalar_one()
        )
        rows = (
            (
                await session.execute(
                    select(ResponseActionRow)
                    .where(*conds)
                    .order_by(ResponseActionRow.created_at.desc(), ResponseActionRow.id.desc())
                    .limit(limit)
                    .offset(offset)
                )
            )
            .scalars()
            .all()
        )
        return Page[ResponseAction](items=[_schema(r) for r in rows], total=total, limit=limit, offset=offset)


# ---------------------------------------------------------------- startup recovery


@on_startup
async def _fail_interrupted_actions() -> None:
    """An ``approved`` row with no ``executed_at`` at startup was interrupted mid-execution.

    It is marked ``failed`` (never re-executed automatically): a human re-proposes if still needed.
    """
    async with session_scope() as session:
        rows = (
            (
                await session.execute(
                    select(ResponseActionRow).where(
                        ResponseActionRow.status == ActionStatus.APPROVED.value,
                        ResponseActionRow.executed_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            row.status = ActionStatus.FAILED.value
            row.result = {**(row.result or {}), "error": "interrupted before execution completed"}
            row.updated_at = utcnow()
            await record_audit(
                "system",
                "response.execute_failed",
                target=row.id,
                details={"error": "interrupted"},
                session=session,
            )
    if rows:
        log.warning("marked %d interrupted response actions as failed", len(rows))
