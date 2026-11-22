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
from tokiwa.db.models.response_suppression import ResponseSuppressionRow
from tokiwa.db.session import session_scope
from tokiwa.respond import suppress
from tokiwa.respond.executors import ExecutionRequest, ExecutorError, get_executor
from tokiwa.respond.policy import auto_approve_allowed, refused_by_settings
from tokiwa.respond.suppress import ActionSuppressed
from tokiwa.respond.validate import (
    NETWORK_ACTIONS,
    ONE_SHOT_ACTIONS,
    ActionValidationError,
    ValidatedAction,
    validate_action,
)
from tokiwa.runtime import on_startup
from tokiwa.schemas.common import Page
from tokiwa.schemas.response import ActionProposal, ActionProposer, ActionStatus, ResponseAction
from tokiwa.schemas.suppressions import SuppressOptions
from tokiwa.schemas.triage import ActionType
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

POLICY_ACTOR = "policy"
EXPIRY_ACTOR = "system:expiry"
SETTINGS_ACTOR = "system:settings"
OPEN_STATUSES = (ActionStatus.PROPOSED.value, ActionStatus.APPROVED.value, ActionStatus.ACTIVE.value)
MAX_REASON_CHARS = 8000
# Audit #130: later proposals for an approved / active action are kept as notes, never merged into its reason.
MAX_NOTES = 50
MAX_NOTE_CHARS = 2000
MAX_AUDIT_REASON_CHARS = 1000

__all__ = [
    "ActionExecutionError",
    "ActionNotFound",
    "ActionStateError",
    "ActionSuppressed",
    "ActionValidationError",
    "approve_action",
    "create_proposal",
    "expire_due_actions",
    "get_action",
    "list_actions",
    "propose_action",
    "reject_action",
    "revert_action",
    "revoke_disallowed_actions",
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


def _add_note(
    row: ResponseActionRow, *, reason: str, proposer: str, who: str, v: ValidatedAction, now: datetime
) -> bool:
    """Record a later proposal on an approved / active row without touching what was approved (audit #130).

    Bounded (every alert from an attacker merges here): identical reasons are skipped, at most ``MAX_NOTES``
    (newest kept), each reason capped at ``MAX_NOTE_CHARS``. Returns True when a note was added.
    """
    notes = list(row.notes or [])
    text = reason[:MAX_NOTE_CHARS]
    if text and (text == row.reason or any(n.get("reason") == text for n in notes)):
        return False
    notes.append(
        {
            "at": now.isoformat(),
            "proposed_by": proposer,
            "by": who[:64],
            "reason": text,
            "incident_id": v.incident_id,
            "alert_id": v.alert_id,
        }
    )
    row.notes = notes[-MAX_NOTES:]
    return True


# ---------------------------------------------------------------- propose


async def propose_action(proposal: ActionProposal) -> ResponseAction | None:
    """Create (or merge into) a proposal. Returns None when validation rejects it or a human suppressed it."""
    try:
        return await create_proposal(proposal)
    except ActionSuppressed as exc:
        log.info("response proposal suppressed (%s %r): %s", proposal.action_type, proposal.target, exc)
        await suppress.note_dropped(exc, actor=proposal.proposed_by.value)
        return None
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
    """Validate and store a proposal. Raises :class:`ActionValidationError` (used by the API for 422).

    A matching suppression (audit #63) drops automated proposals (:class:`ActionSuppressed`, handled by
    :func:`propose_action`) and forbids auto-approval for everything else.
    """
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
        # Same transaction as the dedup below, so a concurrent reject / revert is seen by both or neither.
        hold = await suppress.find_suppression(session, v.action_type.value, v.target, now)
        if hold is not None and suppress.drops(hold, proposal.proposed_by):
            raise ActionSuppressed(hold.id, v.action_type.value, v.target)  # rolled back; audited by caller
        if hold is not None:
            hold.hits = (hold.hits or 0) + 1
            hold.last_hit_at = now
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
            noted = False
            if existing.status == ActionStatus.PROPOSED.value:
                existing.reason = _append_reason(existing.reason, reason)
                existing.incident_id = existing.incident_id or v.incident_id
                existing.alert_id = existing.alert_id or v.alert_id
            else:
                # Approved / active: what the approver saw stays as it was (audit #130).
                noted = _add_note(
                    existing, reason=reason, proposer=proposal.proposed_by.value, who=who, v=v, now=now
                )
            existing.updated_at = now
            await record_audit(
                who,
                "response.propose_duplicate",
                target=existing.id,
                details={"action_type": v.action_type.value, "target": v.target, "noted": noted},
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
                # The person behind an API proposal (rule / llm / policy have none). Audit #130.
                proposed_by_user=actor[:64]
                if actor and proposal.proposed_by is ActionProposer.USER
                else None,
                incident_id=v.incident_id,
                alert_id=v.alert_id,
                status=ActionStatus.PROPOSED.value,
                reversible=v.reversible,
                ttl_minutes=v.ttl_minutes,
                result=_initial_result(v.notes, hold),
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
    if auto_approve_allowed(v.action_type, settings) and hold is None:
        log.info("auto-approving %s %s by policy", v.action_type.value, v.target)
        return await approve_action(created.id, actor=POLICY_ACTOR)
    if hold is not None and auto_approve_allowed(v.action_type, settings):
        await record_audit(
            POLICY_ACTOR,
            "response.auto_approve_suppressed",
            target=created.id,
            details={"suppression_id": hold.id, "mode": hold.mode},
        )
    return created


def _initial_result(notes: tuple[str, ...], hold: ResponseSuppressionRow | None) -> dict[str, Any]:
    result: dict[str, Any] = {"validation_notes": list(notes)} if notes else {}
    if hold is not None:
        # Shown in the UI: why this proposal waits for a human although auto-approve may be on.
        result["suppression"] = {
            "id": hold.id,
            "mode": hold.mode,
            "expires_at": hold.expires_at.isoformat() if hold.expires_at else None,
        }
    return result


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
        row = await session.get(ResponseActionRow, action_id, populate_existing=True)
        assert row is not None
        # Audit #130: freeze what was approved (later proposals become notes, but keep a copy regardless).
        snapshot = {
            "action_type": row.action_type,
            "target": row.target,
            "params": dict(row.params or {}),
            "ttl_minutes": row.ttl_minutes,
            "reason": row.reason,
            "incident_id": row.incident_id,
            "alert_id": row.alert_id,
            "proposed_by": row.proposed_by,
            "proposed_by_user": row.proposed_by_user,
            "approved_by": actor[:64],
            "approved_at": now.isoformat(),
            "self_approval": bool(row.proposed_by_user) and row.proposed_by_user == actor[:64],
        }
        row.result = {**(row.result or {}), "approval_snapshot": snapshot}
        await record_audit(
            actor,
            "response.approve",
            target=action_id,
            details={**snapshot, "reason": (row.reason or "")[:MAX_AUDIT_REASON_CHARS]},
            session=session,
        )
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


async def reject_action(
    action_id: str, *, actor: str, reason: str | None = None, suppress_options: SuppressOptions | None = None
) -> ResponseAction:
    """Reject a proposal. Always records a suppression (audit #63): ``suppress`` when requested, otherwise
    the ``manual_only`` cooldown, so the same proposal cannot come straight back auto-approved."""
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
        held = await suppress.record_decision(
            session,
            row,
            actor=actor,
            decision="reject",
            options=suppress_options,
            reason=reason,
            now=now,
            settings=get_settings().response,
        )
        if held is not None:
            row.result = {**result, "suppression_id": held.id}
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


async def revert_action(
    action_id: str, *, actor: str, reason: str | None = None, suppress_options: SuppressOptions | None = None
) -> ResponseAction:
    """Undo an active action. Status flips to ``reverted`` first, so the Gate stops enforcing immediately.

    Records a suppression like :func:`reject_action`. It is kept even if the executor's revert fails (the
    action is then ``active`` again): it only stops re-proposals, it never enforces anything.
    """
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
        await record_audit(
            actor, "response.revert", target=action_id, details={"reason": reason or ""}, session=session
        )
        row = await session.get(ResponseActionRow, action_id, populate_existing=True)
        assert row is not None
        held = await suppress.record_decision(
            session,
            row,
            actor=actor,
            decision="revert",
            options=suppress_options,
            reason=reason,
            now=now,
            settings=get_settings().response,
        )
        extra: dict[str, Any] = {}
        if reason:
            extra["revert_reason"] = reason.strip()[:2000]
        if held is not None:
            extra["suppression_id"] = held.id
        if extra:
            row.result = {**(row.result or {}), **extra}
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


async def revoke_disallowed_actions(now: datetime | None = None) -> int:
    """Revert active network actions that the *current* settings refuse (audit #64).

    E.g. a CIDR added to ``response.protected_cidrs`` after the block was approved: ``build_gate_policy`` already
    stops serving such rows; this records the transition (``reverted``, audit ``response.auto_revert`` by
    ``system:settings``, ``result.auto_reverted``) and runs the executor's revert, which matters for
    ``nftables_block`` (the element lives in the kernel set). Run by the expiry job and at startup.
    """
    now = now or utcnow()
    settings = get_settings().response
    async with session_scope() as session:
        rows = list(
            (
                await session.execute(
                    select(ResponseActionRow).where(
                        ResponseActionRow.status == ActionStatus.ACTIVE.value,
                        ResponseActionRow.action_type.in_([t.value for t in NETWORK_ACTIONS]),
                    )
                )
            )
            .scalars()
            .all()
        )
        refused = [(row.id, error) for row, error in refused_by_settings(rows, settings)[1]]
    revoked = 0
    for action_id, error in refused:
        async with session_scope() as session:
            res = await session.execute(
                update(ResponseActionRow)
                .where(
                    ResponseActionRow.id == action_id, ResponseActionRow.status == ActionStatus.ACTIVE.value
                )
                .values(status=ActionStatus.REVERTED.value, reverted_at=now, updated_at=now)
                .execution_options(synchronize_session=False)
            )
            if res.rowcount != 1:  # type: ignore[attr-defined]
                continue  # reverted / expired concurrently
            await record_audit(
                SETTINGS_ACTOR,
                "response.auto_revert",
                target=action_id,
                details={"error": error},
                session=session,
            )
            row = await session.get(ResponseActionRow, action_id, populate_existing=True)
            assert row is not None
            row.result = {**(row.result or {}), "auto_reverted": {"reason": error, "at": now.isoformat()}}
            req = _request(_Snapshot.of(row))
        log.warning("reverted active action %s: refused by current settings (%s)", action_id, error)
        try:
            outcome = await get_executor(req.action_type).revert(req)
            final = await _set_result(action_id, revert=outcome)
        except Exception as exc:
            message = str(exc) if isinstance(exc, ExecutorError) else type(exc).__name__
            log.warning("revert of action %s (refused by settings) failed: %s", action_id, message)
            final = await _set_result(action_id, revert_error=message)
        revoked += 1
        await bus.publish("action.updated", final)
    return revoked


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


@on_startup
async def _revoke_on_startup() -> None:
    """Safety settings usually change with a restart: apply them to active actions right away (audit #64)."""
    try:
        await revoke_disallowed_actions()
    except Exception:
        log.exception("could not re-check active actions against the current settings")
