"""Suppressions: remember what a human rejected or reverted (audit #63).

Without this, the dedup in ``create_proposal`` only looks at open rows, so a rejected / reverted (type, target)
was proposed again by the next alert's triage, and with auto-approve on, a reverted false-positive block was
re-applied immediately (flapping that only switching auto-approve off could stop).

Two modes (``tokiwa.schemas.suppressions.SuppressionMode``):

- ``suppress`` (chosen by the analyst on reject / revert, or created via the API, N hours or permanent):
  proposals from the rule engine / LLM / policy are dropped (no row, no bus event, so no approval-request
  notification either; ``response.propose_suppressed`` in the audit log). A proposal a human makes through the
  API is still created, but never auto-approved.
- ``manual_only`` (written on *every* human reject / revert for ``response.auto_approve_cooldown_minutes``):
  proposals are created as usual but never auto-approved.

Matching is by action type and target; for IP / CIDR targets any overlap counts (a suppressed NAT address is
not re-blocked through a broader CIDR, and a suppressed /24 covers its hosts). Expired or lifted rows are
ignored. Nothing here executes anything.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.audit import record_audit
from tokiwa.config import ResponseSettings
from tokiwa.db.models.response import ResponseActionRow
from tokiwa.db.models.response_suppression import ResponseSuppressionRow
from tokiwa.db.session import session_scope
from tokiwa.respond.validate import ActionValidationError, format_network, parse_network
from tokiwa.schemas.common import Page
from tokiwa.schemas.response import ActionProposer
from tokiwa.schemas.suppressions import (
    ResponseSuppression,
    ResponseSuppressionIn,
    SuppressionMode,
    SuppressOptions,
)
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

MAX_REASON_CHARS = 2000
_SAFE_TARGET = re.compile(r"^[A-Za-z0-9/][A-Za-z0-9._:/@~-]{0,254}$")

__all__ = [
    "ActionSuppressed",
    "SuppressionNotFound",
    "SuppressionStateError",
    "create_suppression",
    "drops",
    "find_suppression",
    "is_active",
    "lift_suppression",
    "list_suppressions",
    "note_dropped",
    "record_decision",
]


class SuppressionNotFound(LookupError):
    pass


class SuppressionStateError(RuntimeError):
    """E.g. lifting a row that is already lifted (HTTP 409)."""


class ActionSuppressed(Exception):
    """An automated proposal matched a ``suppress`` row and was dropped (no row was created)."""

    def __init__(self, suppression_id: str, action_type: str, target: str) -> None:
        super().__init__(f"{action_type} {target} is suppressed ({suppression_id})")
        self.suppression_id = suppression_id
        self.action_type = action_type
        self.target = target


def is_active(row: ResponseSuppressionRow, now: datetime) -> bool:
    return row.lifted_at is None and (row.expires_at is None or row.expires_at > now)


def _targets_match(a: str, b: str) -> bool:
    if a == b:
        return True
    try:
        na = ipaddress.ip_network(a, strict=False)
        nb = ipaddress.ip_network(b, strict=False)
    except ValueError:
        return False
    return na.version == nb.version and na.overlaps(nb)


async def find_suppression(
    session: AsyncSession, action_type: str, target: str, now: datetime
) -> ResponseSuppressionRow | None:
    """The strongest active row matching (type, target): ``suppress`` wins over ``manual_only``."""
    rows = (
        (
            await session.execute(
                select(ResponseSuppressionRow)
                .where(
                    ResponseSuppressionRow.action_type == action_type,
                    ResponseSuppressionRow.lifted_at.is_(None),
                    or_(ResponseSuppressionRow.expires_at.is_(None), ResponseSuppressionRow.expires_at > now),
                )
                .order_by(ResponseSuppressionRow.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    matches = [r for r in rows if _targets_match(r.target, target)]
    if not matches:
        return None
    matches.sort(key=lambda r: r.mode != SuppressionMode.SUPPRESS.value)  # stable: newest first per mode
    return matches[0]


def drops(row: ResponseSuppressionRow, proposer: ActionProposer) -> bool:
    """True when the proposal must not be stored at all (automated proposer + ``suppress`` row)."""
    return row.mode == SuppressionMode.SUPPRESS.value and proposer is not ActionProposer.USER


async def note_dropped(exc: ActionSuppressed, *, actor: str) -> None:
    """Count the hit and audit a dropped proposal (own transaction: the proposal's one was rolled back)."""
    now = utcnow()
    async with session_scope() as session:
        row = await session.get(ResponseSuppressionRow, exc.suppression_id)
        if row is not None:
            row.hits = (row.hits or 0) + 1
            row.last_hit_at = now
        await record_audit(
            actor,
            "response.propose_suppressed",
            target=exc.target[:256],
            details={"action_type": exc.action_type, "suppression_id": exc.suppression_id},
            session=session,
        )


async def record_decision(
    session: AsyncSession,
    action: ResponseActionRow,
    *,
    actor: str,
    decision: str,
    options: SuppressOptions | None,
    reason: str | None,
    now: datetime,
    settings: ResponseSettings,
) -> ResponseSuppressionRow | None:
    """After a human reject / revert: ``suppress`` when asked, otherwise the ``manual_only`` cooldown."""
    if options is not None and options.requested:
        mode = SuppressionMode.SUPPRESS
        expires: datetime | None = (
            None
            if options.suppress_permanent or options.suppress_hours is None
            else now + timedelta(hours=options.suppress_hours)
        )
    else:
        minutes = settings.auto_approve_cooldown_minutes
        if minutes <= 0:
            return None
        mode = SuppressionMode.MANUAL_ONLY
        expires = now + timedelta(minutes=minutes)
    row = ResponseSuppressionRow(
        id=new_id(),
        created_at=now,
        updated_at=now,
        action_type=action.action_type,
        target=action.target,
        mode=mode.value,
        reason=(reason or "").strip()[:MAX_REASON_CHARS],
        created_by=actor[:64],
        source_action_id=action.id,
        expires_at=expires,
        hits=0,
    )
    session.add(row)
    await record_audit(
        actor,
        "response.suppress",
        target=row.id,
        details={
            "action_type": action.action_type,
            "target": action.target,
            "mode": mode.value,
            "expires_at": expires.isoformat() if expires else None,
            "after": decision,
            "source_action_id": action.id,
        },
        session=session,
    )
    return row


# ---------------------------------------------------------------- API helpers


def _schema(row: ResponseSuppressionRow, now: datetime) -> ResponseSuppression:
    return ResponseSuppression.model_validate(row).model_copy(update={"active": is_active(row, now)})


def normalize_target(target: str) -> str:
    """Same shape as stored action targets: IP / CIDR normalized, otherwise a path or identifier."""
    t = target.strip()
    try:
        return format_network(parse_network(t))
    except ActionValidationError:
        pass
    if not _SAFE_TARGET.match(t) or ".." in t:
        raise ActionValidationError("target must be an IP/CIDR, an absolute path or a simple identifier")
    return t


async def create_suppression(body: ResponseSuppressionIn, *, actor: str) -> ResponseSuppression:
    now = utcnow()
    target = normalize_target(body.target)
    expires = (
        None
        if body.suppress_permanent or body.suppress_hours is None
        else now + timedelta(hours=body.suppress_hours)
    )
    async with session_scope() as session:
        row = ResponseSuppressionRow(
            id=new_id(),
            created_at=now,
            updated_at=now,
            action_type=body.action_type.value,
            target=target,
            mode=SuppressionMode.SUPPRESS.value,
            reason=body.reason.strip()[:MAX_REASON_CHARS],
            created_by=actor[:64],
            expires_at=expires,
            hits=0,
        )
        session.add(row)
        await record_audit(
            actor,
            "response.suppress",
            target=row.id,
            details={
                "action_type": row.action_type,
                "target": target,
                "mode": row.mode,
                "expires_at": expires.isoformat() if expires else None,
                "after": "manual",
            },
            session=session,
        )
        return _schema(row, now)


async def lift_suppression(suppression_id: str, *, actor: str) -> ResponseSuppression:
    now = utcnow()
    async with session_scope() as session:
        row = await session.get(ResponseSuppressionRow, suppression_id)
        if row is None:
            raise SuppressionNotFound(suppression_id)
        if row.lifted_at is not None:
            raise SuppressionStateError("suppression is already lifted")
        row.lifted_at = now
        row.lifted_by = actor[:64]
        row.updated_at = now
        await record_audit(
            actor,
            "response.suppression_lift",
            target=row.id,
            details={"action_type": row.action_type, "target": row.target, "mode": row.mode},
            session=session,
        )
        return _schema(row, now)


async def list_suppressions(
    *, active_only: bool = True, limit: int = 100, offset: int = 0
) -> Page[ResponseSuppression]:
    now = utcnow()
    conds = []
    if active_only:
        conds = [
            ResponseSuppressionRow.lifted_at.is_(None),
            or_(ResponseSuppressionRow.expires_at.is_(None), ResponseSuppressionRow.expires_at > now),
        ]
    async with session_scope() as session:
        total = int(
            (
                await session.execute(select(func.count()).select_from(ResponseSuppressionRow).where(*conds))
            ).scalar_one()
        )
        rows = (
            (
                await session.execute(
                    select(ResponseSuppressionRow)
                    .where(*conds)
                    .order_by(ResponseSuppressionRow.created_at.desc(), ResponseSuppressionRow.id.desc())
                    .limit(limit)
                    .offset(offset)
                )
            )
            .scalars()
            .all()
        )
        return Page[ResponseSuppression](
            items=[_schema(r, now) for r in rows], total=total, limit=limit, offset=offset
        )
