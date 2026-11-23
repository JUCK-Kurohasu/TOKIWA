"""Alert suppressions: what an analyst said was a false positive, and allowlists for authorised testing.

Audit #166: marking an alert ``false_positive`` changed nothing - the engine's dedup skips closed alerts, so the
next identical hit raised a *new* alert (new triage LLM call, new notification, incident re-link). Audit #173:
an authorised vulnerability scan or load test produced critical incidents and block proposals, and there was no
way to declare it.

Both are rows of ``alert_suppressions`` (``tokiwa.db.models.alert_suppression``) consulted by
``DetectionEngine.persist`` for every draft, before the dedup lookup (:func:`apply`):

``false_positive`` (written by ``PATCH /alerts/{id}`` with status ``false_positive``)
    Fingerprint of the marked alert: the rule, its normalised match (web.*: the matched signature ids, location and
    parameter; Sigma: the matched selections), the route key of the path and, unless widened, the source IP as a
    /32 or /128. A later draft matches when it has the same rule / route / source, a **subset** of the marked
    signatures or selections, and a severity not above the marked alert's: a new signature, another parameter or
    an escalation is new evidence and raises a normal alert. A match is counted on the marked alert (``count``,
    ``last_seen``, evidence) and on the row, and nothing is published: no triage, notification or incident.
``allowlist`` (``POST /alert-suppressions``, admin)
    A source CIDR (required), optionally one rule and one route, for a limited time. ``downgrade`` (default)
    records the alert at info severity with the tag ``allowlisted`` and never publishes it (so it is neither
    triaged, notified, correlated into an incident nor turned into a response proposal); ``suppress`` records
    nothing but the hit count.

Expired and lifted rows are ignored. Nothing here executes anything; it only decides whether an alert is raised.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.audit import record_audit
from tokiwa.config import Settings
from tokiwa.db.models.alert_suppression import AlertSuppressionRow
from tokiwa.db.models.detection import AlertRow
from tokiwa.detect.web_common import clean_path, path_key
from tokiwa.schemas.alert_suppressions import (
    AlertSuppression,
    AlertSuppressionIn,
    AlertSuppressionKind,
    AlertSuppressionMode,
)
from tokiwa.schemas.alerts import AlertDraft
from tokiwa.schemas.common import Page, Severity
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

ALLOWLISTED_TAG = "allowlisted"
MAX_REASON_CHARS = 2000
MAX_ACTIVE_ROWS = 2000  # loaded per persist() call; far above any sane number of exceptions
MAX_MATCH_ITEMS = 32
# Narrowest networks an allowlist may cover: no "allow the whole Internet" by typo.
MIN_ALLOWLIST_PREFIX = {4: 8, 6: 32}

Verdict = Literal["drop", "quiet"] | None

__all__ = [
    "ALLOWLISTED_TAG",
    "SuppressionError",
    "SuppressionNotFound",
    "SuppressionStateError",
    "apply",
    "create_from_alert",
    "create_suppression",
    "lift_for_alert",
    "lift_suppression",
    "list_suppressions",
    "load_active",
    "match_of",
    "row_matches",
]


class SuppressionError(ValueError):
    """Invalid request (HTTP 422)."""


class SuppressionNotFound(LookupError):
    pass


class SuppressionStateError(RuntimeError):
    """E.g. lifting a row that is already lifted (HTTP 409)."""


# --------------------------------------------------------------------------------------------- matching


def match_of(rule_id: str, details: dict[str, Any]) -> dict[str, Any]:
    """Normalised match content of an alert / draft (see the module docstring)."""
    sigs = details.get("signatures")
    if rule_id.startswith("web.") and isinstance(sigs, list) and sigs:
        param = details.get("param")
        return {
            "signatures": sorted({str(s) for s in sigs})[:MAX_MATCH_ITEMS],
            "location": str(details.get("location") or ""),
            "param": str(param)[:200] if param is not None else None,
        }
    selections = details.get("matched")
    if rule_id.startswith("sigma:") and isinstance(selections, list) and selections:
        return {"selections": sorted({str(s) for s in selections})[:MAX_MATCH_ITEMS]}
    return {}


def route_of(entities: dict[str, str]) -> str | None:
    path = entities.get("path")
    if not path:
        return None
    return path_key(clean_path(path.lower()))


def _network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


def _host_cidr(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return f"{addr}/{addr.max_prefixlen}"


def _in_cidr(ip: str | None, cidr: str) -> bool:
    net = _network(cidr)
    if net is None or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == net.version and addr in net


def _subset(draft: dict[str, Any], row: dict[str, Any]) -> bool:
    if "signatures" in row:
        sigs = draft.get("signatures") or []
        return (
            bool(sigs)
            and set(sigs) <= set(row["signatures"])
            and draft.get("location") == row.get("location")
            and draft.get("param") == row.get("param")
        )
    if "selections" in row:
        sel = draft.get("selections") or []
        return bool(sel) and set(sel) <= set(row["selections"])
    return True


def row_matches(row: AlertSuppressionRow, d: AlertDraft) -> bool:
    if row.rule_id and row.rule_id != d.rule_id:
        return False
    if row.source_cidr and not _in_cidr(d.source_ip, row.source_cidr):
        return False
    if row.path_key and row.path_key != route_of(d.entities):
        return False
    if row.max_severity and Severity(d.severity).rank > Severity(row.max_severity).rank:
        return False
    return not row.match or _subset(match_of(d.rule_id, d.details), row.match)


def is_active(row: AlertSuppressionRow, now: datetime) -> bool:
    return row.lifted_at is None and (row.expires_at is None or row.expires_at > now)


async def load_active(session: AsyncSession, now: datetime) -> list[AlertSuppressionRow]:
    """Active rows, false positives first (they absorb into the marked alert), then allowlists, newest first."""
    rows = (
        (
            await session.execute(
                select(AlertSuppressionRow)
                .where(
                    AlertSuppressionRow.lifted_at.is_(None),
                    or_(AlertSuppressionRow.expires_at.is_(None), AlertSuppressionRow.expires_at > now),
                )
                .order_by(AlertSuppressionRow.created_at.desc())
                .limit(MAX_ACTIVE_ROWS)
            )
        )
        .scalars()
        .all()
    )
    return sorted(rows, key=lambda r: r.kind != AlertSuppressionKind.FALSE_POSITIVE.value)


async def apply(
    session: AsyncSession, rows: list[AlertSuppressionRow], d: AlertDraft, now: datetime
) -> Verdict:
    """Decide one draft: ``"drop"`` (no alert), ``"quiet"`` (store downgraded, do not publish) or None."""
    for row in rows:
        if not row_matches(row, d):
            continue
        row.hits = (row.hits or 0) + 1
        row.last_hit_at = now
        if row.mode == AlertSuppressionMode.DOWNGRADE.value:
            d.details["suppression"] = {"id": row.id, "kind": row.kind, "original_severity": str(d.severity)}
            d.severity = Severity.INFO
            if ALLOWLISTED_TAG not in d.tags and row.kind == AlertSuppressionKind.ALLOWLIST.value:
                d.tags.append(ALLOWLISTED_TAG)
            return "quiet"
        if row.kind == AlertSuppressionKind.FALSE_POSITIVE.value and row.source_alert_id:
            marked = await session.get(AlertRow, row.source_alert_id)
            if marked is not None:  # the analyst sees how often "their" false positive recurs
                marked.count += 1
                marked.last_seen = now
                merged = list(dict.fromkeys([*marked.evidence_event_ids, *d.evidence_event_ids]))
                marked.evidence_event_ids = merged[-200:]
        return "drop"
    return None


# --------------------------------------------------------------------------------------------- management


def _view(row: AlertSuppressionRow, now: datetime) -> AlertSuppression:
    out = AlertSuppression.model_validate(row)
    out.active = is_active(row, now)
    return out


async def create_from_alert(
    session: AsyncSession,
    alert: AlertRow,
    *,
    actor: str,
    settings: Settings,
    hours: float | None = None,
    permanent: bool = False,
    any_source: bool = False,
    reason: str | None = None,
) -> AlertSuppressionRow | None:
    """The ``false_positive`` row for an alert an analyst just marked (None when nothing is to be stored)."""
    now = utcnow()
    if permanent:
        expires: datetime | None = None
    else:
        h = hours if hours is not None else settings.detection.fp_suppress_hours
        if h <= 0:
            return None
        expires = now + timedelta(hours=h)
    cidr = None
    if not any_source:
        cidr = _host_cidr(alert.source_ip)
        if cidr is None and alert.source_ip:
            log.warning("alert %s: source %r is not an IP; not suppressing", alert.id, alert.source_ip[:64])
            return None
    await lift_for_alert(session, alert.id, actor=actor, now=now)  # re-marking replaces the earlier row
    row = AlertSuppressionRow(
        id=new_id(),
        created_at=now,
        updated_at=now,
        kind=AlertSuppressionKind.FALSE_POSITIVE.value,
        mode=AlertSuppressionMode.SUPPRESS.value,
        rule_id=alert.rule_id,
        path_key=route_of(alert.entities or {}),
        source_cidr=cidr,
        match=match_of(alert.rule_id, alert.details or {}),
        max_severity=str(alert.severity),
        reason=(reason or "").strip()[:MAX_REASON_CHARS],
        created_by=actor[:64],
        source_alert_id=alert.id,
        expires_at=expires,
        hits=0,
    )
    session.add(row)
    await record_audit(
        actor,
        "alert.suppression.create",
        target=row.id,
        details={
            "kind": row.kind,
            "rule_id": row.rule_id,
            "path_key": row.path_key,
            "source_cidr": row.source_cidr,
            "match": row.match,
            "expires_at": expires.isoformat() if expires else None,
            "source_alert_id": alert.id,
        },
        session=session,
    )
    return row


async def create_suppression(
    session: AsyncSession, body: AlertSuppressionIn, *, actor: str, settings: Settings
) -> AlertSuppression:
    """``POST /alert-suppressions``: an allowlist (or a manual false-positive rule) declared ahead of time."""
    now = utcnow()
    cidr: str | None = None
    if body.source_cidr:
        net = _network(body.source_cidr.strip())
        if net is None:
            raise SuppressionError(f"invalid source_cidr: {body.source_cidr!r}")
        cidr = str(net)
    rule_id = (body.rule_id or "").strip() or None
    if body.kind == AlertSuppressionKind.ALLOWLIST:
        if cidr is None:
            raise SuppressionError("an allowlist needs source_cidr")
        allowed = ipaddress.ip_network(cidr)
        if allowed.prefixlen < MIN_ALLOWLIST_PREFIX[allowed.version]:
            raise SuppressionError(
                f"source_cidr {cidr} is too wide (IPv{allowed.version} prefix must be at least "
                f"/{MIN_ALLOWLIST_PREFIX[allowed.version]})"
            )
        if body.hours is None:
            raise SuppressionError("an allowlist needs hours (it always expires)")
        if body.hours > settings.detection.allowlist_max_hours:
            raise SuppressionError(
                f"hours must be at most detection.allowlist_max_hours ({settings.detection.allowlist_max_hours:g})"
            )
        hours: float | None = body.hours
    else:
        if rule_id is None:
            raise SuppressionError("a false_positive suppression needs rule_id")
        hours = body.hours if body.hours is not None else (settings.detection.fp_suppress_hours or None)
    route = path_key(clean_path(body.path.lower())) if body.path else None
    row = AlertSuppressionRow(
        id=new_id(),
        created_at=now,
        updated_at=now,
        kind=body.kind.value,
        mode=body.mode.value,
        rule_id=rule_id,
        path_key=route,
        source_cidr=cidr,
        match={},
        max_severity=None,
        reason=body.reason.strip()[:MAX_REASON_CHARS],
        created_by=actor[:64],
        source_alert_id=None,
        expires_at=now + timedelta(hours=hours) if hours else None,
        hits=0,
    )
    session.add(row)
    await record_audit(
        actor,
        "alert.suppression.create",
        target=row.id,
        details={
            "kind": row.kind,
            "mode": row.mode,
            "rule_id": rule_id,
            "path_key": route,
            "source_cidr": cidr,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        },
        session=session,
    )
    await session.flush()
    return _view(row, now)


async def lift_suppression(session: AsyncSession, suppression_id: str, *, actor: str) -> AlertSuppression:
    row = await session.get(AlertSuppressionRow, suppression_id)
    if row is None:
        raise SuppressionNotFound(suppression_id)
    now = utcnow()
    if row.lifted_at is not None:
        raise SuppressionStateError("suppression is already lifted")
    row.lifted_at = now
    row.lifted_by = actor[:64]
    row.updated_at = now
    await record_audit(
        actor, "alert.suppression.lift", target=row.id, details={"kind": row.kind}, session=session
    )
    await session.flush()
    return _view(row, now)


async def lift_for_alert(
    session: AsyncSession, alert_id: str, *, actor: str, now: datetime | None = None
) -> int:
    """Lift the active false-positive rows of an alert (status changed away from false_positive, or re-marked)."""
    now = now or utcnow()
    rows = (
        (
            await session.execute(
                select(AlertSuppressionRow).where(
                    AlertSuppressionRow.source_alert_id == alert_id, AlertSuppressionRow.lifted_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    for row in rows:
        row.lifted_at = now
        row.lifted_by = actor[:64]
        row.updated_at = now
        await record_audit(
            actor,
            "alert.suppression.lift",
            target=row.id,
            details={"source_alert_id": alert_id},
            session=session,
        )
    return len(rows)


async def list_suppressions(
    session: AsyncSession,
    *,
    active_only: bool = True,
    kind: AlertSuppressionKind | None = None,
    source_alert_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> Page[AlertSuppression]:
    now = utcnow()
    conds = []
    if active_only:
        conds += [
            AlertSuppressionRow.lifted_at.is_(None),
            or_(AlertSuppressionRow.expires_at.is_(None), AlertSuppressionRow.expires_at > now),
        ]
    if kind is not None:
        conds.append(AlertSuppressionRow.kind == kind.value)
    if source_alert_id:
        conds.append(AlertSuppressionRow.source_alert_id == source_alert_id)
    total = (
        await session.execute(select(func.count()).select_from(AlertSuppressionRow).where(*conds))
    ).scalar_one()
    rows = (
        (
            await session.execute(
                select(AlertSuppressionRow)
                .where(*conds)
                .order_by(AlertSuppressionRow.created_at.desc(), AlertSuppressionRow.id.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return Page[AlertSuppression](
        items=[_view(r, now) for r in rows], total=int(total), limit=limit, offset=offset
    )
