"""Notification service: bus subscriptions, channel fan-out, threshold + dedup, channel CRUD.

Subscriptions (registered at startup):
- ``alert.created``     -> every channel whose ``min_severity`` <= alert severity
- ``incident.created``  -> same threshold rule
- ``incident.updated``  -> only when the severity went up (previous severity is remembered in memory)
- ``action.proposed``   -> approval request (severity "high"), unless ``notify.notify_action_proposals`` is off

Dedup: the same target (alert source IP, incident id, action type+target) is notified at most once per
``notify.dedup_minutes`` unless the severity is higher than what was last sent. State is in-memory (resets on
restart, which at worst produces one extra notification).

``notify.default_webhook_url`` acts as an implicit, read-only webhook channel (id ``default``).
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel
from sqlalchemy import select

from tokiwa.audit import record_audit
from tokiwa.bus import bus
from tokiwa.config import NotifySettings, get_settings
from tokiwa.db.models.response import NotificationChannelRow, ResponseActionRow
from tokiwa.db.session import session_scope
from tokiwa.notify.channels import (
    ChannelConfigError,
    deliver,
    mask_config,
    merge_masked,
    validate_config,
)
from tokiwa.notify.outbound import DeliveryError
from tokiwa.notify.render import (
    Notification,
    render_action,
    render_action_notice,
    render_alert,
    render_incident,
    render_test,
)
from tokiwa.runtime import on_startup
from tokiwa.schemas.alerts import Alert, Incident
from tokiwa.schemas.common import Severity
from tokiwa.schemas.response import (
    ActionStatus,
    ChannelKind,
    NotificationChannel,
    NotificationChannelIn,
    ResponseAction,
)
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

DEFAULT_CHANNEL_ID = "default"
_MAX_TRACKED = 10_000


class ChannelNotFound(LookupError):
    pass


@dataclass(frozen=True)
class ChannelTarget:
    id: str
    kind: ChannelKind
    name: str
    config: dict[str, Any]
    min_severity: Severity


class DeliveryResult(BaseModel):
    channel_id: str
    ok: bool
    error: str | None = None


# ---------------------------------------------------------------- in-memory state


class _Deduper:
    def __init__(self) -> None:
        self._last: OrderedDict[str, tuple[datetime, int]] = OrderedDict()

    def should_send(self, key: str, severity: Severity, now: datetime, window: timedelta) -> bool:
        prev = self._last.get(key)
        if prev is None:
            return True
        sent_at, rank = prev
        return now - sent_at >= window or severity.rank > rank

    def mark(self, key: str, severity: Severity, now: datetime) -> None:
        self._last[key] = (now, severity.rank)
        self._last.move_to_end(key)
        while len(self._last) > _MAX_TRACKED:
            self._last.popitem(last=False)

    def clear(self) -> None:
        self._last.clear()


_dedup = _Deduper()
_incident_severity: OrderedDict[str, int] = OrderedDict()


def reset_notify_state() -> None:
    """For tests."""
    _dedup.clear()
    _incident_severity.clear()


def _remember_incident(incident_id: str, severity: Severity) -> int | None:
    prev = _incident_severity.get(incident_id)
    _incident_severity[incident_id] = max(prev or 0, severity.rank)
    _incident_severity.move_to_end(incident_id)
    while len(_incident_severity) > _MAX_TRACKED:
        _incident_severity.popitem(last=False)
    return prev


# ---------------------------------------------------------------- channels


def _implicit_default(settings: NotifySettings) -> ChannelTarget | None:
    if not settings.default_webhook_url:
        return None
    return ChannelTarget(
        id=DEFAULT_CHANNEL_ID,
        kind=ChannelKind.WEBHOOK,
        name="default (notify.default_webhook_url)",
        config={"url": settings.default_webhook_url},
        min_severity=Severity(settings.default_min_severity),
    )


async def load_channels(settings: NotifySettings | None = None) -> list[ChannelTarget]:
    """Enabled DB channels plus the implicit default webhook."""
    s = settings or get_settings().notify
    async with session_scope() as session:
        rows = (
            (await session.execute(select(NotificationChannelRow).where(NotificationChannelRow.enabled)))
            .scalars()
            .all()
        )
        targets = [
            ChannelTarget(
                id=r.id,
                kind=ChannelKind(r.kind),
                name=r.name,
                config=dict(r.config or {}),
                min_severity=Severity(r.min_severity),
            )
            for r in rows
        ]
    default = _implicit_default(s)
    if default is not None:
        targets.append(default)
    return targets


async def _send(target: ChannelTarget, n: Notification, settings: NotifySettings) -> DeliveryResult:
    try:
        await deliver(target.kind, target.config, n, settings)
        return DeliveryResult(channel_id=target.id, ok=True)
    except DeliveryError as exc:
        log.warning("notification via channel %s (%s) failed: %s", target.id, target.kind, exc)
        return DeliveryResult(channel_id=target.id, ok=False, error=str(exc))
    except Exception as exc:
        log.exception("notification via channel %s crashed", target.id)
        return DeliveryResult(channel_id=target.id, ok=False, error=type(exc).__name__)


async def dispatch(
    n: Notification,
    *,
    respect_threshold: bool = True,
    respect_dedup: bool = True,
    channel_id: str | None = None,
    settings: NotifySettings | None = None,
) -> list[DeliveryResult]:
    """Fan a notification out to eligible channels."""
    s = settings or get_settings().notify
    now = utcnow()
    window = timedelta(minutes=max(0, s.dedup_minutes))
    if respect_dedup and n.dedup_key and not _dedup.should_send(n.dedup_key, n.severity, now, window):
        log.debug("notification %s suppressed by dedup", n.dedup_key)
        return []
    targets = [
        t
        for t in await load_channels(s)
        if (channel_id is None or t.id == channel_id)
        and (not respect_threshold or n.severity.at_least(t.min_severity))
    ]
    if not targets:
        return []
    results = [await _send(t, n, s) for t in targets]
    if respect_dedup and n.dedup_key:
        _dedup.mark(n.dedup_key, n.severity, now)
    return results


# ---------------------------------------------------------------- bus handlers


def _coerce[M: BaseModel](model: type[M], payload: Any) -> M:
    return payload if isinstance(payload, model) else model.model_validate(payload)


async def on_alert_created(payload: Any) -> None:
    alert = _coerce(Alert, payload)
    await dispatch(render_alert(alert))


async def on_incident_created(payload: Any) -> None:
    incident = _coerce(Incident, payload)
    _remember_incident(incident.id, incident.severity)
    await dispatch(render_incident(incident))


async def on_incident_updated(payload: Any) -> None:
    incident = _coerce(Incident, payload)
    prev_rank = _remember_incident(incident.id, incident.severity)
    if prev_rank is None or incident.severity.rank <= prev_rank:
        return  # unknown baseline (e.g. after restart) or no escalation: stay quiet
    previous = next(s for s in Severity if s.rank == prev_rank)
    await dispatch(render_incident(incident, previous=previous))


async def on_action_proposed(payload: Any) -> None:
    if not get_settings().notify.notify_action_proposals:
        return
    action = _coerce(ResponseAction, payload)
    # Policy may have auto-approved it by the time this handler runs: re-read the current status.
    async with session_scope() as session:
        row = await session.get(ResponseActionRow, action.id)
        if row is not None:
            action = ResponseAction.model_validate(row)
    await dispatch(render_action(action, pending=action.status is ActionStatus.PROPOSED))


@on_startup
async def _subscribe() -> None:
    bus.subscribe("alert.created", on_alert_created)
    bus.subscribe("incident.created", on_incident_created)
    bus.subscribe("incident.updated", on_incident_updated)
    bus.subscribe("action.proposed", on_action_proposed)


# ---------------------------------------------------------------- used by the respond "notify" executor


async def send_action_notice(
    *,
    action_id: str,
    target: str,
    incident_id: str | None,
    alert_id: str | None,
    channel_id: str | None = None,
) -> list[DeliveryResult]:
    """Explicit, human-approved page: ignores thresholds and dedup. Raises DeliveryError if nothing was sent."""
    n = render_action_notice(action_id=action_id, target=target, incident_id=incident_id, alert_id=alert_id)
    results = await dispatch(n, respect_threshold=False, respect_dedup=False, channel_id=channel_id)
    if not results:
        raise DeliveryError("no enabled notification channel matched")
    if not any(r.ok for r in results):
        raise DeliveryError("; ".join(f"{r.channel_id}: {r.error}" for r in results))
    return results


# ---------------------------------------------------------------- CRUD (routes/notify.py)


class ChannelPatch(BaseModel):
    name: str | None = None
    config: dict[str, Any] | None = None
    min_severity: Severity | None = None
    enabled: bool | None = None


def _public(row: NotificationChannelRow) -> NotificationChannel:
    kind = ChannelKind(row.kind)
    return NotificationChannel(
        id=row.id,
        created_at=row.created_at,
        kind=kind,
        name=row.name,
        config=mask_config(kind, dict(row.config or {})),
        min_severity=Severity(row.min_severity),
        enabled=row.enabled,
    )


async def list_channels() -> list[NotificationChannel]:
    async with session_scope() as session:
        rows = (
            (
                await session.execute(
                    select(NotificationChannelRow).order_by(NotificationChannelRow.created_at)
                )
            )
            .scalars()
            .all()
        )
        return [_public(r) for r in rows]


async def create_channel(body: NotificationChannelIn, *, actor: str) -> NotificationChannel:
    config = validate_config(body.kind, body.config)
    row = NotificationChannelRow(
        id=new_id(),
        kind=body.kind.value,
        name=body.name[:128],
        config=config,
        min_severity=body.min_severity.value,
        enabled=body.enabled,
        created_at=utcnow(),
    )
    async with session_scope() as session:
        session.add(row)
        await record_audit(
            actor,
            "notify.channel_create",
            target=row.id,
            details={"kind": row.kind, "name": row.name},
            session=session,
        )
    return _public(row)


async def update_channel(channel_id: str, patch: ChannelPatch, *, actor: str) -> NotificationChannel:
    async with session_scope() as session:
        row = await session.get(NotificationChannelRow, channel_id)
        if row is None:
            raise ChannelNotFound(channel_id)
        kind = ChannelKind(row.kind)
        changed: list[str] = []
        if patch.config is not None:
            row.config = validate_config(kind, merge_masked(kind, patch.config, dict(row.config or {})))
            changed.append("config")
        if patch.name is not None:
            row.name = patch.name[:128]
            changed.append("name")
        if patch.min_severity is not None:
            row.min_severity = patch.min_severity.value
            changed.append("min_severity")
        if patch.enabled is not None:
            row.enabled = patch.enabled
            changed.append("enabled")
        await record_audit(
            actor, "notify.channel_update", target=row.id, details={"fields": changed}, session=session
        )
        return _public(row)


async def delete_channel(channel_id: str, *, actor: str) -> None:
    async with session_scope() as session:
        row = await session.get(NotificationChannelRow, channel_id)
        if row is None:
            raise ChannelNotFound(channel_id)
        await session.delete(row)
        await record_audit(
            actor, "notify.channel_delete", target=channel_id, details={"kind": row.kind}, session=session
        )


async def send_channel_test(channel_id: str) -> DeliveryResult:
    """Send a test message through one channel (also the implicit ``default``), ignoring threshold/dedup."""
    settings = get_settings().notify
    if channel_id == DEFAULT_CHANNEL_ID:
        target = _implicit_default(settings)
    else:
        async with session_scope() as session:
            row = await session.get(NotificationChannelRow, channel_id)
            target = (
                ChannelTarget(
                    id=row.id,
                    kind=ChannelKind(row.kind),
                    name=row.name,
                    config=dict(row.config or {}),
                    min_severity=Severity(row.min_severity),
                )
                if row is not None
                else None
            )
    if target is None:
        raise ChannelNotFound(channel_id)
    return await _send(target, render_test(settings), settings)


__all__ = [
    "DEFAULT_CHANNEL_ID",
    "ChannelConfigError",
    "ChannelNotFound",
    "ChannelPatch",
    "DeliveryResult",
    "create_channel",
    "delete_channel",
    "dispatch",
    "list_channels",
    "load_channels",
    "reset_notify_state",
    "send_action_notice",
    "send_channel_test",
    "update_channel",
]
