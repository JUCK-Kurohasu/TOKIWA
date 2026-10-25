"""Channel-independent notification content (ja / en templates).

Alert titles and descriptions can contain attacker-controlled fragments (paths, user agents). They are
shown to humans only, but we still strip control characters, cap lengths, and let each channel escape its
own markup (Slack mrkdwn, Discord mentions) in :mod:`tokiwa.notify.channels`.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field

from tokiwa.config import NotifySettings, get_settings
from tokiwa.schemas.alerts import Alert, Incident
from tokiwa.schemas.common import Severity
from tokiwa.schemas.response import ResponseAction

NotificationKind = Literal["alert", "incident", "action", "test"]

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class Notification(BaseModel):
    kind: NotificationKind
    title: str
    text: str
    severity: Severity
    url: str | None = None
    # Same key within ``notify.dedup_minutes`` is suppressed unless the severity went up. None = never.
    dedup_key: str | None = None
    fields: dict[str, str] = Field(default_factory=dict)
    # Machine-readable payload for generic webhooks (ids, scores ...).
    data: dict[str, Any] = Field(default_factory=dict)


def clean(value: object, limit: int = 300) -> str:
    """Single-line-safe display text: no control chars (keeps \\n), length-capped."""
    s = _CONTROL.sub(" ", str(value))
    return s if len(s) <= limit else s[: limit - 1] + "…"


def ui_link(path: str, settings: NotifySettings | None = None) -> str | None:
    s = settings or get_settings().notify
    if not s.public_ui_url:
        return None
    return s.public_ui_url.rstrip("/") + path


def _pick(ja: str, en: str, settings: NotifySettings, *, sep: str) -> str:
    if settings.language == "ja":
        return ja
    if settings.language == "en":
        return en
    return f"{ja}{sep}{en}"


def _title(ja: str, en: str, settings: NotifySettings) -> str:
    return _pick(ja, en, settings, sep=" / ")


def _body(ja: str, en: str, settings: NotifySettings) -> str:
    return _pick(ja, en, settings, sep="\n\n")


def render_alert(alert: Alert, settings: NotifySettings | None = None) -> Notification:
    s = settings or get_settings().notify
    title = clean(alert.title, 200)
    src = alert.source_ip or "-"
    ai = f"{alert.ai_score:.2f}" if alert.ai_score is not None else "-"
    desc = clean(alert.description, 600)
    ja = f"新しいアラート（{alert.severity.value}）: {title}\n送信元: {src} / カテゴリ: {alert.category.value} / AI スコア: {ai}"
    en = f"New alert ({alert.severity.value}): {title}\nSource: {src} / Category: {alert.category.value} / AI score: {ai}"
    if desc:
        ja += f"\n{desc}"
        en += f"\n{desc}"
    return Notification(
        kind="alert",
        title=_title(f"[TOKIWA] アラート: {title}", f"[TOKIWA] Alert: {title}", s),
        text=_body(ja, en, s),
        severity=alert.severity,
        url=ui_link(f"/alerts/{alert.id}", s),
        dedup_key=f"alert:{alert.source_ip}" if alert.source_ip else f"alert-fp:{alert.fingerprint}",
        fields={
            "severity": alert.severity.value,
            "source_ip": src,
            "category": alert.category.value,
            "rule": clean(alert.rule_id, 120),
            "ai_score": ai,
        },
        data={
            "alert_id": alert.id,
            "rule_id": alert.rule_id,
            "source_ip": alert.source_ip,
            "severity": alert.severity.value,
            "category": alert.category.value,
            "ai_score": alert.ai_score,
            "incident_id": alert.incident_id,
        },
    )


def render_incident(
    incident: Incident,
    *,
    previous: Severity | None = None,
    settings: NotifySettings | None = None,
) -> Notification:
    s = settings or get_settings().notify
    title = clean(incident.title, 200)
    ips = ", ".join(incident.source_ips[:5]) or "-"
    ai = f"{incident.ai_score:.2f}" if incident.ai_score is not None else "-"
    if previous is None:
        head_ja, head_en = "新しいインシデント", "New incident"
    else:
        head_ja = f"インシデントの重大度が上昇（{previous.value} → {incident.severity.value}）"
        head_en = f"Incident severity raised ({previous.value} -> {incident.severity.value})"
    summary = clean(incident.summary, 600)
    ja = (
        f"{head_ja}: {title}\n送信元: {ips} / アクター: {incident.actor_type.value} / AI スコア: {ai}"
        f" / アラート数: {incident.alert_count}"
    )
    en = (
        f"{head_en}: {title}\nSources: {ips} / Actor: {incident.actor_type.value} / AI score: {ai}"
        f" / Alerts: {incident.alert_count}"
    )
    if summary:
        ja += f"\n{summary}"
        en += f"\n{summary}"
    return Notification(
        kind="incident",
        title=_title(f"[TOKIWA] インシデント: {title}", f"[TOKIWA] Incident: {title}", s),
        text=_body(ja, en, s),
        severity=incident.severity,
        url=ui_link(f"/incidents/{incident.id}", s),
        dedup_key=f"incident:{incident.id}",
        fields={
            "severity": incident.severity.value,
            "actor_type": incident.actor_type.value,
            "source_ips": clean(ips, 200),
            "alerts": str(incident.alert_count),
            "kill_chain": clean(" > ".join(incident.kill_chain), 200) or "-",
        },
        data={
            "incident_id": incident.id,
            "severity": incident.severity.value,
            "previous_severity": previous.value if previous else None,
            "actor_type": incident.actor_type.value,
            "ai_score": incident.ai_score,
            "source_ips": incident.source_ips[:20],
        },
    )


# Approval requests are treated as "high" so they reach channels with the default threshold.
ACTION_SEVERITY = Severity.HIGH


def render_action(
    action: ResponseAction, *, pending: bool = True, settings: NotifySettings | None = None
) -> Notification:
    """Approval request (pending) or an informational notice when policy auto-approved it."""
    s = settings or get_settings().notify
    t = action.action_type.value
    target = clean(action.target, 120)
    ttl = f"{action.ttl_minutes} min" if action.ttl_minutes else "-"
    reason = clean(action.reason, 500)
    if pending:
        ja = f"対処の承認依頼: {t} → {target}（TTL {ttl}, 提案元 {action.proposed_by.value}）\n承認するまで実行されません。"
        en = f"Approval required: {t} -> {target} (TTL {ttl}, proposed by {action.proposed_by.value})\nNothing runs until a human approves."
        title = _title(f"[TOKIWA] 承認依頼: {t} {target}", f"[TOKIWA] Approval required: {t} {target}", s)
    else:
        ja = f"ポリシーにより自動承認された対処: {t} → {target}（TTL {ttl}, 状態 {action.status.value}）"
        en = f"Action auto-approved by policy: {t} -> {target} (TTL {ttl}, status {action.status.value})"
        title = _title(f"[TOKIWA] 自動承認: {t} {target}", f"[TOKIWA] Auto-approved: {t} {target}", s)
    if reason:
        ja += f"\n理由: {reason}"
        en += f"\nReason: {reason}"
    return Notification(
        kind="action",
        title=title,
        text=_body(ja, en, s),
        severity=ACTION_SEVERITY,
        url=ui_link(f"/response?action={action.id}", s),
        dedup_key=f"action:{t}:{action.target}",
        fields={
            "action": t,
            "target": target,
            "ttl": ttl,
            "status": action.status.value,
            "proposed_by": action.proposed_by.value,
        },
        data={
            "action_id": action.id,
            "action_type": t,
            "target": action.target,
            "status": action.status.value,
            "ttl_minutes": action.ttl_minutes,
            "incident_id": action.incident_id,
            "alert_id": action.alert_id,
        },
    )


def render_action_notice(
    *,
    action_id: str,
    target: str,
    incident_id: str | None,
    alert_id: str | None,
    settings: NotifySettings | None = None,
) -> Notification:
    """Body of an approved ``notify`` response action. Built from validated fields only (no free text)."""
    s = settings or get_settings().notify
    tgt = clean(target, 120)
    link = (
        ui_link(f"/incidents/{incident_id}", s)
        if incident_id
        else ui_link(f"/response?action={action_id}", s)
    )
    ja = f"対応要請: {tgt} について確認してください（承認済みの通知アクション）。"
    en = f"Attention requested: please review {tgt} (approved notify action)."
    return Notification(
        kind="action",
        title=_title(f"[TOKIWA] 対応要請: {tgt}", f"[TOKIWA] Attention: {tgt}", s),
        text=_body(ja, en, s),
        severity=Severity.HIGH,
        url=link,
        dedup_key=None,
        fields={"target": tgt, "incident": incident_id or "-", "alert": alert_id or "-"},
        data={"action_id": action_id, "target": target, "incident_id": incident_id, "alert_id": alert_id},
    )


def render_test(settings: NotifySettings | None = None) -> Notification:
    s = settings or get_settings().notify
    return Notification(
        kind="test",
        title=_title("[TOKIWA] テスト通知", "[TOKIWA] Test notification", s),
        text=_body("これは TOKIWA からのテスト通知です。", "This is a test notification from TOKIWA.", s),
        severity=Severity.INFO,
        url=ui_link("/", s),
        dedup_key=None,
    )
