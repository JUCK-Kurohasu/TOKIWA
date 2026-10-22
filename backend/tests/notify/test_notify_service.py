"""Notification fan-out: thresholds, dedup, incident escalation, approval requests, implicit default channel."""

from __future__ import annotations

import json
from datetime import timedelta

import httpx
import pytest
import respx

from tokiwa.bus import bus
from tokiwa.config import reset_settings_cache
from tokiwa.db.models.response import NotificationChannelRow
from tokiwa.db.session import session_scope
from tokiwa.notify import service
from tokiwa.notify.outbound import DeliveryError
from tokiwa.schemas.common import Severity
from tokiwa.schemas.response import ActionProposer, ActionStatus, ChannelKind, ResponseAction
from tokiwa.schemas.triage import ActionType
from tokiwa.util import new_id, utcnow

pytestmark = pytest.mark.usefixtures("db")

HOOK = "https://hooks.example.com/tokiwa/SECRET"
SLACK = "https://hooks.slack.com/services/T/B/SECRET"
DISCORD = "https://discord.com/api/webhooks/1/SECRET"


async def _channel(kind: ChannelKind, url: str, min_severity: str = "high", enabled: bool = True) -> str:
    cid = new_id()
    async with session_scope() as s:
        s.add(
            NotificationChannelRow(
                id=cid,
                kind=kind.value,
                name=f"{kind.value}-test",
                config={"url": url},
                min_severity=min_severity,
                enabled=enabled,
                created_at=utcnow(),
            )
        )
    return cid


def _action(**kw) -> ResponseAction:  # type: ignore[no-untyped-def]
    now = utcnow()
    data = {
        "id": new_id(),
        "created_at": now,
        "updated_at": now,
        "action_type": ActionType.BLOCK_IP,
        "target": "203.0.113.10",
        "params": {},
        "reason": "AI agent <!here> recon",
        "proposed_by": ActionProposer.LLM,
        "incident_id": None,
        "alert_id": None,
        "status": ActionStatus.PROPOSED,
        "reversible": True,
        "ttl_minutes": 60,
        "approved_by": None,
        "approved_at": None,
        "executed_at": None,
        "expires_at": None,
        "reverted_at": None,
        "result": {},
    }
    data.update(kw)
    return ResponseAction(**data)


async def test_alert_threshold_per_channel(make_alert) -> None:  # type: ignore[no-untyped-def]
    await _channel(ChannelKind.WEBHOOK, HOOK, min_severity="high")
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(HOOK).mock(return_value=httpx.Response(204))
        await service.on_alert_created(make_alert(severity=Severity.MEDIUM, source_ip="198.51.100.1"))
        assert route.call_count == 0
        await service.on_alert_created(make_alert(severity=Severity.HIGH, source_ip="198.51.100.2"))
        assert route.call_count == 1
        await service.on_alert_created(make_alert(severity=Severity.CRITICAL, source_ip="198.51.100.3"))
        assert route.call_count == 2


async def test_disabled_channel_is_skipped(make_alert) -> None:  # type: ignore[no-untyped-def]
    await _channel(ChannelKind.WEBHOOK, HOOK, enabled=False)
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(HOOK).mock(return_value=httpx.Response(200))
        assert await service.dispatch(service.render_alert(make_alert())) == []
    assert route.call_count == 0


async def test_dedup_same_target_within_window(make_alert, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    await _channel(ChannelKind.WEBHOOK, HOOK, min_severity="medium")
    t0 = utcnow()
    clock = {"now": t0}
    monkeypatch.setattr(service, "utcnow", lambda: clock["now"])
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(HOOK).mock(return_value=httpx.Response(200))
        await service.on_alert_created(make_alert(rule_id="a", severity=Severity.HIGH))
        await service.on_alert_created(
            make_alert(rule_id="b", severity=Severity.HIGH)
        )  # same IP -> suppressed
        await service.on_alert_created(
            make_alert(rule_id="c", severity=Severity.MEDIUM)
        )  # lower -> suppressed
        assert route.call_count == 1
        await service.on_alert_created(make_alert(rule_id="d", severity=Severity.CRITICAL))  # escalation
        assert route.call_count == 2
        await service.on_alert_created(make_alert(source_ip="198.51.100.9"))  # other target
        assert route.call_count == 3
        clock["now"] = t0 + timedelta(minutes=11)  # default dedup_minutes = 10
        await service.on_alert_created(make_alert(rule_id="e", severity=Severity.HIGH))
        assert route.call_count == 4


async def test_incident_created_and_only_severity_increase(make_incident) -> None:  # type: ignore[no-untyped-def]
    await _channel(ChannelKind.WEBHOOK, HOOK, min_severity="medium")
    inc = make_incident(severity=Severity.MEDIUM)
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(HOOK).mock(return_value=httpx.Response(200))
        await service.on_incident_created(inc)
        assert route.call_count == 1
        await service.on_incident_updated(inc.model_copy(update={"alert_count": 9}))  # same severity
        assert route.call_count == 1
        await service.on_incident_updated(inc.model_copy(update={"severity": Severity.CRITICAL}))
        assert route.call_count == 2
        body = json.loads(route.calls.last.request.content)
        assert body["data"]["previous_severity"] == "medium"
        assert body["data"]["severity"] == "critical"
        await service.on_incident_updated(inc.model_copy(update={"severity": Severity.HIGH}))  # went down
        assert route.call_count == 2
        # Unknown baseline (e.g. created before a restart): no notification
        await service.on_incident_updated(make_incident(severity=Severity.CRITICAL))
        assert route.call_count == 2


async def test_action_proposed_sends_approval_request() -> None:
    await _channel(ChannelKind.SLACK, SLACK, min_severity="high")
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(SLACK).mock(return_value=httpx.Response(200))
        await service.on_action_proposed(_action())
    body = json.loads(route.calls.last.request.content)
    assert "Approval required" in body["text"] or "承認依頼" in body["text"]
    assert "<!here>" not in json.dumps(body)


async def test_action_proposals_can_be_turned_off(monkeypatch: pytest.MonkeyPatch) -> None:
    await _channel(ChannelKind.SLACK, SLACK)
    monkeypatch.setenv("TOKIWA_NOTIFY__NOTIFY_ACTION_PROPOSALS", "false")
    reset_settings_cache()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(SLACK).mock(return_value=httpx.Response(200))
        await service.on_action_proposed(_action())
    assert route.call_count == 0


async def test_channel_specific_payloads(make_alert) -> None:  # type: ignore[no-untyped-def]
    await _channel(ChannelKind.WEBHOOK, HOOK)
    await _channel(ChannelKind.SLACK, SLACK)
    await _channel(ChannelKind.DISCORD, DISCORD)
    with respx.mock(assert_all_called=False) as mock:
        hook = mock.post(HOOK).mock(return_value=httpx.Response(200))
        slack = mock.post(SLACK).mock(return_value=httpx.Response(200))
        discord = mock.post(DISCORD).mock(return_value=httpx.Response(204))
        results = await service.dispatch(service.render_alert(make_alert()))
    assert all(r.ok for r in results) and len(results) == 3
    assert json.loads(hook.calls.last.request.content)["source"] == "tokiwa"
    assert "blocks" in json.loads(slack.calls.last.request.content)
    assert "embeds" in json.loads(discord.calls.last.request.content)


async def test_failed_channel_does_not_block_others(make_alert) -> None:  # type: ignore[no-untyped-def]
    await _channel(ChannelKind.WEBHOOK, HOOK)
    await _channel(ChannelKind.SLACK, SLACK)
    with respx.mock(assert_all_called=False) as mock:
        mock.post(HOOK).mock(return_value=httpx.Response(500))
        mock.post(SLACK).mock(return_value=httpx.Response(200))
        results = await service.dispatch(service.render_alert(make_alert()))
    by_ok = sorted((r.ok, r.error) for r in results)
    assert by_ok == [(False, "HTTP 500"), (True, None)]


async def test_implicit_default_webhook(make_alert, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("TOKIWA_NOTIFY__DEFAULT_WEBHOOK_URL", HOOK)
    monkeypatch.setenv("TOKIWA_NOTIFY__DEFAULT_MIN_SEVERITY", "critical")
    reset_settings_cache()
    channels = await service.load_channels()
    assert [c.id for c in channels] == [service.DEFAULT_CHANNEL_ID]
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(HOOK).mock(return_value=httpx.Response(200))
        await service.on_alert_created(make_alert(severity=Severity.HIGH))
        assert route.call_count == 0
        await service.on_alert_created(make_alert(severity=Severity.CRITICAL, source_ip="198.51.100.4"))
        assert route.call_count == 1


async def test_bus_subscription_delivers(make_alert) -> None:  # type: ignore[no-untyped-def]
    await _channel(ChannelKind.WEBHOOK, HOOK)
    await service._subscribe()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(HOOK).mock(return_value=httpx.Response(200))
        await bus.publish("alert.created", make_alert())
        await bus.drain()
    assert route.call_count == 1


async def test_send_action_notice_requires_a_channel() -> None:
    with pytest.raises(DeliveryError):
        await service.send_action_notice(
            action_id=new_id(), target="203.0.113.10", incident_id=None, alert_id=None
        )


async def test_send_action_notice_ignores_threshold_and_dedup() -> None:
    await _channel(ChannelKind.WEBHOOK, HOOK, min_severity="critical")
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(HOOK).mock(return_value=httpx.Response(200))
        for _ in range(2):
            results = await service.send_action_notice(
                action_id=new_id(), target="203.0.113.10", incident_id=None, alert_id=None
            )
            assert results[0].ok
    assert route.call_count == 2
    payload = json.loads(route.calls.last.request.content)
    assert payload["data"]["target"] == "203.0.113.10"
