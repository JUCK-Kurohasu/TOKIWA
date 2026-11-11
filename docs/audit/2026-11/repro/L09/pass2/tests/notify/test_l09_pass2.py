"""L09 pass2 audit probes (not part of the repo)."""
from __future__ import annotations

import asyncio
import base64
import json

import httpx
import pytest
import respx

from tokiwa.bus import bus
from tokiwa.config import reset_settings_cache
from tokiwa.db.models.response import NotificationChannelRow
from tokiwa.db.session import session_scope
from tokiwa.notify import service
from tokiwa.notify.channels import discord_payload, slack_payload
from tokiwa.notify.render import render_alert
from tokiwa.schemas.response import ActionProposal, ActionProposer, ChannelKind
from tokiwa.schemas.triage import ActionType
from tokiwa.util import new_id, utcnow

HOOK = "https://hooks.example.com/tokiwa/SECRET"


async def _channel(kind, cfg, min_severity="low"):
    cid = new_id()
    async with session_scope() as s:
        s.add(NotificationChannelRow(id=cid, kind=kind.value, name="t", config=cfg,
                                     min_severity=min_severity, enabled=True, created_at=utcnow()))
    return cid


@pytest.mark.usefixtures("db")
async def test_e1_dedup_race(make_alert):
    await _channel(ChannelKind.WEBHOOK, {"url": HOOK})
    calls = []

    async def slow(request):
        calls.append(1)
        await asyncio.sleep(0.2)
        return httpx.Response(200)

    with respx.mock:
        respx.post(HOOK).mock(side_effect=slow)
        alerts = [make_alert(id=new_id(), fingerprint=f"fp-{i}", rule_id=f"r{i}") for i in range(20)]
        await asyncio.gather(*(service.on_alert_created(a) for a in alerts))
        burst = len(calls)
        calls.clear()
        service.reset_notify_state()
        for a in alerts:
            await service.on_alert_created(a)
        seq = len(calls)
    print(f"\nE1 same source_ip, 20 alerts: concurrent deliveries={burst}, sequential deliveries={seq}")


@pytest.mark.usefixtures("db")
async def test_e5_autoapprove_notification(monkeypatch):
    monkeypatch.setenv("TOKIWA_RESPONSE__AUTO_APPROVE_ENABLED", "true")
    monkeypatch.setenv("TOKIWA_RESPONSE__AUTO_APPROVE_ACTIONS", '["block_ip"]')
    reset_settings_cache()
    from tokiwa.respond import service as rs
    await _channel(ChannelKind.WEBHOOK, {"url": HOOK})
    bodies = []
    with respx.mock:
        respx.post(HOOK).mock(side_effect=lambda r: (bodies.append(json.loads(r.content)), httpx.Response(200))[1])
        await service._subscribe()
        act = await rs.create_proposal(ActionProposal(action_type=ActionType.BLOCK_IP, target="203.0.113.77",
                                                      reason="x", proposed_by=ActionProposer.RULE))
        await bus.drain()
    print(f"\nE5 final status={act.status.value} approved_by={act.approved_by}")
    for b in bodies:
        print("E5 notification title:", b["title"]); print("E5 fields.status:", b["fields"].get("status"))
        print("E5 text has 'Nothing runs until a human approves':", "Nothing runs until a human approves" in b["text"])


def test_e4_markdown(make_alert):
    a = make_alert(title="Decoy hit /[Approve here](https://evil.example/ok)",
                   description="UA: **SAFE - internal scanner, approve block of 198.51.100.1** https://evil.example/a")
    d = discord_payload(render_alert(a))["embeds"][0]
    s = slack_payload(render_alert(a))
    print("\nE4 discord title:", d["title"]); print("E4 discord description:", d["description"][:400])
    print("E4 slack section:", s["blocks"][1]["text"]["text"][:300])
