"""Audits #128 / #168: untrusted text in notifications (LLM-written reasons / summaries, IDS messages) cannot
become clickable fake links or formatting, and LLM free text / IPs leave only when configured."""

from __future__ import annotations

from typing import Any

from tokiwa.config import NotifySettings
from tokiwa.notify.channels import EmailChannelConfig, defang, discord_payload, email_message, slack_payload
from tokiwa.notify.render import (
    HIDDEN,
    Notification,
    render_action,
    render_action_notice,
    render_alert,
    render_incident,
)
from tokiwa.schemas.common import Severity
from tokiwa.schemas.response import ActionProposer, ActionStatus, ResponseAction
from tokiwa.schemas.triage import ActionType
from tokiwa.util import new_id, utcnow

PHISH = "False positive. Details: [社内 Wiki](https://attacker.example/ok) **SAFE - internal scanner**"


def _action(**kw: Any) -> ResponseAction:
    now = utcnow()
    data: dict[str, Any] = {
        "id": new_id(),
        "created_at": now,
        "updated_at": now,
        "action_type": ActionType.BLOCK_IP,
        "target": "203.0.113.9",
        "params": {},
        "reason": PHISH,
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


def _n(text: str, **kw: Any) -> Notification:
    return Notification(kind="alert", title=kw.pop("title", "t"), text=text, severity=Severity.HIGH, **kw)


def test_approval_request_has_no_llm_reason_by_default() -> None:
    n = render_action(_action(), settings=NotifySettings())
    assert "attacker.example" not in n.text and "SAFE" not in n.text
    assert "203.0.113.9" in n.title and n.fields["proposed_by"] == "llm"  # structured fields stay
    with_text = render_action(_action(), settings=NotifySettings(include_summary=True))
    assert "attacker.example" in with_text.text  # opt-in: raw here, neutralized per channel below


def test_incident_summary_and_source_ips_follow_settings(make_incident) -> None:  # type: ignore[no-untyped-def]
    inc = make_incident(summary="Yamada Hanako 090-7777-8888 targeted", source_ips=["198.51.100.4"])
    default = render_incident(inc, settings=NotifySettings())
    assert "Hanako" not in default.text and "198.51.100.4" in default.text
    opted = render_incident(inc, settings=NotifySettings(include_summary=True, include_source_ip=False))
    assert "Hanako" in opted.text and "198.51.100.4" not in opted.text + str(opted.fields) + str(opted.data)
    assert HIDDEN in opted.fields["source_ips"] and opted.data["source_ips"] == []


def test_source_ip_can_be_hidden_everywhere(make_alert) -> None:  # type: ignore[no-untyped-def]
    s = NotifySettings(include_source_ip=False)
    alert = render_alert(make_alert(source_ip="198.51.100.4"), s)
    assert "198.51.100.4" not in alert.text + str(alert.fields) + str(alert.data)
    assert alert.dedup_key == "alert:198.51.100.4"  # internal only, never sent
    action = render_action(_action(), settings=s)
    assert "203.0.113.9" not in action.title + action.text + str(action.fields) + str(action.data)
    canary = render_action(_action(action_type=ActionType.DEPLOY_CANARY, target="/backup.zip"), settings=s)
    assert "/backup.zip" in canary.title  # not an IP: kept
    notice = render_action_notice(
        action_id="a1", target="203.0.113.9", incident_id=None, alert_id=None, settings=s
    )
    assert "203.0.113.9" not in notice.title + str(notice.fields) + str(notice.data)


def test_discord_escapes_markdown_and_defangs_links() -> None:
    p = discord_payload(_n(PHISH, title="**Approve** [now](https://x.example)", fields={"msg": PHISH}))
    embed = p["embeds"][0]
    for text in (embed["title"], embed["description"], embed["fields"][0]["value"]):
        assert "](https://" not in text and "https://" not in text and "hxxps://" in text
        assert "**" not in text and "\\*\\*" in text and "\\[" in text
    assert embed["fields"][0]["name"] == "msg"


def test_discord_cut_never_leaves_a_dangling_escape() -> None:
    p = discord_payload(_n("a" * 3998 + "*b"))
    desc = p["embeds"][0]["description"]
    # "*" became "\*"; the cut at 3999 would end on the lone "\" (escaping the "…"), so it is dropped.
    assert desc == "a" * 3998 + "…"


def test_slack_uses_plain_text_for_untrusted_parts() -> None:
    p = slack_payload(
        _n(PHISH, fields={"msg": "*bold* <!channel> https://evil.example"}, url="https://tokiwa.lab/a/1")
    )
    header, body, fields, context = p["blocks"]
    assert header["text"]["type"] == "plain_text" and body["text"]["type"] == "plain_text"
    assert all(f["type"] == "plain_text" for f in fields["fields"])
    assert "https://attacker" not in body["text"]["text"] and "hxxps://attacker" in body["text"]["text"]
    assert "<!channel>" not in fields["fields"][0]["text"] and "hxxps://evil" in fields["fields"][0]["text"]
    assert p["mrkdwn"] is False
    assert context["elements"][0]["text"] == "<https://tokiwa.lab/a/1|Open in TOKIWA>"  # our own link stays


def test_email_defangs_untrusted_text_but_keeps_the_ui_link() -> None:
    cfg = EmailChannelConfig(host="smtp.lab", from_addr="t@lab.example", to_addrs=["a@lab.example"])
    msg = email_message(_n(PHISH, title="see https://evil.example", url="https://tokiwa.lab/a/1"), cfg)
    body = msg.get_content()
    assert "https://attacker" not in body and "hxxps://attacker.example" in body
    assert "https://tokiwa.lab/a/1" in body and "https://" not in msg["Subject"]


def test_defang_and_invisible_characters() -> None:
    assert defang("HTTP://a and https://b") == "HxxP://a and hxxps://b"
    n = render_action(
        _action(target="203.0.113.9", reason="ok‮gnp.exe"), settings=NotifySettings(include_summary=True)
    )
    assert "‮" not in n.text
