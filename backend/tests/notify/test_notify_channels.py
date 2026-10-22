"""Channel payload shapes, secret masking, config validation, SSRF guard, SMTP delivery (all offline)."""

from __future__ import annotations

import smtplib
from typing import Any

import httpx
import pytest
import respx

from tokiwa.notify import channels
from tokiwa.notify.channels import (
    MASK,
    ChannelConfigError,
    deliver,
    discord_payload,
    mask_config,
    merge_masked,
    slack_payload,
    validate_config,
    webhook_payload,
)
from tokiwa.notify.outbound import DeliveryError, OutboundBlocked, check_url, host_allowed, post_json
from tokiwa.notify.render import Notification, render_alert
from tokiwa.schemas.common import Severity
from tokiwa.schemas.response import ChannelKind

SLACK_URL = "https://hooks.slack.com/services/T000/B000/SECRETTOKEN"


def _n(**kw: Any) -> Notification:
    data: dict[str, Any] = {
        "kind": "alert",
        "title": "Alert <!channel>",
        "text": "path /a?x=<script> & more",
        "severity": Severity.HIGH,
        "url": "https://tokiwa.lab/alerts/1",
        "fields": {"source_ip": "203.0.113.10"},
        "data": {"alert_id": "1"},
    }
    data.update(kw)
    return Notification(**data)


# ---------------------------------------------------------------- payload shapes


def test_webhook_payload_shape() -> None:
    p = webhook_payload(_n())
    assert p["source"] == "tokiwa"
    assert set(p) == {"source", "kind", "severity", "title", "text", "url", "fields", "data", "sent_at"}
    assert p["severity"] == "high"
    assert p["data"] == {"alert_id": "1"}


def test_slack_payload_shape_and_escaping() -> None:
    p = slack_payload(_n())
    assert set(p) == {"text", "blocks"}
    types = [b["type"] for b in p["blocks"]]
    assert types[0] == "header" and "section" in types and types[-1] == "context"
    body = p["blocks"][1]["text"]["text"]
    assert "<script>" not in body and "&lt;script&gt;" in body
    assert "<!channel>" not in p["text"]  # no mass mention from untrusted text
    assert p["blocks"][-1]["elements"][0]["text"] == "<https://tokiwa.lab/alerts/1|Open in TOKIWA>"


def test_discord_payload_shape_suppresses_mentions() -> None:
    p = discord_payload(_n(severity=Severity.CRITICAL))
    assert p["allowed_mentions"] == {"parse": []}
    embed = p["embeds"][0]
    assert embed["url"] == "https://tokiwa.lab/alerts/1"
    assert embed["color"] == 0xDC2626
    assert embed["fields"][0] == {"name": "source_ip", "value": "203.0.113.10", "inline": True}


def test_render_alert_bilingual_and_link(settings, make_alert) -> None:  # type: ignore[no-untyped-def]
    s = settings.notify.model_copy(update={"public_ui_url": "https://tokiwa.lab/", "language": "both"})
    n = render_alert(make_alert(title="evil\x07title"), s)
    assert "アラート" in n.title and "Alert" in n.title
    assert "\x07" not in n.title
    assert n.url is not None and n.url.startswith("https://tokiwa.lab/alerts/")
    assert n.dedup_key == "alert:203.0.113.10"
    en_only = render_alert(make_alert(), s.model_copy(update={"language": "en"}))
    assert "アラート" not in en_only.title


# ---------------------------------------------------------------- config / masking


def test_mask_and_merge_roundtrip() -> None:
    cfg = validate_config(ChannelKind.WEBHOOK, {"url": SLACK_URL, "headers": {"X-Auth": "s3cr3t"}})
    masked = mask_config(ChannelKind.WEBHOOK, cfg)
    assert masked["url"] == f"https://hooks.slack.com/{MASK}"
    assert masked["headers"] == {"X-Auth": MASK}
    assert "SECRETTOKEN" not in str(masked) and "s3cr3t" not in str(masked)
    # Echoing the masked form back keeps the stored secrets; a new value replaces them.
    assert merge_masked(ChannelKind.WEBHOOK, masked, cfg) == cfg
    changed = merge_masked(ChannelKind.WEBHOOK, {**masked, "url": "https://example.org/new"}, cfg)
    assert changed["url"] == "https://example.org/new" and changed["headers"] == {"X-Auth": "s3cr3t"}
    email = validate_config(
        ChannelKind.EMAIL,
        {"host": "smtp.lab", "from_addr": "t@lab.example", "to_addrs": ["a@lab.example"], "password": "pw"},
    )
    assert mask_config(ChannelKind.EMAIL, email)["password"] == MASK


@pytest.mark.parametrize(
    ("kind", "config"),
    [
        (ChannelKind.SLACK, {"url": "ftp://hooks.slack.com/x"}),
        (ChannelKind.SLACK, {"url": SLACK_URL, "extra": 1}),
        (ChannelKind.DISCORD, {}),
        (ChannelKind.WEBHOOK, {"url": SLACK_URL, "headers": {"X-Bad": "a\r\nInjected: 1"}}),
        (ChannelKind.EMAIL, {"host": "smtp.lab", "from_addr": "x@y.z", "to_addrs": ["not an email"]}),
        (ChannelKind.EMAIL, {"host": "smtp.lab", "from_addr": "x@y.z\r\nBcc: a@b.c", "to_addrs": ["a@b.c"]}),
    ],
)
def test_invalid_configs_rejected(kind: ChannelKind, config: dict[str, Any]) -> None:
    with pytest.raises(ChannelConfigError) as ei:
        validate_config(kind, config)
    assert "SECRETTOKEN" not in str(ei.value)


# ---------------------------------------------------------------- SSRF guard


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/hook",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.1:8080/x",
        "http://[::1]/x",
        "http://[::ffff:127.0.0.1]/x",
        "https://internal.example.com/x",
        "https://metadata.example.com/x",
        "https://rebind.example.com/x",  # any non-public resolution is refused
        "file:///etc/passwd",
        "gopher://example.com/",
    ],
)
async def test_ssrf_guard_blocks(url: str) -> None:
    with pytest.raises(OutboundBlocked):
        await check_url(url, allowed_hosts=[], block_private=True)


async def test_ssrf_guard_allows_public_and_respects_toggles() -> None:
    await check_url(SLACK_URL, allowed_hosts=[], block_private=True)
    await check_url("http://10.0.0.1/x", allowed_hosts=[], block_private=False)  # lab receivers
    await check_url(SLACK_URL, allowed_hosts=[".slack.com"], block_private=True)
    with pytest.raises(OutboundBlocked):
        await check_url(
            "https://discord.com/api/webhooks/1", allowed_hosts=[".slack.com"], block_private=True
        )
    with pytest.raises(OutboundBlocked):  # allow-list applies even when private blocking is off
        await check_url("http://10.0.0.1/x", allowed_hosts=["hooks.slack.com"], block_private=False)


def test_host_allowed_matching() -> None:
    assert host_allowed("hooks.slack.com", [".slack.com"])
    assert host_allowed("slack.com", [".slack.com"])
    assert not host_allowed("evilslack.com", [".slack.com"])
    assert host_allowed("a.example", ["A.EXAMPLE."])
    assert host_allowed("anything", [])


async def test_post_json_errors_never_leak_url() -> None:
    with respx.mock(assert_all_called=True) as mock:
        mock.post(SLACK_URL).mock(return_value=httpx.Response(500))
        with pytest.raises(DeliveryError) as ei:
            await post_json(SLACK_URL, {"a": 1}, allowed_hosts=[], block_private=True, timeout=5)
    assert str(ei.value) == "HTTP 500"
    with respx.mock() as mock:
        mock.post(SLACK_URL).mock(side_effect=httpx.ConnectError("boom " + SLACK_URL))
        with pytest.raises(DeliveryError) as ei2:
            await post_json(SLACK_URL, {}, allowed_hosts=[], block_private=True, timeout=5)
    assert "SECRETTOKEN" not in str(ei2.value)


async def test_post_json_does_not_follow_redirects() -> None:
    with respx.mock() as mock:
        route = mock.post(SLACK_URL).mock(
            return_value=httpx.Response(302, headers={"Location": "http://127.0.0.1/admin"})
        )
        with pytest.raises(DeliveryError, match="HTTP 302"):
            await post_json(SLACK_URL, {}, allowed_hosts=[], block_private=True, timeout=5)
    assert route.call_count == 1


# ---------------------------------------------------------------- delivery per channel


async def test_deliver_slack_posts_expected_json(settings) -> None:  # type: ignore[no-untyped-def]
    with respx.mock() as mock:
        route = mock.post(SLACK_URL).mock(return_value=httpx.Response(200, text="ok"))
        await deliver(ChannelKind.SLACK, {"url": SLACK_URL}, _n(), settings.notify)
    sent = route.calls.last.request
    import json

    body = json.loads(sent.content)
    assert set(body) == {"text", "blocks"}


async def test_deliver_refused_destination_reports_safely(settings) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(DeliveryError) as ei:
        await deliver(ChannelKind.WEBHOOK, {"url": "http://127.0.0.1:9/hook/SECRET"}, _n(), settings.notify)
    assert "destination refused" in str(ei.value)
    assert "SECRET" not in str(ei.value)


class FakeSMTP:
    instances: list[FakeSMTP] = []  # noqa: RUF012

    def __init__(self, host: str, port: int, timeout: float | None = None, **_: Any) -> None:
        self.host, self.port = host, port
        self.started_tls = False
        self.logged_in: tuple[str, str] | None = None
        self.sent: list[Any] = []
        FakeSMTP.instances.append(self)

    def __enter__(self) -> FakeSMTP:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def starttls(self, context: Any = None) -> None:
        self.started_tls = True

    def login(self, user: str, password: str) -> None:
        self.logged_in = (user, password)

    def send_message(self, msg: Any) -> None:
        self.sent.append(msg)


async def test_deliver_email_uses_smtp_in_thread(settings, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    FakeSMTP.instances.clear()
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setenv("TEST_SMTP_PW", "from-env")
    cfg = {
        "host": "smtp.lab",
        "port": 587,
        "from_addr": "tokiwa@lab.example",
        "to_addrs": ["soc@lab.example", "oncall@lab.example"],
        "username": "tokiwa",
        "password_env": "TEST_SMTP_PW",
    }
    await deliver(
        ChannelKind.EMAIL,
        validate_config(ChannelKind.EMAIL, cfg),
        _n(title="Hi\r\nBcc: x@y"),
        settings.notify,
    )
    smtp = FakeSMTP.instances[-1]
    assert smtp.started_tls and smtp.logged_in == ("tokiwa", "from-env")
    msg = smtp.sent[0]
    assert msg["To"] == "soc@lab.example, oncall@lab.example"
    assert msg["Subject"].startswith("[HIGH]") and "\n" not in msg["Subject"]
    assert "https://tokiwa.lab/alerts/1" in msg.get_content()


async def test_deliver_email_smtp_failure(settings, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    class Boom(FakeSMTP):
        def send_message(self, msg: Any) -> None:
            raise smtplib.SMTPRecipientsRefused({})

    monkeypatch.setattr(smtplib, "SMTP", Boom)
    cfg = validate_config(
        ChannelKind.EMAIL, {"host": "smtp.lab", "from_addr": "t@lab.example", "to_addrs": ["a@lab.example"]}
    )
    with pytest.raises(DeliveryError, match="SMTP error"):
        await deliver(ChannelKind.EMAIL, cfg, _n(), settings.notify)
    assert channels.MASK == MASK
