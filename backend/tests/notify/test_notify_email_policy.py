"""Audit #118: an admin session must not turn an e-mail channel into a way to ship process secrets (LLM API key,
DB URL ...) or stored channel secrets to an SMTP server of its choosing. All offline (fake SMTP class)."""

from __future__ import annotations

import json
import smtplib
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from tokiwa.config import NotifySettings, reset_settings_cache
from tokiwa.db.models.core import AuditRow
from tokiwa.db.models.response import NotificationChannelRow
from tokiwa.db.session import session_scope
from tokiwa.notify.channels import (
    MASK,
    ChannelConfigError,
    deliver,
    mask_config,
    merge_masked,
    password_env_problem,
    validate_config,
)
from tokiwa.notify.outbound import DeliveryError
from tokiwa.notify.render import render_test
from tokiwa.schemas.response import ChannelKind
from tokiwa.util import new_id, utcnow


class FakeSMTP:
    instances: list[FakeSMTP] = []  # noqa: RUF012
    fail: BaseException | None = None

    def __init__(self, host: str, port: int, timeout: float | None = None, **_: Any) -> None:
        if FakeSMTP.fail is not None:
            raise FakeSMTP.fail
        self.host, self.port = host, port
        self.logged_in: tuple[str, str] | None = None
        FakeSMTP.instances.append(self)

    def __enter__(self) -> FakeSMTP:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def starttls(self, context: Any = None) -> None:
        return None

    def login(self, user: str, password: str) -> None:
        self.logged_in = (user, password)

    def send_message(self, msg: Any) -> None:
        return None


@pytest.fixture
def smtp(monkeypatch: pytest.MonkeyPatch) -> type[FakeSMTP]:
    FakeSMTP.instances.clear()
    FakeSMTP.fail = None
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)
    return FakeSMTP


def _email(**kw: Any) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "host": "smtp.corp.example",
        "port": 587,
        "from_addr": "tokiwa@corp.example",
        "to_addrs": ["soc@corp.example"],
        "username": "tokiwa",
    }
    cfg.update(kw)
    return cfg


def _configure(monkeypatch: pytest.MonkeyPatch, **values: Any) -> None:
    for key, value in values.items():
        raw = value if isinstance(value, str) else json.dumps(value)
        monkeypatch.setenv(f"TOKIWA_NOTIFY__{key.upper()}", raw)
    reset_settings_cache()


@pytest.mark.parametrize(
    "name",
    [
        "ANTHROPIC_API_KEY",
        "TOKIWA_LLM__ANTHROPIC_API_KEY",
        "TOKIWA_DATABASE__URL",
        "TOKIWA_SERVER__SECRET_KEY",
        "TOKIWA_INTEL__NVD_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "SMTP_PASSWORD",  # not allow-listed (would need notify.smtp_password_envs)
    ],
)
def test_password_env_refused(name: str, settings) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ChannelConfigError, match="password_env"):
        validate_config(ChannelKind.EMAIL, _email(password_env=name))


def test_password_env_allow_list(settings) -> None:  # type: ignore[no-untyped-def]
    for name in ("TOKIWA_NOTIFY_SMTP_PASSWORD", "TOKIWA_NOTIFY_SMTP_RELAY1", "TOKIWA_SMTP_PASSWORD"):
        assert validate_config(ChannelKind.EMAIL, _email(password_env=name))["password_env"] == name
    extra = NotifySettings(smtp_password_envs=["SMTP_PASSWORD", "ANTHROPIC_API_KEY", "TOKIWA_LLM__X"])
    assert password_env_problem("SMTP_PASSWORD", extra) is None  # legacy name, explicitly allowed by config
    assert password_env_problem("ANTHROPIC_API_KEY", extra)  # the deny list wins over the config list
    assert password_env_problem("TOKIWA_LLM__X", extra)


def test_plaintext_auth_refused_unless_allowed(settings, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    clear = _email(password="pw", starttls=False)
    with pytest.raises(ChannelConfigError, match="starttls or ssl"):
        validate_config(ChannelKind.EMAIL, clear)
    assert validate_config(ChannelKind.EMAIL, _email(password="pw", starttls=False, ssl=True))
    assert validate_config(ChannelKind.EMAIL, _email(username=None, starttls=False))  # no AUTH: fine
    _configure(monkeypatch, smtp_allow_plaintext_auth=True)
    assert validate_config(ChannelKind.EMAIL, clear)


async def test_api_refuses_llm_key_as_smtp_password(client: httpx.AsyncClient, admin_headers, smtp) -> None:  # type: ignore[no-untyped-def]
    """The audit reproduction: password_env=ANTHROPIC_API_KEY towards an attacker's SMTP host."""
    r = await client.post(
        "/api/v1/notify/channels",
        headers=admin_headers,
        json={
            "kind": "email",
            "name": "e",
            "config": _email(host="127.0.0.1", port=21902, password_env="ANTHROPIC_API_KEY"),
        },
    )
    assert r.status_code == 422 and "password_env" in r.json()["detail"]
    assert smtp.instances == []


async def test_legacy_channel_with_refused_env_does_not_send_the_secret(  # type: ignore[no-untyped-def]
    client: httpx.AsyncClient, admin_headers, smtp, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "DUMMY-NOT-REAL")
    cid = new_id()
    async with session_scope() as s:  # saved before the allow-list existed
        s.add(
            NotificationChannelRow(
                id=cid,
                kind="email",
                name="legacy",
                config=_email(password_env="ANTHROPIC_API_KEY"),
                min_severity="high",
                enabled=True,
                created_at=utcnow(),
            )
        )
    r = await client.post(f"/api/v1/notify/channels/{cid}/test", headers=admin_headers)
    assert r.json()["ok"] is False and "not allowed" in r.json()["error"]
    assert smtp.instances == []  # refused before connecting


async def test_masked_password_is_not_carried_to_a_new_host(  # type: ignore[no-untyped-def]
    client: httpx.AsyncClient, admin_headers, smtp
) -> None:
    created = await client.post(
        "/api/v1/notify/channels",
        headers=admin_headers,
        json={"kind": "email", "name": "e2", "config": _email(password="StoredSmtpPw-DUMMY")},
    )
    assert created.status_code == 200, created.text
    cid, masked = created.json()["id"], created.json()["config"]
    assert masked["password"] == MASK
    moved = await client.patch(
        f"/api/v1/notify/channels/{cid}",
        headers=admin_headers,
        json={"config": {**masked, "host": "127.0.0.1"}},
    )
    assert moved.status_code == 422 and "re-enter the password" in moved.json()["detail"]
    renamed = await client.patch(
        f"/api/v1/notify/channels/{cid}",
        headers=admin_headers,
        json={"config": {**masked, "to_addrs": ["x@corp.example"]}},
    )
    assert renamed.status_code == 200  # same destination: the stored password is kept
    async with session_scope() as s:
        row = await s.get(NotificationChannelRow, cid)
        assert row is not None and row.config["password"] == "StoredSmtpPw-DUMMY"
    new_host = await client.patch(
        f"/api/v1/notify/channels/{cid}",
        headers=admin_headers,
        json={"config": {**masked, "host": "smtp2.corp.example", "password": "another"}},
    )
    assert new_host.status_code == 200
    async with session_scope() as s:
        audits = (
            (await s.execute(select(AuditRow).where(AuditRow.action == "notify.channel_update")))
            .scalars()
            .all()
        )
    moves = [a.details["destination"] for a in audits if "destination" in a.details]
    assert moves == [{"before": "smtp://smtp.corp.example:587", "after": "smtp://smtp2.corp.example:587"}]


def test_email_merge_rules() -> None:
    stored = _email(password="pw")
    masked = mask_config(ChannelKind.EMAIL, stored)
    assert merge_masked(ChannelKind.EMAIL, masked, stored)["password"] == "pw"
    for change in ({"port": 25}, {"username": "other"}, {"host": "evil.example"}):
        with pytest.raises(ChannelConfigError):
            merge_masked(ChannelKind.EMAIL, {**masked, **change}, stored)


async def test_smtp_host_restrictions(settings, smtp) -> None:  # type: ignore[no-untyped-def]
    n = render_test()
    allowed_only = NotifySettings(smtp_allowed_hosts=[".corp.example"])
    await deliver(ChannelKind.EMAIL, _email(username=None), n, allowed_only)
    with pytest.raises(DeliveryError, match="destination refused"):
        await deliver(ChannelKind.EMAIL, _email(username=None, host="mail.attacker.example"), n, allowed_only)
    private = NotifySettings(smtp_block_private=True)
    for host in ("127.0.0.1", "internal.example.com"):  # literal, and a name resolving to 10.1.2.3
        with pytest.raises(DeliveryError, match="non-public"):
            await deliver(ChannelKind.EMAIL, _email(username=None, host=host), n, private)
    await deliver(
        ChannelKind.EMAIL, _email(username=None, host="127.0.0.1"), n, NotifySettings()
    )  # default: relays ok
    assert [i.host for i in smtp.instances] == ["smtp.corp.example", "127.0.0.1"]


@pytest.mark.parametrize(
    ("exc", "message"),
    [
        (ConnectionRefusedError(), "SMTP connection failed"),
        (TimeoutError(), "SMTP connection failed"),
        (smtplib.SMTPAuthenticationError(535, b"no"), "SMTP authentication failed"),
        (smtplib.SMTPServerDisconnected(), "SMTP error"),
    ],
)
async def test_smtp_errors_are_reported_by_category(settings, smtp, exc: BaseException, message: str) -> None:  # type: ignore[no-untyped-def]
    smtp.fail = exc
    with pytest.raises(DeliveryError) as info:
        await deliver(ChannelKind.EMAIL, _email(username=None), render_test(), NotifySettings())
    assert str(info.value) == message  # no exception type: not a port-probing oracle
