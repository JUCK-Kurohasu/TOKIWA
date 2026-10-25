"""Notification channels: config validation, secret masking, payload shapes, delivery.

Payload shapes (tested):
- webhook: ``{"source": "tokiwa", "kind", "severity", "title", "text", "url", "fields", "data", "sent_at"}``
- slack:   incoming-webhook ``{"text", "blocks": [header, section(mrkdwn), section(fields), context?]}``
- discord: ``{"username", "embeds": [{title, description, url?, color, fields, timestamp}], "allowed_mentions": {"parse": []}}``
- email:   plain-text ``EmailMessage`` sent with smtplib in a worker thread

Secrets (webhook URLs embed tokens in their path; SMTP password; custom headers) are masked on read and
never included in error messages.
"""

from __future__ import annotations

import asyncio
import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from tokiwa.config import NotifySettings, get_settings
from tokiwa.notify.outbound import DeliveryError, OutboundBlocked, post_json
from tokiwa.notify.render import Notification
from tokiwa.schemas.common import Severity
from tokiwa.schemas.response import ChannelKind
from tokiwa.util import utcnow

MASK = "********"
_EMAIL_RE = re.compile(r"^[^@\s<>,;\"']+@[^@\s<>,;\"']+$")
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")


def _check_http_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        _ = parts.port
    except ValueError as exc:
        raise ValueError("invalid URL") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("url must be an http(s) URL with a host")
    if any(c in value for c in "\r\n\t "):
        raise ValueError("url must not contain whitespace")
    return value


class _UrlConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        return _check_http_url(v)


class WebhookChannelConfig(_UrlConfig):
    # Extra request headers (e.g. a SOAR auth header). Values are secrets (masked on read).
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("headers")
    @classmethod
    def _headers(cls, v: dict[str, str]) -> dict[str, str]:
        for name, value in v.items():
            if not _HEADER_NAME_RE.match(name) or any(c in value for c in "\r\n"):
                raise ValueError(f"invalid header {name!r}")
        return v


class SlackChannelConfig(_UrlConfig):
    pass


class DiscordChannelConfig(_UrlConfig):
    pass


class EmailChannelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=587, ge=1, le=65535)
    from_addr: str
    to_addrs: list[str] = Field(min_length=1, max_length=50)
    username: str | None = None
    # Prefer ``password_env`` (name of an environment variable) so the secret is not stored in the DB.
    password: str | None = None
    password_env: str | None = None
    starttls: bool = True
    ssl: bool = False
    timeout_seconds: float = Field(default=15.0, gt=0, le=120)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        if not re.match(r"^[A-Za-z0-9.\-:\[\]]+$", v):
            raise ValueError("invalid SMTP host")
        return v

    @field_validator("from_addr")
    @classmethod
    def _from(cls, v: str) -> str:
        if not _EMAIL_RE.match(v):
            raise ValueError("invalid from_addr")
        return v

    @field_validator("to_addrs")
    @classmethod
    def _to(cls, v: list[str]) -> list[str]:
        for addr in v:
            if not _EMAIL_RE.match(addr):
                raise ValueError(f"invalid recipient {addr!r}")
        return v

    @field_validator("password_env")
    @classmethod
    def _env(cls, v: str | None) -> str | None:
        if v is not None and not _ENV_NAME_RE.match(v):
            raise ValueError("password_env must be an environment variable name")
        return v

    def resolved_password(self) -> str | None:
        if self.password_env:
            return os.environ.get(self.password_env) or None
        return self.password or None


_CONFIG_MODELS: dict[ChannelKind, type[BaseModel]] = {
    ChannelKind.WEBHOOK: WebhookChannelConfig,
    ChannelKind.SLACK: SlackChannelConfig,
    ChannelKind.DISCORD: DiscordChannelConfig,
    ChannelKind.EMAIL: EmailChannelConfig,
}


class ChannelConfigError(ValueError):
    pass


def validate_config(kind: ChannelKind, config: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a channel config. Raises :class:`ChannelConfigError` (message is safe)."""
    model = _CONFIG_MODELS[kind]
    try:
        return model.model_validate(config).model_dump(exclude_none=True)
    except ValidationError as exc:
        # Do not echo input values (they may be secrets): report locations and messages only.
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'config'}: {err['msg']}" for err in exc.errors()
        )
        raise ChannelConfigError(problems) from None


def _mask_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        host = parts.hostname or "?"
    except ValueError:
        return MASK
    return f"{parts.scheme}://{host}/{MASK}"


def mask_config(kind: ChannelKind, config: dict[str, Any]) -> dict[str, Any]:
    """Copy of ``config`` safe to return from the API."""
    out = dict(config)
    if isinstance(out.get("url"), str):
        out["url"] = _mask_url(out["url"])
    if out.get("password"):
        out["password"] = MASK
    if isinstance(out.get("headers"), dict):
        out["headers"] = dict.fromkeys(out["headers"], MASK)
    return out


def merge_masked(kind: ChannelKind, incoming: dict[str, Any], existing: dict[str, Any]) -> dict[str, Any]:
    """PATCH support: values the client echoes back in masked form keep the stored secret."""
    merged = dict(incoming)
    if (
        "url" in merged
        and isinstance(existing.get("url"), str)
        and merged["url"] == _mask_url(existing["url"])
    ):
        merged["url"] = existing["url"]
    if merged.get("password") == MASK and existing.get("password"):
        merged["password"] = existing["password"]
    if isinstance(merged.get("headers"), dict) and isinstance(existing.get("headers"), dict):
        merged["headers"] = {
            k: (existing["headers"].get(k, v) if v == MASK else v) for k, v in merged["headers"].items()
        }
    return merged


# ---------------------------------------------------------------- payloads

_SEVERITY_COLOR = {
    Severity.INFO: 0x6B7280,
    Severity.LOW: 0x3B82F6,
    Severity.MEDIUM: 0xEAB308,
    Severity.HIGH: 0xF97316,
    Severity.CRITICAL: 0xDC2626,
}


def _slack_escape(text: str) -> str:
    # Slack control sequences (<!channel>, <url|label>) start with "<"; escaping neutralizes mentions.
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def webhook_payload(n: Notification) -> dict[str, Any]:
    return {
        "source": "tokiwa",
        "kind": n.kind,
        "severity": n.severity.value,
        "title": n.title,
        "text": n.text,
        "url": n.url,
        "fields": dict(n.fields),
        "data": dict(n.data),
        "sent_at": utcnow().isoformat(),
    }


def slack_payload(n: Notification) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": n.title[:150]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": _slack_escape(n.text)[:2900]}},
    ]
    if n.fields:
        blocks.append(
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*{_slack_escape(k)}*\n{_slack_escape(v)}"[:1900]}
                    for k, v in list(n.fields.items())[:10]
                ],
            }
        )
    if n.url:
        blocks.append(
            {"type": "context", "elements": [{"type": "mrkdwn", "text": f"<{n.url}|Open in TOKIWA>"}]}
        )
    return {"text": _slack_escape(f"[{n.severity.value.upper()}] {n.title}")[:3000], "blocks": blocks}


def discord_payload(n: Notification) -> dict[str, Any]:
    embed: dict[str, Any] = {
        "title": n.title[:256],
        "description": n.text[:4000],
        "color": _SEVERITY_COLOR[n.severity],
        "fields": [
            {"name": k[:256], "value": (v or "-")[:1024], "inline": True}
            for k, v in list(n.fields.items())[:25]
        ],
        "timestamp": utcnow().isoformat(),
    }
    if n.url:
        embed["url"] = n.url
    # allowed_mentions.parse=[] -> no @everyone / role / user pings from untrusted text.
    return {"username": "TOKIWA", "embeds": [embed], "allowed_mentions": {"parse": []}}


def email_message(n: Notification, cfg: EmailChannelConfig) -> EmailMessage:
    msg = EmailMessage()
    subject = f"[{n.severity.value.upper()}] {n.title}".replace("\r", " ").replace("\n", " ")
    msg["Subject"] = subject[:250]
    msg["From"] = cfg.from_addr
    msg["To"] = ", ".join(cfg.to_addrs)
    lines = [n.text, ""]
    lines += [f"{k}: {v}" for k, v in n.fields.items()]
    if n.url:
        lines += ["", n.url]
    msg.set_content("\n".join(lines))
    return msg


def _send_email_sync(cfg: EmailChannelConfig, msg: EmailMessage) -> None:
    context = ssl.create_default_context()
    password = cfg.resolved_password()
    smtp: smtplib.SMTP
    if cfg.ssl:
        smtp = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=cfg.timeout_seconds, context=context)
    else:
        smtp = smtplib.SMTP(cfg.host, cfg.port, timeout=cfg.timeout_seconds)
    with smtp:
        if cfg.starttls and not cfg.ssl:
            smtp.starttls(context=context)
        if cfg.username and password:
            smtp.login(cfg.username, password)
        smtp.send_message(msg)


# ---------------------------------------------------------------- delivery


async def deliver(
    kind: ChannelKind,
    config: dict[str, Any],
    notification: Notification,
    settings: NotifySettings | None = None,
) -> None:
    """Send one notification through one channel. Raises :class:`DeliveryError` with a safe message."""
    s = settings or get_settings().notify
    try:
        if kind is ChannelKind.EMAIL:
            cfg = EmailChannelConfig.model_validate(config)
            try:
                await asyncio.to_thread(_send_email_sync, cfg, email_message(notification, cfg))
            except (smtplib.SMTPException, OSError) as exc:
                raise DeliveryError(f"SMTP error: {type(exc).__name__}") from None
            return
        url_cfg = _CONFIG_MODELS[kind].model_validate(config)
        url = str(url_cfg.url)  # type: ignore[attr-defined]
        headers: dict[str, str] = {}
        if kind is ChannelKind.WEBHOOK:
            payload = webhook_payload(notification)
            headers = dict(url_cfg.headers)  # type: ignore[attr-defined]
        elif kind is ChannelKind.SLACK:
            payload = slack_payload(notification)
        else:
            payload = discord_payload(notification)
        await post_json(
            url,
            payload,
            allowed_hosts=s.allowed_hosts,
            block_private=s.block_private_destinations,
            timeout=s.http_timeout_seconds,
            headers=headers,
        )
    except OutboundBlocked as exc:
        raise DeliveryError(f"destination refused: {exc}") from None
    except ValidationError:
        raise DeliveryError("invalid channel configuration") from None
