"""Notification channels: config validation, secret masking, payload shapes, delivery.

Payload shapes (tested):
- webhook: ``{"source": "tokiwa", "kind", "severity", "title", "text", "url", "fields", "data", "sent_at"}``
- slack:   incoming-webhook ``{"text", "mrkdwn": false, "blocks": [header, section(plain_text),
  section(plain_text fields), context(mrkdwn link)?]}``
- discord: ``{"username", "embeds": [{title, description, url?, color, fields, timestamp}], "allowed_mentions": {"parse": []}}``
- email:   plain-text ``EmailMessage`` sent with smtplib in a worker thread

Untrusted text (audit #128): titles, bodies and field values can carry attacker-controlled fragments (paths, IDS
messages, LLM-written reasons). For the human channels (Slack, Discord, e-mail) URLs inside them are defanged
(``https://`` -> ``hxxps://``) so they are not clickable, Discord Markdown is backslash-escaped (no masked links
``[text](url)``, emphasis or headings), and Slack gets them as ``plain_text``. Only TOKIWA's own UI link
(``Notification.url``) stays a link. Webhooks receive the raw strings (machine consumers).

Secrets (webhook URLs embed tokens in their path; SMTP password; custom headers) are masked on read and
never included in error messages.

E-mail channels (audit #118): ``password_env`` may only name an allowed variable (:func:`password_env_problem`),
SMTP AUTH needs STARTTLS or SSL unless ``notify.smtp_allow_plaintext_auth``, the host is checked against
``notify.smtp_allowed_hosts`` / ``notify.smtp_block_private``, a masked secret is never carried over to a new
destination (:func:`merge_masked`), and SMTP errors are reported by category only (no port-probing oracle).
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
from tokiwa.notify.outbound import DeliveryError, OutboundBlocked, check_host, post_json, safe_url_label
from tokiwa.notify.render import Notification
from tokiwa.schemas.common import Severity
from tokiwa.schemas.response import ChannelKind
from tokiwa.util import utcnow

MASK = "********"
_EMAIL_RE = re.compile(r"^[^@\s<>,;\"']+@[^@\s<>,;\"']+$")
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
# password_env names an operator may use without any extra configuration.
ALLOWED_PASSWORD_ENV_PREFIXES = ("TOKIWA_NOTIFY_SMTP_", "TOKIWA_SMTP_PASSWORD")
# Never readable as an SMTP password, even when listed in notify.smtp_password_envs: TOKIWA's own settings
# (TOKIWA_LLM__ANTHROPIC_API_KEY, TOKIWA_DATABASE__URL, TOKIWA_SERVER__SECRET_KEY ...) and common credentials.
_DENIED_ENV_RE = re.compile(r"^TOKIWA_[A-Z0-9]+__")
DENIED_PASSWORD_ENV_PREFIXES = (
    "ANTHROPIC_",
    "OPENAI_",
    "AWS_",
    "AZURE_",
    "GOOGLE_",
    "GCP_",
    "GITHUB_",
    "GH_",
    "HF_",
    "HUGGING",
    "NVD_",
    "DATABASE_",
    "POSTGRES",
    "PG",
)


def password_env_problem(name: str, settings: NotifySettings) -> str | None:
    """Why ``name`` may not be used as ``password_env`` (None = allowed). The message is safe to show."""
    if _DENIED_ENV_RE.match(name) or name.startswith(DENIED_PASSWORD_ENV_PREFIXES):
        return f"password_env {name} is not allowed (TOKIWA settings and API credentials cannot be read)"
    if name.startswith(ALLOWED_PASSWORD_ENV_PREFIXES) or name in settings.smtp_password_envs:
        return None
    return (
        f"password_env {name} is not allowed: use a TOKIWA_NOTIFY_SMTP_* or TOKIWA_SMTP_PASSWORD* variable, "
        "or list the name in notify.smtp_password_envs (server configuration)"
    )


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

    def has_credentials(self) -> bool:
        return bool(self.username and (self.password or self.password_env))


def email_problem(cfg: EmailChannelConfig, settings: NotifySettings) -> str | None:
    """Policy checks that depend on server settings (at save time and again before every send)."""
    if cfg.password_env:
        problem = password_env_problem(cfg.password_env, settings)
        if problem:
            return problem
    if cfg.has_credentials() and not (cfg.starttls or cfg.ssl) and not settings.smtp_allow_plaintext_auth:
        return "SMTP AUTH requires starttls or ssl (set notify.smtp_allow_plaintext_auth to allow clear-text AUTH)"
    return None


def resolve_smtp_password(cfg: EmailChannelConfig, settings: NotifySettings) -> str | None:
    """The password to log in with. Re-checks ``password_env`` (channels saved before the allow-list)."""
    if cfg.password_env:
        if password_env_problem(cfg.password_env, settings):
            return None
        return os.environ.get(cfg.password_env) or None
    return cfg.password or None


_CONFIG_MODELS: dict[ChannelKind, type[BaseModel]] = {
    ChannelKind.WEBHOOK: WebhookChannelConfig,
    ChannelKind.SLACK: SlackChannelConfig,
    ChannelKind.DISCORD: DiscordChannelConfig,
    ChannelKind.EMAIL: EmailChannelConfig,
}


class ChannelConfigError(ValueError):
    pass


def validate_config(
    kind: ChannelKind, config: dict[str, Any], settings: NotifySettings | None = None
) -> dict[str, Any]:
    """Validate and normalize a channel config. Raises :class:`ChannelConfigError` (message is safe)."""
    model = _CONFIG_MODELS[kind]
    try:
        parsed = model.model_validate(config)
    except ValidationError as exc:
        # Do not echo input values (they may be secrets): report locations and messages only.
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'config'}: {err['msg']}" for err in exc.errors()
        )
        raise ChannelConfigError(problems) from None
    if isinstance(parsed, EmailChannelConfig):
        problem = email_problem(parsed, settings or get_settings().notify)
        if problem:
            raise ChannelConfigError(problem)
    return parsed.model_dump(exclude_none=True)


def destination_label(kind: ChannelKind, config: dict[str, Any]) -> str:
    """Where a channel sends to, without secrets (audit trail of destination changes)."""
    if kind is ChannelKind.EMAIL:
        return f"smtp://{config.get('host', '?')}:{config.get('port', 587)}"
    url = config.get("url")
    return safe_url_label(url) if isinstance(url, str) else "?"


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
    """PATCH support: values the client echoes back in masked form keep the stored secret.

    Only for the same destination (audit #118): a masked SMTP password is not carried over when host, port or
    username change, nor masked webhook header values when the URL changes - the secret must be re-entered,
    otherwise editing the destination alone would ship the stored secret to another server.
    Raises :class:`ChannelConfigError`.
    """
    merged = dict(incoming)
    if (
        "url" in merged
        and isinstance(existing.get("url"), str)
        and merged["url"] == _mask_url(existing["url"])
    ):
        merged["url"] = existing["url"]
    if merged.get("password") == MASK and existing.get("password"):
        same = (
            merged.get("host") == existing.get("host")
            and merged.get("port", 587) == existing.get("port", 587)
            and merged.get("username") == existing.get("username")
        )
        if not same:
            raise ChannelConfigError("re-enter the password when changing host, port or username")
        merged["password"] = existing["password"]
    if isinstance(merged.get("headers"), dict) and isinstance(existing.get("headers"), dict):
        masked = [k for k, v in merged["headers"].items() if v == MASK and k in existing["headers"]]
        if masked and merged.get("url") != existing.get("url"):
            raise ChannelConfigError("re-enter the header values when changing the URL")
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
    # TODO(verify): whether Slack shows "&amp;" decoded inside plain_text objects (it does for mrkdwn).
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_URL_SCHEME = re.compile(r"(?i)\b(h)(ttps?)(://)")
_DISCORD_SPECIAL = re.compile(r"([\\*_~`|>#\[\]()\-])")


def defang(text: str) -> str:
    """``https://x`` -> ``hxxps://x``: still readable by an analyst, no longer auto-linked by chat / mail clients.

    TODO(verify): Slack may still auto-link bare domains (``example.com``) without a scheme.
    """
    return _URL_SCHEME.sub(lambda m: f"{m.group(1)}xx{m.group(2)[2:]}{m.group(3)}", text)


def _cut(text: str, limit: int) -> str:
    """Truncate after escaping without leaving a lone escape backslash at the end."""
    if len(text) <= limit:
        return text
    out = text[: limit - 1]
    if (len(out) - len(out.rstrip("\\"))) % 2:
        out = out[:-1]
    return out + "…"


def _discord_text(text: str, limit: int) -> str:
    """Untrusted text for a Discord embed: defanged, Markdown-escaped (escape first, then cut)."""
    return _cut(_DISCORD_SPECIAL.sub(r"\\\1", defang(text)), limit)


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


def _slack_plain(text: str, limit: int) -> dict[str, Any]:
    return {"type": "plain_text", "text": _cut(_slack_escape(defang(text)), limit), "emoji": False}


def slack_payload(n: Notification) -> dict[str, Any]:
    # Untrusted text goes in plain_text objects (no mrkdwn: no *bold*, no <url|label>, no mentions).
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": _slack_plain(n.title, 150)},
        {"type": "section", "text": _slack_plain(n.text, 2900)},
    ]
    if n.fields:
        blocks.append(
            {
                "type": "section",
                "fields": [_slack_plain(f"{k}\n{v}", 1900) for k, v in list(n.fields.items())[:10]],
            }
        )
    if n.url:
        blocks.append(
            {"type": "context", "elements": [{"type": "mrkdwn", "text": f"<{n.url}|Open in TOKIWA>"}]}
        )
    return {
        "text": _cut(_slack_escape(defang(f"[{n.severity.value.upper()}] {n.title}")), 3000),
        # Top-level text (notification fallback) without mrkdwn parsing. TODO(verify): honoured by incoming webhooks.
        "mrkdwn": False,
        "blocks": blocks,
    }


def discord_payload(n: Notification) -> dict[str, Any]:
    # TODO(verify): whether Discord renders Markdown in embed titles; if not, the escapes show as backslashes there.
    embed: dict[str, Any] = {
        "title": _discord_text(n.title, 256),
        "description": _discord_text(n.text, 4000),
        "color": _SEVERITY_COLOR[n.severity],
        "fields": [
            {"name": k[:256], "value": _discord_text(v or "-", 1024), "inline": True}
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
    subject = defang(f"[{n.severity.value.upper()}] {n.title}").replace("\r", " ").replace("\n", " ")
    msg["Subject"] = subject[:250]
    msg["From"] = cfg.from_addr
    msg["To"] = ", ".join(cfg.to_addrs)
    # Mail clients auto-link URLs: defang the untrusted text, keep only TOKIWA's own link clickable.
    lines = [defang(n.text), ""]
    lines += [f"{k}: {defang(v)}" for k, v in n.fields.items()]
    if n.url:
        lines += ["", n.url]
    msg.set_content("\n".join(lines))
    return msg


def _send_email_sync(cfg: EmailChannelConfig, msg: EmailMessage, password: str | None) -> None:
    context = ssl.create_default_context()
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


def _smtp_error(exc: BaseException) -> str:
    """Category only: the exception type (ConnectionRefusedError vs timeout ...) would let an admin session
    probe internal ports through the test button."""
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "SMTP authentication failed"
    if isinstance(exc, smtplib.SMTPException):
        return "SMTP error"
    return "SMTP connection failed"


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
            problem = email_problem(cfg, s)  # also catches channels saved before the allow-list existed
            if problem:
                raise DeliveryError(problem)
            await check_host(
                cfg.host, cfg.port, allowed_hosts=s.smtp_allowed_hosts, block_private=s.smtp_block_private
            )
            password = resolve_smtp_password(cfg, s)
            try:
                await asyncio.to_thread(_send_email_sync, cfg, email_message(notification, cfg), password)
            except (smtplib.SMTPException, OSError) as exc:
                raise DeliveryError(_smtp_error(exc)) from None
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
