"""Runtime LLM configuration (UI-editable overlay). OWNER: llm module.

Static configuration comes from env / ``tokiwa.yaml`` (:class:`tokiwa.config.LLMSettings`). Operators can override a
subset of it from the UI; those overrides are stored as a JSON object in ``settings_kv["llm.config"]`` and overlaid
on the static settings to build the process-wide :class:`~tokiwa.llm.gateway.LLMGateway`.

- Only keys in :data:`EDITABLE_FIELDS` / :data:`SECRET_FIELDS` are honoured; unknown or invalid stored values are
  ignored (logged) so a bad row can never brick startup.
- ``null`` in an update means "remove the override" (revert to the static value).
- API keys are write-only: they may be stored in the overlay (plaintext in the DB - prefer env vars; see
  docs/security/llm-safety.md) but are never returned by :func:`config_view` or written to the audit log.
- Other modules that need runtime LLM values (e.g. ``output_language``) should read ``get_gateway().llm``
  (or :func:`effective_llm_settings`), not ``get_settings().llm``.
"""

from __future__ import annotations

import logging
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

from tokiwa.config import LLMSettings, Settings, anthropic_api_key, get_settings
from tokiwa.llm.gateway import LLMGateway, get_gateway, set_gateway
from tokiwa.runtime import on_startup
from tokiwa.settings_store import get_setting, set_setting

log = logging.getLogger(__name__)

LLM_CONFIG_KEY = "llm.config"

EDITABLE_FIELDS: frozenset[str] = frozenset(
    {
        "provider",
        "model_fast",
        "model_deep",
        "effort_fast",
        "effort_deep",
        "max_output_tokens",
        "max_input_tokens_per_call",
        "daily_budget_usd",
        "enable_fallbacks",
        "prompt_cache",
        "output_language",
        "request_timeout_seconds",
        "anthropic_base_url",
        "openai_base_url",
    }
)
SECRET_FIELDS: frozenset[str] = frozenset({"anthropic_api_key", "openai_api_key"})

_URL_FIELDS: frozenset[str] = frozenset({"anthropic_base_url", "openai_base_url"})

Effort = Literal["low", "medium", "high", "xhigh", "max"]


def mask_url(url: str | None) -> str | None:
    """Hide ``user:password@`` in a URL before showing or auditing it."""
    if not url:
        return url
    parts = urlsplit(url)
    if "@" not in parts.netloc:
        return url
    host = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, f"[REDACTED]@{host}", parts.path, parts.query, parts.fragment))


class LLMConfigUpdate(BaseModel):
    """``PUT /llm/config`` body. Omitted fields are unchanged; ``null`` reverts a field to its static value."""

    model_config = ConfigDict(extra="forbid")

    provider: Literal["auto", "anthropic", "openai_compat", "mock"] | None = None
    model_fast: str | None = Field(default=None, min_length=1, max_length=64)
    model_deep: str | None = Field(default=None, min_length=1, max_length=64)
    effort_fast: Effort | None = None
    effort_deep: Effort | None = None
    max_output_tokens: int | None = Field(default=None, ge=256, le=128_000)
    max_input_tokens_per_call: int | None = Field(default=None, ge=1_000, le=1_000_000)
    daily_budget_usd: float | None = Field(default=None, ge=0, le=100_000)
    enable_fallbacks: bool | None = None
    prompt_cache: bool | None = None
    output_language: Literal["ja", "en"] | None = None
    request_timeout_seconds: float | None = Field(default=None, gt=0, le=3_600)
    anthropic_base_url: str | None = Field(default=None, max_length=512)
    openai_base_url: str | None = Field(default=None, max_length=512)
    # Write-only secrets. "" or null clears the override.
    anthropic_api_key: SecretStr | None = None
    openai_api_key: SecretStr | None = None

    @field_validator("anthropic_base_url", "openai_base_url")
    @classmethod
    def _http_url(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if not v.startswith(("http://", "https://")):
            raise ValueError("must start with http:// or https://")
        return v.rstrip("/")


class LLMConfigOut(BaseModel):
    """``GET /llm/config``. Never contains API keys - only whether one is configured."""

    provider: str  # configured setting: auto | anthropic | openai_compat | mock
    active_provider: str  # provider actually in use (auto resolved)
    available: bool
    model_fast: str
    model_deep: str
    effort_fast: str
    effort_deep: str
    daily_budget_usd: float
    spent_today_usd: float
    output_language: str
    enable_fallbacks: bool
    prompt_cache: bool
    max_output_tokens: int
    max_input_tokens_per_call: int
    request_timeout_seconds: float
    anthropic_base_url: str | None = None
    openai_base_url: str | None = None
    anthropic_api_key_set: bool = False
    openai_api_key_set: bool = False
    overridden: list[str] = Field(default_factory=list)  # fields currently set by the runtime overlay


def _validate_with(base: LLMSettings, extra: dict[str, Any]) -> LLMSettings:
    data = base.model_dump()
    # model_dump keeps SecretStr objects; LLMSettings accepts them back.
    data.update(extra)
    return LLMSettings.model_validate(data)


def clean_overlay(base: LLMSettings, overlay: dict[str, Any]) -> dict[str, Any]:
    """Drop unknown keys and values that do not validate against :class:`LLMSettings` (logged)."""
    allowed = EDITABLE_FIELDS | SECRET_FIELDS
    clean: dict[str, Any] = {}
    for key, value in overlay.items():
        if key not in allowed:
            log.warning("ignoring unknown llm.config key %r", key)
            continue
        if value is None or (key in SECRET_FIELDS and value == ""):
            continue
        try:
            _validate_with(base, {key: value})
        except ValidationError:
            log.warning("ignoring invalid llm.config value for %r", key)
            continue
        clean[key] = value
    return clean


def apply_overlay(base: Settings, overlay: dict[str, Any]) -> Settings:
    """Static settings + runtime overlay -> effective settings (pure function)."""
    clean = clean_overlay(base.llm, overlay)
    if not clean:
        return base
    return base.model_copy(update={"llm": _validate_with(base.llm, clean)})


async def load_overlay() -> dict[str, Any]:
    return await get_setting(LLM_CONFIG_KEY, {})


async def effective_settings() -> Settings:
    return apply_overlay(get_settings(), await load_overlay())


def effective_llm_settings() -> LLMSettings:
    """Runtime LLM settings as used by the current gateway (sync; no DB access)."""
    return get_gateway().llm


async def rebuild_gateway() -> LLMGateway:
    gateway = LLMGateway(settings=await effective_settings())
    set_gateway(gateway)
    log.info("LLM gateway rebuilt (provider=%s)", gateway.provider.name)
    return gateway


async def update_config(update: LLMConfigUpdate) -> tuple[LLMGateway, dict[str, str]]:
    """Merge ``update`` into the stored overlay, persist it and rebuild the gateway.

    Returns the new gateway and an audit-safe summary of the change (secrets reported as "set"/"cleared").
    """
    overlay = await load_overlay()
    changes: dict[str, str] = {}
    for key in update.model_fields_set:
        value = getattr(update, key)
        if isinstance(value, SecretStr):
            value = value.get_secret_value()
        if value is None or (key in SECRET_FIELDS and value == ""):
            if key in overlay:
                overlay.pop(key)
                changes[key] = "cleared" if key in SECRET_FIELDS else "reverted"
            continue
        overlay[key] = value
        if key in SECRET_FIELDS:
            changes[key] = "set"
        elif key in _URL_FIELDS:
            changes[key] = mask_url(str(value)) or ""
        else:
            changes[key] = repr(value)
    # Input was validated by LLMConfigUpdate; clean_overlay additionally guards against stale/corrupt rows.
    await set_setting(LLM_CONFIG_KEY, overlay)
    return await rebuild_gateway(), changes


async def config_view(gateway: LLMGateway | None = None) -> LLMConfigOut:
    gw = gateway or get_gateway()
    llm = gw.llm
    overlay = clean_overlay(get_settings().llm, await load_overlay())
    try:
        spent = await gw.spent_today_usd()
    except Exception:
        log.exception("failed to compute LLM spend")
        spent = 0.0
    openai_key = llm.openai_api_key
    return LLMConfigOut(
        provider=llm.provider,
        active_provider=gw.provider.name,
        available=gw.provider.available(),
        model_fast=llm.model_fast,
        model_deep=llm.model_deep,
        effort_fast=llm.effort_fast,
        effort_deep=llm.effort_deep,
        daily_budget_usd=llm.daily_budget_usd,
        spent_today_usd=round(spent, 6),
        output_language=llm.output_language,
        enable_fallbacks=llm.enable_fallbacks,
        prompt_cache=llm.prompt_cache,
        max_output_tokens=llm.max_output_tokens,
        max_input_tokens_per_call=llm.max_input_tokens_per_call,
        request_timeout_seconds=llm.request_timeout_seconds,
        anthropic_base_url=mask_url(llm.anthropic_base_url),
        openai_base_url=mask_url(llm.openai_base_url),
        anthropic_api_key_set=anthropic_api_key(gw.settings) is not None,
        openai_api_key_set=bool(openai_key is not None and openai_key.get_secret_value()),
        overridden=sorted(overlay),
    )


@on_startup
async def apply_stored_config() -> None:
    """Apply the stored overlay at startup.

    Only rebuilds when an overlay exists, so a gateway installed explicitly (tests, embedding) is left alone
    otherwise - ``get_gateway()`` already builds one from static settings lazily.
    """
    try:
        overlay = await load_overlay()
    except Exception:
        log.exception("could not read %s; using static LLM settings", LLM_CONFIG_KEY)
        return
    if overlay:
        await rebuild_gateway()
