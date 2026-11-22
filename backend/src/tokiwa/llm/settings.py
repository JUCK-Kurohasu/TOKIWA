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
- **API keys are bound to their endpoint (#98).** A runtime ``*_base_url`` must pass
  :func:`tokiwa.llm.endpoints.validate_runtime_base_url` (https, http only for loopback, no link-local / metadata).
  Changing it drops the stored key for that provider unless a new key comes in the same update, and while a runtime
  URL is set only a key entered *for that URL* is used - the static / ``ANTHROPIC_API_KEY`` key is blanked, so a
  hijacked admin session cannot make TOKIWA send an existing key to a host of its choosing. The binding is kept in
  the overlay under ``_key_bound_to`` (key field -> URL it was entered for, ``""`` = the static endpoint). Rows from
  before this rule (a runtime URL + key without a binding) are treated fail-closed: the key is ignored until re-entered.
"""

from __future__ import annotations

import logging
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

from tokiwa.config import LLMSettings, Settings, anthropic_api_key, get_settings
from tokiwa.llm.endpoints import validate_runtime_base_url
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
# Which endpoint each stored key belongs to (#98).
KEY_URL_FIELDS: dict[str, str] = {
    "anthropic_api_key": "anthropic_base_url",
    "openai_api_key": "openai_base_url",
}
KEY_BINDINGS = "_key_bound_to"  # internal overlay entry, never an LLMSettings field
_PROVIDER_OF_KEY = {"anthropic_api_key": "anthropic", "openai_api_key": "openai_compat"}

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
    def _endpoint_url(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        return validate_runtime_base_url(v)


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
    # Providers whose endpoint was changed at runtime but have no key entered for that endpoint (#98): the key must be
    # entered again (static / env keys are never sent to a runtime-set endpoint).
    api_key_rebind_required: list[str] = Field(default_factory=list)
    # Configured models without a price: their calls are charged at the highest known rates (#35). Fix: llm.pricing.
    unpriced_models: list[str] = Field(default_factory=list)


def _validate_with(base: LLMSettings, extra: dict[str, Any]) -> LLMSettings:
    data = base.model_dump()
    # model_dump keeps SecretStr objects; LLMSettings accepts them back.
    data.update(extra)
    return LLMSettings.model_validate(data)


def clean_overlay(base: LLMSettings, overlay: dict[str, Any]) -> dict[str, Any]:
    """Drop unknown keys and values that do not validate (logged); keys not bound to their endpoint are dropped.

    URLs are re-checked with the runtime rules, so a row stored before #98 (``http://attacker``, ``169.254...``) or
    written to the DB directly is ignored instead of applied.
    """
    allowed = EDITABLE_FIELDS | SECRET_FIELDS
    clean: dict[str, Any] = {}
    for key, value in overlay.items():
        if key == KEY_BINDINGS:
            continue
        if key not in allowed:
            log.warning("ignoring unknown llm.config key %r", key)
            continue
        if value is None or (key in SECRET_FIELDS and value == ""):
            continue
        try:
            if key in _URL_FIELDS:
                value = validate_runtime_base_url(str(value))
            _validate_with(base, {key: value})
        except (ValidationError, ValueError) as exc:
            reason = str(exc).splitlines()[0] if key in _URL_FIELDS else "invalid value"
            log.warning("ignoring stored llm.config value for %r (%s)", key, reason)
            continue
        clean[key] = value
    bindings = overlay.get(KEY_BINDINGS)
    bindings = bindings if isinstance(bindings, dict) else {}
    for key_field, url_field in KEY_URL_FIELDS.items():
        if key_field not in clean:
            continue
        url = clean.get(url_field)
        bound = bindings.get(key_field)
        # Runtime URL: the key must have been entered for exactly that URL. Static URL: a key entered for the static
        # endpoint ("") or a pre-#98 row without any binding (None) - never a key entered for some other runtime URL.
        if (bound != url) if url is not None else (bound not in (None, "")):
            log.warning(
                "ignoring stored %s: it was not entered for the configured endpoint; enter the key again",
                key_field,
            )
            clean.pop(key_field)
    return clean


def _effective_overlay(clean: dict[str, Any]) -> dict[str, Any]:
    """``clean`` plus blank keys for providers whose endpoint is set at runtime without a key bound to it.

    The blank ("" -> no key) also disables the static key and the ``ANTHROPIC_API_KEY`` fallback for that provider.
    """
    out = dict(clean)
    for key_field, url_field in KEY_URL_FIELDS.items():
        if url_field in clean and key_field not in clean:
            out[key_field] = SecretStr("")
    return out


def rebind_required(clean: dict[str, Any]) -> list[str]:
    """Providers whose runtime endpoint has no key entered for it."""
    return [
        _PROVIDER_OF_KEY[k]
        for k, url_field in KEY_URL_FIELDS.items()
        if url_field in clean and k not in clean
    ]


def apply_overlay(base: Settings, overlay: dict[str, Any]) -> Settings:
    """Static settings + runtime overlay -> effective settings (pure function)."""
    clean = clean_overlay(base.llm, overlay)
    if not clean:
        return base
    return base.model_copy(update={"llm": _validate_with(base.llm, _effective_overlay(clean))})


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
    before = dict(overlay)
    raw_bindings = overlay.pop(KEY_BINDINGS, None)
    bindings: dict[str, str] = dict(raw_bindings) if isinstance(raw_bindings, dict) else {}
    changes: dict[str, str] = {}
    keys_set: set[str] = set()
    for key in update.model_fields_set:
        value = getattr(update, key)
        if isinstance(value, SecretStr):
            value = value.get_secret_value()
        if value is None or (key in SECRET_FIELDS and value == ""):
            if key in overlay:
                overlay.pop(key)
                changes[key] = "cleared" if key in SECRET_FIELDS else "reverted"
            if key in SECRET_FIELDS:
                bindings.pop(key, None)
            continue
        overlay[key] = value
        if key in SECRET_FIELDS:
            keys_set.add(key)
            changes[key] = "set"
        elif key in _URL_FIELDS:
            changes[key] = mask_url(str(value)) or ""
        else:
            changes[key] = repr(value)
    # Bind keys to endpoints (#98): a changed endpoint invalidates the stored key unless a new one came with it.
    for key_field, url_field in KEY_URL_FIELDS.items():
        if key_field in keys_set:
            bindings[key_field] = overlay.get(url_field) or ""
        elif before.get(url_field) != overlay.get(url_field):
            if key_field in overlay:
                overlay.pop(key_field)
                changes[key_field] = "cleared (endpoint changed; enter the key again)"
            bindings.pop(key_field, None)
    if bindings:
        overlay[KEY_BINDINGS] = bindings
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
        api_key_rebind_required=rebind_required(overlay),
        unpriced_models=gw.unpriced_models(),
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
