"""Model choices for the settings UI. OWNER: llm module.

For Anthropic the choices come from ``GET /v1/models`` (so they match what the configured key can actually use and
stay current without a release). When that is not possible - no key yet, provider is not Anthropic, network or API
error - a built-in list is returned instead and ``source`` says so. A model that is in neither can still be typed in
by hand in the UI (custom endpoints, proxies, brand-new models).

This is metadata, not an LLM call: it spends no tokens, so it is neither budgeted nor written to ``llm_calls``.
"""

from __future__ import annotations

import logging
import time
from typing import Literal

from pydantic import BaseModel

from tokiwa.llm.base import ModelOption

log = logging.getLogger(__name__)

# Successful API listings are cached per gateway (a gateway is rebuilt whenever the key or endpoint changes).
CACHE_TTL_SECONDS = 300.0

# IDs as published in Anthropic's model catalog (no date suffixes). TODO(verify): refresh when new models ship; the
# live list from the API makes this only a fallback.
BUILTIN_ANTHROPIC_MODELS: tuple[ModelOption, ...] = (
    ModelOption(id="claude-fable-5-1", display_name="Claude Fable 5.1"),
    ModelOption(id="claude-opus-5-5", display_name="Claude Opus 5.5"),
    ModelOption(id="claude-sonnet-5-5", display_name="Claude Sonnet 5.5"),
    ModelOption(id="claude-haiku-5-5", display_name="Claude Haiku 5.5"),
    ModelOption(id="claude-fable-5", display_name="Claude Fable 5"),
    ModelOption(id="claude-opus-5", display_name="Claude Opus 5"),
    ModelOption(id="claude-sonnet-5", display_name="Claude Sonnet 5"),
    ModelOption(id="claude-opus-4-8", display_name="Claude Opus 4.8"),
    ModelOption(id="claude-sonnet-4-6", display_name="Claude Sonnet 4.6"),
    ModelOption(id="claude-haiku-4-5", display_name="Claude Haiku 4.5"),
)


class ModelListing(BaseModel):
    source: Literal["api", "builtin"]
    models: list[ModelOption]
    error: str | None = None  # why the API list was not used (never contains secrets)


class ModelListCache:
    def __init__(self) -> None:
        self._value: list[ModelOption] | None = None
        self._at = 0.0

    def get(self) -> list[ModelOption] | None:
        if self._value is not None and time.monotonic() - self._at < CACHE_TTL_SECONDS:
            return self._value
        return None

    def put(self, models: list[ModelOption]) -> None:
        self._value, self._at = models, time.monotonic()


def builtin_listing(error: str | None = None) -> ModelListing:
    return ModelListing(source="builtin", models=list(BUILTIN_ANTHROPIC_MODELS), error=error)
