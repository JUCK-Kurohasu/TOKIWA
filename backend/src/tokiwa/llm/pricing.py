"""Token pricing (USD per 1M tokens). Override/extend via ``llm.pricing`` in config.

Values from the Anthropic pricing table as of 2026-10 (verify before relying on cost reports:
https://platform.claude.com/docs/en/about-claude/pricing). Cache reads ~0.1x input, cache writes ~1.25x input
(5-minute TTL). Web search is billed per 1K searches.

Why fail-closed (audit #35): the daily budget (``llm.daily_budget_usd``) is enforced on the *recorded* cost. A
model missing from this table used to cost $0, so the budget never tripped for it - a selectable built-in model,
a dated snapshot ID, a hand-typed proxy ID or a server-side fallback answer could all spend without limit and the
budget meter kept showing $0. Now:

1. the model ID is looked up as given, then *normalized* (platform prefix such as ``anthropic.`` /
   ``us.anthropic.`` removed, snapshot suffixes ``-YYYYMMDD`` / ``@YYYYMMDD`` / ``-vN[:N]`` / ``-latest`` removed);
   only snapshot-shaped remainders are stripped, so an unknown *family member* (``claude-opus-5-9``) is not priced
   as a guess from a sibling;
2. anything still unknown is charged at the **highest known rates** (per token kind, over the built-in table and
   ``llm.pricing``) and recorded with ``cost_basis="unpriced"`` so the Usage page can count such calls.

Free local models (Ollama / vLLM through ``openai_compat``) therefore need an explicit zero price in ``llm.pricing``
(``{"llama3.1:8b": {"input": 0, "output": 0}}``) or ``llm.daily_budget_usd: 0`` (no budget). Where to adjust:
:data:`DEFAULT_PRICING`, ``llm.pricing``.
"""

from __future__ import annotations

import re
from enum import StrEnum

from tokiwa.llm.base import LLMUsage

DEFAULT_PRICING: dict[str, dict[str, float]] = {
    "claude-fable-5-1": {"input": 10.0, "output": 50.0},
    "claude-opus-5-5": {"input": 4.0, "output": 20.0, "cache_read": 0.20},
    "claude-opus-5": {"input": 5.0, "output": 25.0},
    # Server-side fallback targets (fallbacks="default" may serve a refused request with these).
    "claude-opus-4-8": {"input": 5.0, "output": 25.0},
    "claude-opus-4-7": {"input": 5.0, "output": 25.0},
    # TODO(verify): the claude-api reference model table (cached 2026-11-03) lists Sonnet 5.5 cache reads at $0.10;
    # kept at the older 0.20 (over-estimating is the safe direction for the budget) until checked on the pricing page.
    "claude-sonnet-5-5": {"input": 2.0, "output": 10.0, "cache_read": 0.20},
    "claude-sonnet-5": {"input": 2.0, "output": 10.0},
    "claude-haiku-5-5": {"input": 0.10, "output": 0.50},
    "claude-haiku-4-5": {"input": 1.0, "output": 5.0},
    # Added for the built-in model list (llm/models.py) so every selectable model has a price (#35).
    # TODO(verify): taken from the claude-api reference model table (cached 2026-11-03), not yet checked against
    # https://platform.claude.com/docs/en/about-claude/pricing.
    "claude-fable-5": {"input": 10.0, "output": 50.0},
    "claude-opus-4-6": {"input": 5.0, "output": 25.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
}

WEB_SEARCH_USD_PER_1K = 10.0


class CostBasis(StrEnum):
    """How a call's ``cost_usd`` was obtained (``llm_calls.cost_basis``)."""

    TABLE = "table"  # the model ID is in the table (built-in or llm.pricing)
    SNAPSHOT = (
        "snapshot"  # a normalized form of the ID (snapshot suffix / platform prefix removed) is in the table
    )
    UNPRICED = "unpriced"  # not in the table: estimated at the highest known rates (fail-closed)


# Bedrock-style prefixes ("anthropic.", "us.anthropic.", "global.anthropic.") and "anthropic/" (proxies, gateways).
_PLATFORM_PREFIX = re.compile(r"^(?:[a-z]{2,8}\.)?anthropic[./]")
# Snapshot / version suffixes only. Deliberately not a generic "-anything" prefix match (see module docstring).
_SNAPSHOT_SUFFIX = re.compile(r"(?:-\d{8}|@\d{8}|-v\d+(?::\d+)?|-latest)$")


def normalize_model(model: str) -> str:
    """Canonical catalog ID for pricing: lowercase, platform prefix and snapshot/version suffixes removed.

    ``anthropic.claude-opus-5-5-20261001-v1:0`` -> ``claude-opus-5-5``; ``claude-opus-4-5@20251101`` ->
    ``claude-opus-4-5``. Unknown shapes are returned lowercased and otherwise unchanged.
    """
    m = model.strip().lower()
    m = _PLATFORM_PREFIX.sub("", m)
    while True:
        stripped = _SNAPSHOT_SUFFIX.sub("", m)
        if stripped == m or not stripped:
            return m
        m = stripped


def _table(overrides: dict[str, dict[str, float]] | None) -> dict[str, dict[str, float]]:
    return {**DEFAULT_PRICING, **(overrides or {})}


def unpriced_rates(overrides: dict[str, dict[str, float]] | None = None) -> dict[str, float]:
    """The highest known rate per token kind: what an unknown model is charged (fail-closed)."""
    table = _table(overrides)
    inp = max((float(p.get("input", 0.0)) for p in table.values()), default=0.0)
    out = max((float(p.get("output", 0.0)) for p in table.values()), default=0.0)
    cache_read = max(
        (float(p.get("cache_read", p.get("input", 0.0) * 0.1)) for p in table.values()), default=0.0
    )
    cache_write = max(
        (float(p.get("cache_write", p.get("input", 0.0) * 1.25)) for p in table.values()), default=0.0
    )
    return {"input": inp, "output": out, "cache_read": cache_read, "cache_write": cache_write}


def price_for(
    model: str, overrides: dict[str, dict[str, float]] | None = None
) -> tuple[dict[str, float], CostBasis]:
    """Rates used for ``model`` and where they came from. Never returns "free" for an unknown model."""
    table = _table(overrides)
    if model in table:
        return table[model], CostBasis.TABLE
    normalized_table: dict[str, dict[str, float]] = {}
    # llm.pricing entries are merged last so an operator's entry wins over a built-in one with the same canonical ID.
    for key, rates in table.items():
        normalized_table[normalize_model(key)] = rates
    canonical = normalize_model(model)
    if canonical in normalized_table:
        return normalized_table[canonical], CostBasis.SNAPSHOT
    return unpriced_rates(overrides), CostBasis.UNPRICED


def is_priced(model: str, overrides: dict[str, dict[str, float]] | None = None) -> bool:
    return price_for(model, overrides)[1] != CostBasis.UNPRICED


def estimate(
    model: str, usage: LLMUsage, overrides: dict[str, dict[str, float]] | None = None
) -> tuple[float, CostBasis]:
    p, basis = price_for(model, overrides)
    inp = p.get("input", 0.0)
    cost = (
        usage.input_tokens * inp
        + usage.output_tokens * p.get("output", 0.0)
        + usage.cache_read_tokens * p.get("cache_read", inp * 0.1)
        + usage.cache_write_tokens * p.get("cache_write", inp * 1.25)
    ) / 1_000_000
    cost += usage.web_search_requests * WEB_SEARCH_USD_PER_1K / 1000
    return round(cost, 6), basis


def estimate_cost(model: str, usage: LLMUsage, overrides: dict[str, dict[str, float]] | None = None) -> float:
    return estimate(model, usage, overrides)[0]
