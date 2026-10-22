"""Token pricing (USD per 1M tokens). Override/extend via ``llm.pricing`` in config.

Values from the Anthropic pricing table as of 2026-10 (verify before relying on cost reports:
https://platform.claude.com/docs/en/about-claude/pricing). Cache reads ~0.1x input, cache writes ~1.25x input
(5-minute TTL). Web search is billed per 1K searches.
"""

from __future__ import annotations

from tokiwa.llm.base import LLMUsage

DEFAULT_PRICING: dict[str, dict[str, float]] = {
    "claude-fable-5-1": {"input": 10.0, "output": 50.0},
    "claude-opus-5-5": {"input": 4.0, "output": 20.0, "cache_read": 0.20},
    "claude-opus-5": {"input": 5.0, "output": 25.0},
    # Server-side fallback targets (fallbacks="default" may serve a refused request with these).
    "claude-opus-4-8": {"input": 5.0, "output": 25.0},
    "claude-opus-4-7": {"input": 5.0, "output": 25.0},
    "claude-sonnet-5-5": {"input": 2.0, "output": 10.0, "cache_read": 0.20},
    "claude-sonnet-5": {"input": 2.0, "output": 10.0},
    "claude-haiku-5-5": {"input": 0.10, "output": 0.50},
    "claude-haiku-4-5": {"input": 1.0, "output": 5.0},
}

WEB_SEARCH_USD_PER_1K = 10.0


def estimate_cost(model: str, usage: LLMUsage, overrides: dict[str, dict[str, float]] | None = None) -> float:
    table = {**DEFAULT_PRICING, **(overrides or {})}
    p = table.get(model)
    if p is None:
        # Unknown / local model: count as free but keep token stats.
        return 0.0
    inp = p["input"]
    cost = (
        usage.input_tokens * inp
        + usage.output_tokens * p["output"]
        + usage.cache_read_tokens * p.get("cache_read", inp * 0.1)
        + usage.cache_write_tokens * p.get("cache_write", inp * 1.25)
    ) / 1_000_000
    cost += usage.web_search_requests * WEB_SEARCH_USD_PER_1K / 1000
    return round(cost, 6)
