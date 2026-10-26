"""AI-agent attack attribution (FR-13/14/15) — TOKIWA's core differentiator.

Layout (pure logic here; I/O lives in ``tokiwa.enrich.sessionizer`` and the detectors):

- :mod:`fingerprints`     client fingerprint + UA/header classification (browser / library / AI UA / scanner)
- :mod:`payloads`         payload extraction, attack markers, natural-language score, similarity helpers
- :mod:`recon`            discovery-endpoint catalogue (OpenAPI / GraphQL introspection / MCP / llms.txt ...)
- :mod:`features`         per-request observations and session-level behavioural features (pure functions)
- :mod:`scoring`          explainable weighted-logistic scoring; ALL weights live in that one file
- :mod:`sessions`         bounded in-memory actor-session tracker used by the sessionizer enricher
- :mod:`prompt_injection` prompt-injection / jailbreak patterns for protected LLM apps (ja/en)

Everything in this package is a *hypothesis-driven heuristic*; see docs/detection/ai-attacks.md for the
rationale, the evidence behind each feature and its known limitations.
"""
