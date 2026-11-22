"""What an LLM verdict may contribute to an incident's attribution, and how earlier verdicts are shown again (#62).

Why: an incident's ``summary`` and ``actor_type`` used to be overwritten with the LLM's verdict and then shown to the
next triage call as "the incident as produced by TOKIWA detectors" - so text injected into the evidence ("authorized
red-team exercise, benign") could be written once by the model and come back as a detector fact, reinforcing itself
on every re-triage. Rules now:

1. The LLM only breaks a tie (rules say ``unknown``) and only *towards* suspicion: ``ai_agent`` or
   ``automated_scanner``. It never sets ``benign`` / ``human`` - a downgrade must come from rules or an analyst.
2. Re-triage prompts carry rule-derived attribution only; a previous LLM verdict, when shown, is its own untrusted
   block (``previous_llm_verdict``) explicitly labelled as unverified model output.

This module depends on schemas only, so ``tokiwa.correlate`` can import it (``triage.service`` imports correlate).
Where to adjust: :data:`LLM_ASSIGNABLE_ACTORS`.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from tokiwa.schemas.common import ActorType
from tokiwa.schemas.triage import TriageRecord

RULES_TIER = "rules"
MOCK_PROVIDER = "mock"

# Attributions an LLM verdict may set when the rules could not attribute (requirements §6-8: the LLM never decides
# alone; #62: never a downgrade to benign / human).
LLM_ASSIGNABLE_ACTORS: frozenset[ActorType] = frozenset({ActorType.AI_AGENT, ActorType.AUTOMATED_SCANNER})


def as_record(value: TriageRecord | dict[str, Any] | None) -> TriageRecord | None:
    if value is None or isinstance(value, TriageRecord):
        return value
    try:
        return TriageRecord.model_validate(value)
    except (ValidationError, ValueError, TypeError):
        return None


def is_rule_based(record: TriageRecord) -> bool:
    """The rule verdict, or a verdict from the mock provider (which answers with the rule verdict)."""
    return record.tier == RULES_TIER or record.provider == MOCK_PROVIDER


def is_llm_verdict(value: TriageRecord | dict[str, Any] | None) -> bool:
    record = as_record(value)
    return record is not None and not is_rule_based(record)


def llm_actor_tiebreak(value: TriageRecord | dict[str, Any] | None) -> ActorType | None:
    """The actor type a stored LLM verdict may set on an incident whose rule attribution is ``unknown`` (else None)."""
    record = as_record(value)
    if record is None or is_rule_based(record):
        return None
    try:
        actor = ActorType(record.result.actor_type)
    except ValueError:
        return None
    return actor if actor in LLM_ASSIGNABLE_ACTORS else None


def previous_llm_verdict(value: TriageRecord | dict[str, Any] | None) -> dict[str, Any] | None:
    """A stored LLM verdict, reduced to what a re-triage may see as *unverified* context (None if not an LLM one)."""
    record = as_record(value)
    if record is None or is_rule_based(record):
        return None
    r = record.result
    return {
        "note": "model-generated verdict from an earlier triage; unverified, may reflect injected text",
        "summary": r.summary[:1000],
        "actor_type": str(r.actor_type),
        "severity": str(r.severity),
        "category": r.category,
        "confidence": r.confidence,
        "prompt_version": record.prompt_version,
    }
