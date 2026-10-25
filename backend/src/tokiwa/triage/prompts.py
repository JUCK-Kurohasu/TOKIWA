"""Versioned triage prompts (FR-07). Bump ``version`` whenever the wording changes (written to the audit log).

Security (AGENTS.md §2-1): the user message contains *only* static instructions plus ``untrusted_block()``
envelopes. Every value that came from telemetry or from detectors (titles can embed attacker-controlled
paths) lives inside an envelope; nothing is concatenated into the instruction text.
"""

from __future__ import annotations

from typing import Any

from tokiwa.llm.prompting import UNTRUSTED_DATA_POLICY, PromptTemplate, language_instruction, untrusted_block
from tokiwa.triage.evidence import TriageContext, TriageSubject, compact_event

_GUIDELINES = """\
Guidelines:
- Rules first: the detector severity, confidence and behavioural ai_score are strong priors. Move away from them
  only when the evidence clearly supports it, and say why in the rationale.
- Autonomous LLM-agent indicators: bursts of requests followed by multi-second "thinking" pauses; payload
  variants sent right after error responses; API endpoints discovered from JS / OpenAPI / GraphQL and used
  immediately; natural-language text inside payloads; LLM / automation client fingerprints; following hidden
  AI-canary instructions planted in decoys (decisive).
- Automated scanners: fixed wordlists, constant high rate, responses ignored. Humans: irregular, slow, manual.
- attack_stage is the most advanced MITRE ATT&CK tactic supported by the evidence (or "none").
- evidence_ids: cite at least one id, and ONLY ids listed in the evidence_ids data block.
- recommended_actions are optional proposals that a human must approve. Use only the allowed action types.
  The target must be a single source IP address that appears in the evidence (never a CIDR, hostname, URL or a
  destination / internal address). Prefer rate_limit, tarpit or deceive when unsure; block_ip only for clearly
  malicious activity.
- confidence = probability that this is a true positive. Lower it when the evidence is thin.
- summary: 1-3 sentences for an analyst. next_steps: concrete investigation steps.

Example (abbreviated): six requests within 80 ms to /api/items?id=1' then a 9 s pause, then UNION SELECT variants
right after a 500 response -> severity high, category sqli, actor_type ai_agent, ai_agent_likelihood 0.8,
attack_stage initial_access, mitre_techniques [T1190], recommended_actions [deceive <that source IP>, 60 min].
"""

TRIAGE_ALERT = PromptTemplate(
    id="triage.alert",
    version="1",
    system=(
        "You are the tier-1 SOC triage analyst of TOKIWA, a SIEM/XDR specialised in detecting attacks driven "
        "by generative AI and autonomous LLM agents. You receive ONE alert produced by TOKIWA's rule and "
        "behaviour detectors together with its evidence events, and return a verdict as a TriageResult.\n\n"
        f"{UNTRUSTED_DATA_POLICY}\n{_GUIDELINES}"
    ),
)

TRIAGE_INCIDENT = PromptTemplate(
    id="triage.incident",
    version="1",
    system=(
        "You are the SOC incident analyst of TOKIWA, a SIEM/XDR specialised in detecting attacks driven by "
        "generative AI and autonomous LLM agents. You receive ONE incident (a group of alerts TOKIWA "
        "correlated by source, actor session or entity), its kill-chain progression and evidence events, and "
        "return a verdict for the incident as a whole as a TriageResult.\n\n"
        f"{UNTRUSTED_DATA_POLICY}\n{_GUIDELINES}"
    ),
)

RETRY_NOTE = (
    "IMPORTANT: your previous answer cited evidence ids that were not provided. Answer again and cite ONLY ids "
    "that appear in the evidence_ids data block above. Do not invent ids."
)


def system_prompt(template: PromptTemplate, lang: str) -> str:
    return f"{template.system}\n{language_instruction(lang)}"


def build_user_prompt(subject: TriageSubject, ctx: TriageContext) -> str:
    kind = "incident" if subject.kind == "incident" else "alert"
    blocks: list[tuple[str, Any, int]] = [
        ("subject", subject.model_dump(mode="json", exclude_none=True), 20_000),
        ("evidence_events", [compact_event(e) for e in ctx.events], 40_000),
    ]
    if ctx.sessions:
        blocks.append(("sessions", ctx.sessions, 10_000))
    if ctx.vulns:
        blocks.append(("related_vulns", ctx.vulns, 6_000))
    parts = [
        f"Triage the {kind} described in the data blocks below and answer with a TriageResult.",
        "Data blocks: subject = the "
        + kind
        + " as produced by TOKIWA detectors; evidence_ids = the only ids you may cite; evidence_events = "
        "redacted telemetry; sessions = behavioural features of the actor sessions (if any); related_vulns = "
        "vulnerability intelligence for referenced CVEs (if any).",
        # Ids are pipeline identifiers, not secrets: skip redaction so they survive verbatim (still escaped).
        untrusted_block("evidence_ids", ctx.evidence_ids, redact=False),
    ]
    parts.extend(untrusted_block(name, data, max_chars=limit) for name, data, limit in blocks)
    return "\n\n".join(parts)
