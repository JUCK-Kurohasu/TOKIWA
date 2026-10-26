"""``ai.agent_session`` — session-level AI-agent attribution crossed the threshold.

Reads the live session snapshot maintained by the sessionizer enricher (``tokiwa.aidetect.sessions``). Fires once
when the session's (peak) AI score reaches ``detection.ai_agent_threshold`` and again whenever the score rises by
``RISE_DELTA`` (same fingerprint -> the engine bumps the existing alert within the dedup window).
"""

from __future__ import annotations

from tokiwa.aidetect.detectkit import base_entities, clip
from tokiwa.aidetect.sessions import current_tracker
from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import ActorType, Severity
from tokiwa.schemas.events import Event

RISE_DELTA = 0.05
MAX_EVIDENCE = 25
_FEATURE_SUMMARY_KEYS = (
    "n_requests",
    "request_count_total",
    "burst_frac",
    "think_frac",
    "think_gap_median_ms",
    "adaptive_mutations",
    "mutation_chain_max",
    "api_after_discovery_hits",
    "spec_fetches",
    "ai_ecosystem_probes",
    "nl_attack_payloads",
    "attack_families",
    "error_rate",
    "client_family",
    "client_tool",
    "header_anomalies",
    "canary_hits",
)


@register_detector
class AIAgentSessionDetector(Detector):
    id = "ai.agent_session"
    name = "AI agent session"
    description = (
        "Actor session whose behavioural features (burst/think rhythm, adaptive mutation, spec-driven discovery, "
        "natural-language payloads, client fingerprint, AI canary) score above the AI-agent threshold."
    )
    category = AlertCategory.AI_AGENT
    kinds = frozenset()  # HTTP, deception and llm_app events can all move the session score
    mitre = ("T1595",)
    default_severity = Severity.MEDIUM

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        if not event.session_id:
            return []
        tracker = current_tracker()
        s = tracker.get(event.session_id) if tracker is not None else None
        if s is None:
            return []
        threshold = ctx.settings.detection.ai_agent_threshold
        if s.ai_score < threshold and s.classification != ActorType.AI_AGENT:
            return []
        last = ctx.state.get(self.id, s.id)
        if last is not None and s.ai_score < float(last) + RISE_DELTA:
            return []
        ttl = max(3600.0, 2.0 * ctx.settings.detection.session_idle_timeout_seconds)
        ctx.state.set(self.id, s.id, s.ai_score, ttl=ttl)

        f = s.features
        canary = int(f.get("canary_hits", 0) or 0) > 0
        if canary:
            severity = Severity.CRITICAL
        elif s.ai_score >= 0.9:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM
        span = max(1e-6, 1.0 - threshold)
        confidence = min(0.95, 0.6 + 0.35 * max(0.0, s.ai_score - threshold) / span)
        if canary:
            confidence = 0.97
        top = s.indicators[:6]
        reasons = ", ".join(i["en"] for i in top if i.get("direction") == "for")[:300]
        reasons_ja = "、".join(i["ja"] for i in top if i.get("direction") == "for")[:300]
        evidence = list(dict.fromkeys([*list(s.recent_event_ids)[-MAX_EVIDENCE:], event.id]))[-MAX_EVIDENCE:]
        mitre = ["T1595"]
        if int(f.get("attack_requests", 0) or 0) > 0:
            mitre.append("T1190")
        entities = base_entities(event)
        entities.pop("path", None)
        entities.update({"session_id": s.id, "client_fingerprint": s.fp.fingerprint})
        if s.user_agent:
            entities["user_agent"] = clip(s.user_agent)
        return [
            self.draft(
                event,
                title=f"AI agent session from {s.source_ip} (score {s.ai_score:.2f})",
                description=(
                    f"Session {s.id} is attributed to an autonomous LLM agent. Indicators: {reasons or 'n/a'}. / "
                    f"AI エージェントと推定されるセッション。根拠: {reasons_ja or 'なし'}"
                ),
                severity=severity,
                confidence=round(confidence, 3),
                ai_score=round(s.ai_score, 4),
                evidence=evidence,
                entities=entities,
                tags=["ai-agent", "session", *(["ai-canary"] if canary else [])],
                fingerprint=f"{self.id}|{s.id}",
                source_ip=s.source_ip,
                mitre=mitre,
                details={
                    "session_id": s.id,
                    "classification": str(s.classification),
                    "ai_score": s.ai_score,
                    "ai_score_current": s.ai_score_current,
                    "threshold": threshold,
                    "scores": f.get("scores", {}),
                    "indicators": top,
                    "features": {k: f.get(k) for k in _FEATURE_SUMMARY_KEYS if k in f},
                },
            )
        ]
