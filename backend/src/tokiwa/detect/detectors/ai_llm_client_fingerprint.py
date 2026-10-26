"""``ai.llm_client_fingerprint`` — the client declares itself as an AI agent / AI crawler / LLM SDK.

Weak evidence on its own (UAs are trivially spoofed and many AI fetchers are benign), hence LOW/INFO severity,
once per actor and tool. It raises to MEDIUM only when the same request also carries an attack payload.
"""

from __future__ import annotations

from tokiwa.aidetect import payloads as pl
from tokiwa.aidetect.detectkit import base_entities, clip, event_actor_key
from tokiwa.aidetect.fingerprints import ClientFamily, fingerprint_info
from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind


@register_detector
class LLMClientFingerprintDetector(Detector):
    id = "ai.llm_client_fingerprint"
    name = "AI / LLM client fingerprint"
    description = (
        "User-Agent or headers identify an AI agent, AI crawler, agent framework, LLM SDK (x-stainless-*) or MCP "
        "client. Low severity alone; combine with behaviour (ai.agent_session)."
    )
    category = AlertCategory.AI_AGENT
    kinds = frozenset({EventKind.HTTP})
    mitre = ("T1595",)
    default_severity = Severity.LOW

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        h = event.http
        if h is None:
            return []
        ua = h.user_agent or (h.headers or {}).get("user-agent")
        fp = fingerprint_info(ua, h.headers, scheme=h.scheme)
        is_ai = fp.family in (ClientFamily.AI_AGENT, ClientFamily.AI_CRAWLER)
        if not is_ai and not fp.llm_sdk_headers:
            return []
        tool = fp.tool or (
            "mcp-client" if any(n.startswith("mcp-") for n in fp.llm_sdk_headers) else "llm-sdk"
        )
        key = event_actor_key(event)
        state_key = f"{key}|{tool}"
        if ctx.state.get(self.id, state_key):
            return []
        ctx.state.set(
            self.id, state_key, True, ttl=float(ctx.settings.detection.session_idle_timeout_seconds)
        )
        text = pl.extract_payload(h.path, h.query, h.request_body, h.content_type).values_text()
        attack = sorted(pl.attack_markers(text)) if text else []
        if fp.family == ClientFamily.AI_CRAWLER and not fp.llm_sdk_headers:
            severity, ai_score, kind = Severity.INFO, 0.3, "ai_crawler"
        elif fp.family == ClientFamily.AI_AGENT:
            severity, ai_score, kind = Severity.LOW, 0.5, "ai_agent"
        else:
            severity, ai_score, kind = Severity.LOW, 0.55, "llm_sdk"
        if attack:
            severity = Severity.MEDIUM
            ai_score = min(0.8, ai_score + 0.2)
        entities = base_entities(event)
        entities["client"] = tool
        if ua:
            entities["user_agent"] = clip(ua)
        return [
            self.draft(
                event,
                title=f"AI/LLM client fingerprint: {tool}",
                description=(
                    f"Client identified as {kind} ({tool}). Fingerprints are spoofable; weigh with behaviour. / "
                    f"AI/LLM 系クライアントの指紋（{tool}）。単独では弱い根拠です。"
                ),
                severity=severity,
                confidence=0.6 if is_ai else 0.5,
                ai_score=round(ai_score, 3),
                entities=entities,
                tags=["ai-client", kind, *(["attack-payload"] if attack else [])],
                fingerprint=f"{self.id}|{event.source_ip or '-'}|{tool}",
                details={
                    "family": str(fp.family),
                    "tool": tool,
                    "user_agent": clip(ua, 300),
                    "llm_sdk_headers": list(fp.llm_sdk_headers),
                    "header_anomalies": list(fp.anomalies),
                    "attack_families": attack,
                },
            )
        ]
