"""``ai.natural_language_payload`` — explanatory natural language inside an attack payload.

Hypothesis H4: LLM-generated requests often carry prose that explains the payload (SQL/HTML comments such as
``-- check whether id is injectable``, descriptive custom headers, readable test values) in English or Japanese.
Requires *both* an attack marker and a sentence-like NL score, so ordinary search queries / contact forms (prose
without attack syntax) and raw payloads (syntax without prose) do not fire. LLM-app paths are excluded (prompts are
prose by nature; ``llm_app.prompt_injection`` covers them).
"""

from __future__ import annotations

from tokiwa.aidetect import payloads as pl
from tokiwa.aidetect.detectkit import base_entities
from tokiwa.aidetect.prompt_injection import path_matches
from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind

NL_THRESHOLD = 0.55


@register_detector
class NaturalLanguagePayloadDetector(Detector):
    id = "ai.natural_language_payload"
    name = "Natural-language explanation inside attack payload"
    description = (
        "Attack payload (SQLi/XSS/traversal/...) that also contains explanatory English/Japanese prose, e.g. in "
        "SQL/HTML comments or custom headers — a habit of LLM-generated requests."
    )
    category = AlertCategory.AI_AGENT
    kinds = frozenset({EventKind.HTTP})
    mitre = ("T1190",)
    default_severity = Severity.MEDIUM

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        h = event.http
        if h is None or path_matches(h.path, ctx.settings.detection.llm_app_paths):
            return []
        payload = pl.extract_payload(h.path, h.query, h.request_body, h.content_type)
        text = payload.values_text()
        custom = pl.custom_header_text(h.headers)
        combined = f"{text} {custom}".strip()
        if not combined:
            return []
        attack = pl.attack_markers(combined)
        if not attack:
            return []
        nl = pl.natural_language_score(combined)
        if nl.score < NL_THRESHOLD:
            return []
        template = pl.path_template(h.path)
        entities = base_entities(event)
        return [
            self.draft(
                event,
                title=f"Natural-language prose in {'/'.join(sorted(attack))} payload ({nl.lang or '?'})",
                description=(
                    "The attack payload contains an explanatory sentence"
                    f"{' inside a code comment' if nl.in_comment else ''}. / 攻撃ペイロード内に説明文"
                    f"{'（コメント内）' if nl.in_comment else ''}が含まれています。"
                ),
                severity=Severity.MEDIUM,
                confidence=round(min(0.85, 0.5 + 0.4 * nl.score), 3),
                ai_score=round(min(0.85, 0.55 + 0.3 * nl.score), 3),
                entities=entities,
                tags=["ai-agent", "nl-payload", *(f"attack:{a}" for a in sorted(attack))],
                fingerprint=f"{self.id}|{event.source_ip or '-'}|{template}",
                details={
                    "nl_score": nl.score,
                    "language": nl.lang,
                    "in_comment": nl.in_comment,
                    "sample": nl.sample[:160],
                    "attack_families": sorted(attack),
                    "from_custom_header": bool(custom)
                    and pl.natural_language_score(custom).score >= NL_THRESHOLD,
                },
            )
        ]
