"""``llm_app.prompt_injection`` — prompt injection / jailbreak attempts against protected LLM applications.

Inputs: ``EventKind.LLM_APP`` events (``llm_app.prompt`` from app hooks) and HTTP requests to
``detection.llm_app_paths`` (prompt text extracted from JSON chat bodies; the app's own system/developer messages
are skipped). Patterns: :mod:`tokiwa.aidetect.prompt_injection` (ja/en).

MITRE ATLAS: AML.T0051 (LLM Prompt Injection), AML.T0054 (LLM Jailbreak).
TODO(verify): ATLAS ids for system-prompt extraction / LLM data leakage before adding them.
"""

from __future__ import annotations

from tokiwa.aidetect.detectkit import base_entities
from tokiwa.aidetect.prompt_injection import analyze_prompt, extract_prompt_text, path_matches
from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind

_HIGH_IMPACT = frozenset({"tool_abuse", "markdown_exfiltration", "obfuscated_instruction"})


@register_detector
class PromptInjectionDetector(Detector):
    id = "llm_app.prompt_injection"
    name = "Prompt injection / jailbreak against LLM app"
    description = (
        "Instruction override, system-prompt extraction, role-play jailbreak, obfuscated (Base64 / Unicode tag / "
        "invisible) instructions, tool-abuse steering and markdown-image exfiltration in prompts (ja/en)."
    )
    category = AlertCategory.PROMPT_INJECTION
    kinds = frozenset({EventKind.HTTP, EventKind.LLM_APP})
    mitre = ("AML.T0051",)
    default_severity = Severity.MEDIUM

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        app: str | None = None
        path: str | None = None
        if event.kind == EventKind.LLM_APP:
            if event.llm_app is None:
                return []
            text = event.llm_app.prompt or ""
            app = event.llm_app.app
        else:
            h = event.http
            if h is None or not path_matches(h.path, ctx.settings.detection.llm_app_paths):
                return []
            path = (h.path or "").split("?", 1)[0]
            text = extract_prompt_text(h.request_body, h.content_type, h.query)
        if not text:
            return []
        res = analyze_prompt(text)
        if not res.detected:
            return []
        families = res.families
        score = res.score
        strong_high = any(f.family in _HIGH_IMPACT and f.strength >= 0.75 for f in res.findings)
        if score >= 0.9 or strong_high or len(families) >= 3:
            severity = Severity.HIGH
        elif score >= 0.6:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        mitre = ["AML.T0051"]
        if "roleplay_jailbreak" in families:
            mitre.append("AML.T0054")
        entities = base_entities(event)
        target = app or path or "llm_app"
        entities["app"] = target[:255]
        return [
            self.draft(
                event,
                title=f"Prompt injection attempt against {target[:80]} ({', '.join(families)})",
                description=(
                    f"Prompt matches injection/jailbreak patterns: {', '.join(families)}. / "
                    f"プロンプトインジェクション/ジェイルブレイクの兆候: {', '.join(families)}"
                ),
                severity=severity,
                confidence=round(min(0.95, 0.4 + 0.5 * score), 3),
                entities=entities,
                tags=["prompt-injection", *families],
                fingerprint=f"{self.id}|{event.source_ip or '-'}|{target[:80]}|{','.join(families)}",
                mitre=mitre,
                details={
                    "families": families,
                    "score": score,
                    "findings": [
                        {"family": f.family, "snippet": f.snippet, "source": f.source, "strength": f.strength}
                        for f in res.findings[:8]
                    ],
                    "invisible_chars": res.invisible_chars,
                    "tag_chars": res.tag_chars,
                },
            )
        ]
