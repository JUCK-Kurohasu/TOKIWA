"""``ai.adaptive_mutation`` — response-conditioned payload mutation chains.

Hypothesis H2 (docs/detection/ai-attacks.md): an LLM agent reads an error response (500 / 400 / WAF 403), reasons,
and sends a *variant* of the same payload to the same endpoint/parameter (different encoding, fixed syntax,
another bypass). Wordlist scanners fire their payload list regardless of the response and without pauses.

A *link* = previous request to the same endpoint (method + path template) errored (>= 400) and this request
carries a similar-but-different payload with (mostly) the same parameter names. It is *adaptive* when the gap
before it is at least ``ADAPTIVE_MIN_GAP_S`` (time to read and reason). Alert when a chain reaches
``MIN_CHAIN`` links of which ``MIN_ADAPTIVE`` are adaptive; re-alert every ``REALERT_EVERY`` links (dedup bumps).
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from tokiwa.aidetect import payloads as pl
from tokiwa.aidetect.detectkit import base_entities, event_actor_key
from tokiwa.aidetect.features import (
    ADAPTIVE_MIN_GAP_S,
    MUTATION_MAX_SIMILARITY,
    MUTATION_MIN_SIMILARITY,
    MUTATION_WINDOW_S,
)
from tokiwa.aidetect.prompt_injection import path_matches
from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind

MIN_CHAIN = 3
MIN_ADAPTIVE = 2
REALERT_EVERY = 3
MAX_ENDPOINTS_PER_ACTOR = 64
STATE_TTL_S = 3600.0


@dataclass(slots=True)
class _EpState:
    t: float
    status: int
    sig: str
    names: frozenset[str]
    chain: int = 0
    adaptive: int = 0
    event_ids: list[str] = field(default_factory=list)
    samples: list[str] = field(default_factory=list)
    gaps_ms: list[float] = field(default_factory=list)
    alerted_at: int = 0


@register_detector
class AdaptiveMutationDetector(Detector):
    id = "ai.adaptive_mutation"
    name = "Adaptive payload mutation after errors"
    description = (
        "Chain of payload variants sent to the same endpoint/parameter right after error responses, with "
        "reasoning-length pauses in between (response-conditioned adaptation typical of LLM agents)."
    )
    category = AlertCategory.AI_AGENT
    kinds = frozenset({EventKind.HTTP})
    mitre = ("T1190",)
    default_severity = Severity.MEDIUM

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        h = event.http
        if h is None or h.status is None:
            return []
        if path_matches(h.path, ctx.settings.detection.llm_app_paths):
            return []  # chat prompts legitimately vary turn by turn
        payload = pl.extract_payload(h.path, h.query, h.request_body, h.content_type)
        if not payload.present:
            return []
        sig = payload.signature()
        names = payload.names
        ep = f"{(h.method or 'GET').upper()} {pl.path_template(h.path)}"
        key = event_actor_key(event)
        eps: OrderedDict[str, _EpState] = ctx.state.setdefault(self.id, key, OrderedDict, ttl=STATE_TTL_S)
        t = event.timestamp.timestamp()
        prev = eps.get(ep)
        cur = _EpState(t=t, status=h.status, sig=sig, names=names, event_ids=[event.id], samples=[sig[:120]])
        if (
            prev is not None
            and 0 <= t - prev.t <= MUTATION_WINDOW_S
            and prev.status >= 400
            and sig != prev.sig
        ):
            overlap = pl.jaccard(names, prev.names) if (names or prev.names) else 1.0
            sim = pl.payload_similarity(prev.sig, sig)
            if overlap >= 0.5 and MUTATION_MIN_SIMILARITY <= sim < MUTATION_MAX_SIMILARITY:
                gap = t - prev.t
                cur.chain = prev.chain + 1
                cur.adaptive = prev.adaptive + (1 if gap >= ADAPTIVE_MIN_GAP_S else 0)
                cur.event_ids = [*prev.event_ids, event.id][-12:]
                cur.samples = [*prev.samples, sig[:120]][-6:]
                cur.gaps_ms = [*prev.gaps_ms, round(gap * 1000, 1)][-12:]
                cur.alerted_at = prev.alerted_at
        eps[ep] = cur
        eps.move_to_end(ep)
        while len(eps) > MAX_ENDPOINTS_PER_ACTOR:
            eps.popitem(last=False)

        if cur.chain < MIN_CHAIN or cur.adaptive < MIN_ADAPTIVE:
            return []
        if cur.alerted_at and cur.chain - cur.alerted_at < REALERT_EVERY:
            return []
        cur.alerted_at = cur.chain
        success_after_errors = h.status < 400
        severity = Severity.HIGH if (success_after_errors or cur.chain >= 6) else Severity.MEDIUM
        edit_sim = (
            pl.edit_similarity(cur.samples[-2], cur.samples[-1], cap=96) if len(cur.samples) >= 2 else None
        )
        ai_score = round(min(0.9, 0.5 + 0.08 * cur.adaptive), 3)
        entities = base_entities(event)
        entities["endpoint"] = ep[:255]
        if names:
            entities["param"] = ",".join(sorted(names))[:120]
        return [
            self.draft(
                event,
                title=f"Adaptive payload mutation on {ep[:120]} ({cur.chain} variants after errors)",
                description=(
                    "Successive payload variants were sent to the same endpoint/parameter after error responses, "
                    "with reasoning-length pauses. / エラー応答の直後に同一エンドポイント・同一パラメータへ"
                    "思考待ちを挟んだペイロード変種が連続しています。"
                ),
                severity=severity,
                confidence=round(min(0.9, 0.55 + 0.05 * cur.chain), 3),
                ai_score=ai_score,
                evidence=list(cur.event_ids),
                entities=entities,
                tags=[
                    "ai-agent",
                    "adaptive-mutation",
                    *(["bypass-suspected"] if success_after_errors else []),
                ],
                fingerprint=f"{self.id}|{key}|{ep[:200]}",
                details={
                    "endpoint": ep[:255],
                    "chain": cur.chain,
                    "adaptive_links": cur.adaptive,
                    "gaps_ms": cur.gaps_ms,
                    "payload_samples": cur.samples,
                    "last_edit_similarity": round(edit_sim, 3) if edit_sim is not None else None,
                    "final_status": h.status,
                },
            )
        ]
