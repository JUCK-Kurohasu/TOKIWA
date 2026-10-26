"""``ai.semantic_recon`` — machine-readable discovery followed by enumeration of the routes it describes.

Hypothesis H3: LLM agents read API descriptions (OpenAPI / Swagger, GraphQL introspection, AI-ecosystem manifests,
robots.txt, JS bundles) and then call the *real* routes directly — unlinked (no Referer), mostly non-404. Wordlist
scanners instead produce mostly 404s, and browsers carry Referer from the page that issued the call.

Two alert shapes (same detector id, different fingerprints):
- AI-ecosystem probe (``/.well-known/ai-plugin.json``, MCP endpoints, ``/llms.txt``, agent card): LOW, once per kind.
- Spec-driven enumeration: >= ``MIN_ENUM_STRONG`` new non-404 routes within ``DISCOVERY_WINDOW_S`` after a spec /
  AI-ecosystem fetch (or >= ``MIN_ENUM_WEAK`` after robots / sitemap / Referer-less JS fetch).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tokiwa.aidetect import payloads as pl
from tokiwa.aidetect.detectkit import base_entities, event_actor_key, referer_of
from tokiwa.aidetect.features import DISCOVERY_WINDOW_S
from tokiwa.aidetect.recon import AI_ECOSYSTEM_KINDS, discovery_kind, is_strong_discovery
from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind

MIN_ENUM_STRONG = 3
MIN_ENUM_WEAK = 5
# Share of new routes after discovery that must exist (non-404). Wordlist scanners mostly miss.
MIN_HIT_RATE = 0.5
REALERT_EVERY = 5
MAX_SEEN = 2048
STATE_TTL_S = 3600.0


@dataclass(slots=True)
class _Source:
    t: float | None = None
    kind: str | None = None
    enum_ids: list[str] = field(default_factory=list)
    misses: int = 0
    alerted: int = 0

    def active(self, now: float) -> bool:
        return self.t is not None and 0 <= now - self.t <= DISCOVERY_WINDOW_S


@dataclass(slots=True)
class _ReconState:
    strong: _Source = field(default_factory=_Source)
    weak: _Source = field(default_factory=_Source)
    disc_ids: list[str] = field(default_factory=list)
    seen: set[str] = field(default_factory=set)
    eco: set[str] = field(default_factory=set)


@register_detector
class SemanticReconDetector(Detector):
    id = "ai.semantic_recon"
    name = "Semantic reconnaissance (spec-driven API enumeration)"
    description = (
        "API description / AI-ecosystem manifest fetched (OpenAPI, GraphQL introspection, MCP, ai-plugin, "
        "llms.txt, robots, JS) and then the described routes enumerated directly without Referer."
    )
    category = AlertCategory.RECON
    kinds = frozenset({EventKind.HTTP})
    mitre = ("T1595", "T1592")
    default_severity = Severity.MEDIUM

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        h = event.http
        if h is None:
            return []
        path = h.path or "/"
        kind = discovery_kind(path, h.query, h.request_body)
        key = event_actor_key(event)
        st: _ReconState = ctx.state.setdefault(self.id, key, _ReconState, ttl=STATE_TTL_S)
        template = pl.path_template(path)
        t = event.timestamp.timestamp()
        has_ref = bool(referer_of(event))
        out: list[AlertDraft] = []
        if kind is not None:
            if kind in AI_ECOSYSTEM_KINDS and kind not in st.eco:
                st.eco.add(kind)
                out.append(self._eco_alert(event, key, kind))
            if is_strong_discovery(kind):
                st.strong = _Source(t=t, kind=kind)
                st.disc_ids = [*st.disc_ids, event.id][-5:]
            elif kind in ("robots", "sitemap") or (kind in ("js", "source_map") and not has_ref):
                keep = st.weak.active(t)
                st.weak = _Source(
                    t=t,
                    kind=kind,
                    alerted=st.weak.alerted if keep else 0,
                    enum_ids=st.weak.enum_ids if keep else [],
                    misses=st.weak.misses if keep else 0,
                )
                st.disc_ids = [*st.disc_ids, event.id][-5:]
            if len(st.seen) < MAX_SEEN:
                st.seen.add(template)
            return out
        if pl.is_static_asset(path):
            return out
        is_new = template not in st.seen
        if len(st.seen) < MAX_SEEN:
            st.seen.add(template)
        if not is_new or has_ref:
            return out
        for src, strong, minimum in ((st.strong, True, MIN_ENUM_STRONG), (st.weak, False, MIN_ENUM_WEAK)):
            if not src.active(t):
                continue
            if h.status == 404:
                src.misses += 1
                break
            src.enum_ids.append(event.id)
            n = len(src.enum_ids)
            if n / (n + src.misses) < MIN_HIT_RATE:
                break
            if n >= minimum and (src.alerted == 0 or n - src.alerted >= REALERT_EVERY):
                src.alerted = n
                out.append(self._enum_alert(event, key, src, st.disc_ids, strong=strong))
            break  # attribute the route to the strongest active source only
        return out

    def _eco_alert(self, event: Event, key: str, kind: str) -> AlertDraft:
        entities = base_entities(event)
        entities["discovery"] = kind
        return self.draft(
            event,
            title=f"AI-ecosystem discovery probe ({kind})",
            description=(
                "Request for an endpoint that only AI agents / LLM tooling consume (ai-plugin manifest, MCP, "
                "llms.txt, agent card). / AI エージェント向けエンドポイントの探索。"
            ),
            severity=Severity.LOW,
            confidence=0.55,
            ai_score=0.5,
            entities=entities,
            tags=["ai-agent", "semantic-recon", f"discovery:{kind}"],
            fingerprint=f"{self.id}|eco|{key}|{kind}",
            details={"discovery_kind": kind, "path": event.http.path if event.http else None},
        )

    def _enum_alert(
        self, event: Event, key: str, src: _Source, disc_ids: list[str], *, strong: bool
    ) -> AlertDraft:
        kind = src.kind or "discovery"
        n = len(src.enum_ids)
        evidence = list(dict.fromkeys([*disc_ids, *src.enum_ids[-20:]]))
        entities = base_entities(event)
        entities["discovery"] = kind
        return self.draft(
            event,
            title=f"Spec-driven API enumeration after {kind} fetch ({n} routes)",
            description=(
                f"{n} previously unseen, existing (non-404) routes were requested without Referer shortly after "
                f"fetching {kind}. / {kind} 取得直後に、リンクされていない実在ルートを直接列挙しています。"
            ),
            severity=Severity.MEDIUM if strong else Severity.LOW,
            confidence=0.7 if strong else 0.55,
            ai_score=0.6 if strong else 0.45,
            evidence=evidence,
            entities=entities,
            tags=["ai-agent", "semantic-recon", f"discovery:{kind}"],
            fingerprint=f"{self.id}|enum|{key}|{'strong' if strong else 'weak'}",
            details={"discovery_kind": kind, "enumerated_routes": n, "strong_source": strong},
        )
