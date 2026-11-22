"""Mirage trip detector: decoy paths, honeytokens, AI canaries (reverse prompt injection), labyrinth.

Deception assets are things no legitimate user touches, so a deliberate hit is high fidelity (critical). An AI
canary value sent the way the hidden instruction asks in the canary header (``X-Debug-Auth``) can only come from a
client that read and obeyed natural-language text -> ``category=ai_agent``, ``ai_score=0.99``.

But a third party can make other people's clients trip (audit #133: ``<img src=/api/internal/<value>/>`` on a
forum, a link fetched by a preview bot). :mod:`tokiwa.deception.provenance` grades every trip:

* ``direct``  - the ``_SPECS`` table below, unchanged (decisive);
* ``passive`` - AI-canary value only in link-reachable fields (path, query, body, Referer): *medium*, category
  ``deception``, no AI attribution. Other alerts of the same source still raise the incident (correlation);
* ``induced`` - browser cross-site / sub-resource signals: *low*, any trip type.

Downgraded alerts never carry the ``ai_canary`` marker (tag substring / entity value) that correlation and the
rule-based triage treat as a decisive AI verdict, and their ``ai_score`` stays below the AI-agent threshold, so
the rule-based triage never proposes a block on them alone.

The detector only reads the in-memory index (rebuilt by the deception service when assets change). Trip
counters and ``deception.tripped`` are handled by the service's ``event.ingested`` subscriber, so detection
stays side-effect free.
"""

from __future__ import annotations

from dataclasses import dataclass

from tokiwa.deception.matcher import CANARY_TRIP_TYPES, Trip, TripType, match_event
from tokiwa.deception.provenance import Provenance
from tokiwa.deception.service import get_index
from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event

LABYRINTH_CRITICAL_DEPTH = 3  # going this deep into generated pages = automated crawling
PASSIVE_CANARY_AI_SCORE = 0.5  # weak AI hint for a link-reachable canary hit; never reaches the AI threshold


@dataclass(frozen=True)
class _Spec:
    title: str
    description: str
    category: AlertCategory
    severity: Severity
    confidence: float
    ai_score: float | None
    mitre: tuple[str, ...]
    fp_class: str


_SPECS: dict[TripType, _Spec] = {
    TripType.AI_CANARY_FOLLOWED: _Spec(
        title="AI canary followed: LLM agent obeyed a hidden instruction",
        description=(
            "デコイ内の隠し指示（AI カナリア / 逆プロンプトインジェクション）どおりのリクエストを検知"
            "（カナリアヘッダ等、クライアント自身にしか付けられない位置に値がある）。"
            "自然言語の指示を読んで従えるのは LLM 駆動のクライアントだけ。 "
            "A request used an AI-canary value exactly as the hidden instruction asked, in a place only the client "
            "itself can set (the canary header); only an LLM-driven client does that."
        ),
        category=AlertCategory.AI_AGENT,
        severity=Severity.CRITICAL,
        confidence=0.99,
        ai_score=0.99,
        mitre=(),
        fp_class="ai",
    ),
    TripType.AI_CANARY_TOKEN: _Spec(
        title="AI canary value observed in a request",
        description=(
            "隠し指示にだけ書かれた AI カナリア値がリクエストに現れた（指示どおりの形ではない）。"
            "隠しテキストを読んだ主体であり AI の可能性が高い。 "
            "A value that only exists in hidden canary text appeared outside the instructed form."
        ),
        category=AlertCategory.DECEPTION,
        severity=Severity.CRITICAL,
        confidence=0.9,
        ai_score=0.85,
        mitre=(),
        fp_class="canary",
    ),
    TripType.HONEYTOKEN: _Spec(
        title="Honeytoken used",
        description=(
            "デコイにだけ置いた偽の認証情報（ハニートークン）が使われた。デコイを読み取った主体による利用。 "
            "A fake credential that only exists inside a decoy was used."
        ),
        category=AlertCategory.DECEPTION,
        severity=Severity.CRITICAL,
        confidence=0.95,
        ai_score=None,
        mitre=("T1552.001", "T1078"),
        fp_class="token",
    ),
    TripType.DECOY_PATH: _Spec(
        title="Decoy path requested",
        description=(
            "正規利用者がアクセスしないデコイパスへのリクエスト。 "
            "A path that no legitimate user requests (Mirage decoy) was accessed."
        ),
        category=AlertCategory.DECEPTION,
        severity=Severity.CRITICAL,
        confidence=0.9,
        ai_score=None,
        mitre=("T1595.003",),
        fp_class="path",
    ),
    TripType.LABYRINTH: _Spec(
        title="Labyrinth traversal",
        description=(
            "自動生成された迷路ページ（隠しリンク・noindex）を辿っている。深いほど自動化の確度が高い。 "
            "The client is walking generated labyrinth pages (hidden, noindex links)."
        ),
        category=AlertCategory.DECEPTION,
        severity=Severity.HIGH,
        confidence=0.85,
        ai_score=None,
        mitre=("T1594",),
        fp_class="labyrinth",
    ),
}

# Downgraded trips (#133). Titles / descriptions say why, so an analyst does not read them as an AI verdict.
_PASSIVE_SPECS: dict[TripType, _Spec] = {
    TripType.AI_CANARY_FOLLOWED: _Spec(
        title="AI canary path requested without the canary header (not attributed)",
        description=(
            "AI カナリアの経路（/api/internal/<値>）へのアクセス。ただしカナリアヘッダは無く、リンク・画像・"
            "リンクプレビュー等で第三者が誘発できる形のため AI とは断定しない（他の攻撃アラートとの相関で判断）。 "
            "The AI-canary path was requested, but without the canary header. A link, an image or a link-preview "
            "bot can make any client do this, so it is not an AI-agent verdict on its own."
        ),
        category=AlertCategory.DECEPTION,
        severity=Severity.MEDIUM,
        confidence=0.5,
        ai_score=PASSIVE_CANARY_AI_SCORE,
        mitre=(),
        fp_class="canary_passive",
    ),
    TripType.AI_CANARY_TOKEN: _Spec(
        title="AI canary value seen in a link-reachable field (not attributed)",
        description=(
            "AI カナリア値がパス・クエリ・本文・Referer にだけ現れた。リンクやフォームで第三者が誘発できるため "
            "AI とは断定しない。 The AI-canary value appeared only where a link or a form can put it."
        ),
        category=AlertCategory.DECEPTION,
        severity=Severity.MEDIUM,
        confidence=0.45,
        ai_score=PASSIVE_CANARY_AI_SCORE,
        mitre=(),
        fp_class="canary_passive",
    ),
}

_INDUCED_SPEC = _Spec(
    title="Deception trip induced by a browser (cross-site / sub-resource; not attributed)",
    description=(
        "ブラウザがクロスサイト／サブリソース（画像・スクリプト・iframe 等）として送ったリクエスト、または外部の "
        "Origin / Referer を伴うトリップ。第三者のページが閲覧者に送らせられるため、送信元の遮断の根拠にしない。 "
        "The browser marked this request as cross-site or as a sub-resource (or it came with a foreign Origin / "
        "Referer). Any third-party page can make its visitors send it, so it is no basis for blocking the source."
    ),
    category=AlertCategory.DECEPTION,
    severity=Severity.LOW,
    confidence=0.3,
    ai_score=None,
    mitre=(),
    fp_class="induced",
)

# Trip-type labels for downgraded alerts. They must not contain "ai_canary": correlate.scoring._is_ai_canary and
# triage.fallback._is_canary treat that substring in a tag (or the entity value "ai_canary") as an AI verdict.
_NEUTRAL_LABEL = {
    TripType.AI_CANARY_FOLLOWED: "canary_followed",
    TripType.AI_CANARY_TOKEN: "canary_observed",
}


@register_detector
class DeceptionTripDetector(Detector):
    id = "deception.trip"
    name = "Deception trip (decoy / honeytoken / AI canary / labyrinth)"
    description = (
        "Mirage の罠（デコイパス・ハニートークン・AI カナリア・迷路）への接触を検知。AI カナリアがカナリアヘッダで"
        "指示どおりに使われた場合は AI エージェントと断定（ai_score 0.99）。リンク・画像で第三者が誘発できる形"
        "（経路だけ・クロスサイト）は重みを下げ、遮断提案の根拠にしない。"
    )
    category = AlertCategory.DECEPTION
    kinds = frozenset()  # tokens can show up in any event kind
    mitre = ("T1595.003",)
    default_severity = Severity.CRITICAL

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        index = await get_index()
        if index.empty:
            return []
        threshold = ctx.settings.detection.ai_agent_threshold
        return [self._draft(event, trip, threshold) for trip in match_event(event, index)]

    def _draft(self, event: Event, trip: Trip, ai_threshold: float) -> AlertDraft:
        kind = trip.asset.kind.value
        entities = {"deception_asset": trip.asset.id, "deception_kind": kind}
        if trip.provenance == Provenance.DIRECT:
            spec = _SPECS[trip.trip_type]
            severity = spec.severity
            if trip.trip_type == TripType.LABYRINTH and (trip.depth or 0) >= LABYRINTH_CRITICAL_DEPTH:
                severity = Severity.CRITICAL
            tags = ["deception", f"deception:{trip.trip_type.value}", f"deception_kind:{kind}"]
            if trip.trip_type in CANARY_TRIP_TYPES:
                tags.append("ai_canary")
            if trip.ai_followed:
                tags.append("ai_agent")
            ai_score = spec.ai_score
        else:
            spec = _INDUCED_SPEC if trip.provenance == Provenance.INDUCED else _PASSIVE_SPECS[trip.trip_type]
            severity = spec.severity
            label = _NEUTRAL_LABEL.get(trip.trip_type, trip.trip_type.value)
            tags = ["deception", f"deception:{trip.provenance.value}", f"deception_trip:{label}"]
            if "ai_canary" in kind:
                del entities[
                    "deception_kind"
                ]  # correlation reads the entity value "ai_canary" as an AI verdict
            else:
                tags.append(f"deception_kind:{kind}")
            ai_score = spec.ai_score if spec.ai_score is not None and spec.ai_score < ai_threshold else None
        path = event.http.path if event.http else None
        return self.draft(
            event,
            title=f"{spec.title} ({trip.asset.name})",
            description=spec.description,
            severity=severity,
            confidence=spec.confidence,
            category=spec.category,
            ai_score=ai_score,
            mitre=list(spec.mitre),
            tags=tags,
            entities=entities,
            fingerprint=f"{self.id}|{trip.asset.id}|{spec.fp_class}|{event.source_ip or '-'}",
            details={
                "asset_id": trip.asset.id,
                "asset_kind": trip.asset.kind.value,
                "asset_name": trip.asset.name,
                "trip_type": trip.trip_type.value,
                "ai_canary_followed": trip.ai_followed,
                "token": trip.token,
                "fields": trip.fields,
                "slots": trip.slots,
                "path": path,
                "depth": trip.depth,
                "provenance": trip.provenance.value,
                "induced_by": trip.induced_by,
            },
        )
