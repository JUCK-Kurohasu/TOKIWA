"""Mirage trip detector: decoy paths, honeytokens, AI canaries (reverse prompt injection), labyrinth.

Deception assets are things no legitimate user touches, so every hit is high fidelity (critical). An AI canary
value used the way the hidden instruction asks (header ``X-Debug-Auth`` or path ``/api/internal/<value>``) can
only come from a client that read and obeyed natural-language text -> ``category=ai_agent``, ``ai_score=0.99``.

The detector only reads the in-memory index (rebuilt by the deception service when assets change). Trip
counters and ``deception.tripped`` are handled by the service's ``event.ingested`` subscriber, so detection
stays side-effect free.
"""

from __future__ import annotations

from dataclasses import dataclass

from tokiwa.deception.matcher import Trip, TripType, match_event
from tokiwa.deception.service import get_index
from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event

LABYRINTH_CRITICAL_DEPTH = 3  # going this deep into generated pages = automated crawling


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
            "デコイ内の隠し指示（AI カナリア / 逆プロンプトインジェクション）どおりのリクエストを検知。"
            "自然言語の指示を読んで従えるのは LLM 駆動のクライアントだけ。 "
            "A request used an AI-canary value exactly as the hidden instruction asked "
            "(canary header or /api/internal/<value>); only an LLM-driven client does that."
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


@register_detector
class DeceptionTripDetector(Detector):
    id = "deception.trip"
    name = "Deception trip (decoy / honeytoken / AI canary / labyrinth)"
    description = (
        "Mirage の罠（デコイパス・ハニートークン・AI カナリア・迷路）への接触を検知。AI カナリアが指示どおりに"
        "使われた場合は AI エージェントと断定（ai_score 0.99）。"
    )
    category = AlertCategory.DECEPTION
    kinds = frozenset()  # tokens can show up in any event kind
    mitre = ("T1595.003",)
    default_severity = Severity.CRITICAL

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        index = await get_index()
        if index.empty:
            return []
        return [self._draft(event, trip) for trip in match_event(event, index)]

    def _draft(self, event: Event, trip: Trip) -> AlertDraft:
        spec = _SPECS[trip.trip_type]
        severity = spec.severity
        if trip.trip_type == TripType.LABYRINTH and (trip.depth or 0) >= LABYRINTH_CRITICAL_DEPTH:
            severity = Severity.CRITICAL
        tags = ["deception", f"deception:{trip.trip_type.value}", f"deception_kind:{trip.asset.kind.value}"]
        if trip.trip_type in (TripType.AI_CANARY_FOLLOWED, TripType.AI_CANARY_TOKEN):
            tags.append("ai_canary")
        if trip.ai_followed:
            tags.append("ai_agent")
        path = event.http.path if event.http else None
        return self.draft(
            event,
            title=f"{spec.title} ({trip.asset.name})",
            description=spec.description,
            severity=severity,
            confidence=spec.confidence,
            category=spec.category,
            ai_score=spec.ai_score,
            mitre=list(spec.mitre),
            tags=tags,
            entities={"deception_asset": trip.asset.id, "deception_kind": trip.asset.kind.value},
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
            },
        )
