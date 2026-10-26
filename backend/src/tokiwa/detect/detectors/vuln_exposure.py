"""vuln_exposure: an attack hit an asset that has an open CISA-KEV / high-EPSS vulnerability match -> critical.

Why alert-driven instead of per-event: detectors run without DB access and cannot see the drafts of other
detectors in the same batch, while "is this event an attack?" is exactly what the other detectors decide. So this
detector subscribes to ``alert.created``; for attack-type alerts it looks up the ``asset_id`` of the evidence
events (set by the ``asset_mapper`` enricher) and the asset's open KEV / EPSS >= ``intel.epss_alert_threshold``
matches (confidence >= :data:`MIN_MATCH_CONFIDENCE`). The resulting critical alert goes through the normal
engine persistence, so it is de-duplicated by fingerprint (asset + attacker IP) inside the dedup window and is
published as ``alert.created`` / ``alert.updated`` like any other alert.

The detector is registered (so it is listed in /detectors and can be disabled there) but never processes events
directly (``accepts`` returns False).
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select

from tokiwa.bus import bus
from tokiwa.config import get_settings
from tokiwa.db.models.intel import AssetRow
from tokiwa.db.models.telemetry import EventRow
from tokiwa.db.session import session_scope
from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.intel.matcher import LoopLocks, open_exposures
from tokiwa.runtime import on_startup
from tokiwa.schemas.alerts import Alert, AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event

log = logging.getLogger(__name__)

DETECTOR_ID = "intel.vuln_exposure"
MIN_MATCH_CONFIDENCE = 0.5
MAX_EVIDENCE = 200
# Alert categories that count as "an attack against the asset". Adjust here.
ATTACK_CATEGORIES = frozenset(
    {
        AlertCategory.EXPLOIT_ATTEMPT,
        AlertCategory.CREDENTIAL_ATTACK,
        AlertCategory.AI_AGENT,
        AlertCategory.PROMPT_INJECTION,
        AlertCategory.IDS,
    }
)

_locks = LoopLocks()


@register_detector
class VulnExposureDetector(Detector):
    id = DETECTOR_ID
    name = "Attack on an asset exposed to a known-exploited / high-EPSS vulnerability"
    description = (
        "Raised when an attack-type alert (exploit attempt, credential attack, AI agent, prompt injection, IDS) "
        "targets an asset with an open vulnerability match that is in CISA KEV or has EPSS >= the configured "
        "threshold. Driven by alert.created; de-duplicated per asset and source IP."
    )
    category = AlertCategory.VULN_EXPOSURE
    default_severity = Severity.CRITICAL
    mitre = ("T1190",)

    def accepts(self, event: Event) -> bool:
        return False

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        return []

    def build_draft(
        self, alert: Alert, asset_id: str, asset_name: str, vulns: list[dict[str, Any]]
    ) -> AlertDraft:
        kev = [v for v in vulns if v["kev"]]
        top = vulns[0]
        ids = ", ".join(v["vuln_id"] for v in vulns[:3]) + (" ..." if len(vulns) > 3 else "")
        label = "KEV" if kev else "high EPSS"
        return self.draft(
            None,
            title=f"Attack on {asset_name} exposed to {label} vulnerability ({ids})",
            severity=Severity.CRITICAL,
            description=(
                f"Alert '{alert.title}' ({alert.rule_id}) targeted asset '{asset_name}', which has "
                f"{len(vulns)} open exploitable vulnerability match(es): {ids}."
            ),
            confidence=0.85 if kev else 0.7,
            evidence=list(alert.evidence_event_ids[:MAX_EVIDENCE]),
            entities={
                "asset_id": asset_id,
                "asset": asset_name,
                "cve": top["vuln_id"],
                "trigger_alert_id": alert.id,
            },
            tags=["vuln_exposure", "kev"] if kev else ["vuln_exposure", "epss"],
            fingerprint=f"{DETECTOR_ID}|{asset_id}|{alert.source_ip or '-'}",
            details={
                "detector": DETECTOR_ID,
                "trigger_alert_id": alert.id,
                "trigger_rule_id": alert.rule_id,
                "trigger_category": str(alert.category),
                "asset_id": asset_id,
                "vulns": vulns[:20],
            },
            mitre=list(dict.fromkeys([*self.mitre, *alert.mitre])),
            source_ip=alert.source_ip,
        )


async def handle_alert_created(payload: Any) -> list[Alert]:
    """Create/bump vuln_exposure alerts for an attack alert. Returns the newly created alerts."""
    try:
        alert = payload if isinstance(payload, Alert) else Alert.model_validate(payload)
    except Exception:
        return []
    if alert.category not in ATTACK_CATEGORIES or alert.rule_id == DETECTOR_ID:
        return []
    from tokiwa.detect.engine import get_detection_engine  # late: engine imports the detectors package

    engine = get_detection_engine()
    det = engine.all_detectors().get(DETECTOR_ID)
    if not isinstance(det, VulnExposureDetector) or not engine.is_enabled(det):
        return []
    threshold = get_settings().intel.epss_alert_threshold
    async with _locks.get("vuln_exposure"):  # serialize so two attack alerts cannot race past the dedup check
        async with session_scope() as session:
            asset_ids: set[str] = set()
            if alert.entities.get("asset_id"):
                asset_ids.add(alert.entities["asset_id"])
            evidence = alert.evidence_event_ids[:MAX_EVIDENCE]
            if evidence:
                rows = await session.execute(select(EventRow.asset_id).where(EventRow.id.in_(evidence)))
                asset_ids.update(a for a in rows.scalars() if a)
            if not asset_ids:
                return []
            exposures = await open_exposures(
                session, asset_ids, epss_threshold=threshold, min_confidence=MIN_MATCH_CONFIDENCE
            )
            if not exposures:
                return []
            names = dict(
                (
                    await session.execute(
                        select(AssetRow.id, AssetRow.name).where(AssetRow.id.in_(list(exposures)))
                    )
                ).all()
            )
            drafts = [
                det.build_draft(alert, aid, names.get(aid, aid), vulns)
                for aid, vulns in sorted(exposures.items())
            ]
            created, updated = await engine.persist(session, drafts)
        await engine.publish(created, updated)
    return created


async def _on_alert_created(payload: Any) -> None:
    await handle_alert_created(payload)


@on_startup
async def _subscribe_vuln_exposure() -> None:
    bus.subscribe("alert.created", _on_alert_created)
