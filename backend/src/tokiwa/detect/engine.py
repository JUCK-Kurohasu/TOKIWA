"""Detection engine: runs registered detectors over event batches and persists de-duplicated alerts."""

from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.bus import bus
from tokiwa.config import Settings, get_settings
from tokiwa.db.models.detection import AlertRow
from tokiwa.detect import suppress
from tokiwa.detect.base import Detector, registered_detectors
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.sigma.overlap import merge_native_overlap
from tokiwa.schemas.alerts import Alert, AlertDraft, AlertStatus
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

_DETECTOR_PACKAGE = "tokiwa.detect.detectors"


class DetectionEngine:
    def __init__(self, settings: Settings | None = None, ctx: DetectionContext | None = None) -> None:
        self.settings = settings or get_settings()
        self.ctx = ctx or DetectionContext(self.settings)
        self._instances: dict[str, Detector] = {}
        # Runtime overrides (from settings_kv "detection.overrides"): id -> enabled
        self.overrides: dict[str, bool] = {}
        self._loaded = False

    def load(self) -> None:
        from tokiwa.plugins import import_submodules

        import_submodules(_DETECTOR_PACKAGE)
        for det_id, cls in registered_detectors().items():
            if det_id not in self._instances:
                try:
                    self._instances[det_id] = cls()
                except Exception:
                    log.exception("failed to instantiate detector %s", det_id)
        self._loaded = True

    def all_detectors(self) -> dict[str, Detector]:
        if not self._loaded:
            self.load()
        return dict(self._instances)

    def is_enabled(self, det: Detector) -> bool:
        if det.id in self.overrides:
            return self.overrides[det.id]
        if det.id in self.settings.detection.disabled_detectors:
            return False
        return det.enabled_by_default

    def enabled_detectors(self) -> list[Detector]:
        return [d for d in self.all_detectors().values() if self.is_enabled(d)]

    async def run(self, events: list[Event]) -> list[AlertDraft]:
        """Pure detection (no DB). Exceptions in one detector never affect the others."""
        drafts: list[AlertDraft] = []
        self.ctx.scratch.clear()
        detectors = self.enabled_detectors()
        enabled_ids = {d.id for d in detectors}
        for event in events:
            event_drafts: list[AlertDraft] = []
            for det in detectors:
                if not det.accepts(event):
                    continue
                try:
                    out = await det.process(event, self.ctx)
                except Exception:
                    log.exception("detector %s failed on event %s", det.id, event.id)
                    continue
                for d in out:
                    d.details.setdefault("detector", det.id)
                event_drafts.extend(out)
            # Bundled Sigma web rules that duplicate a native web.* detector: one alert per finding (#76).
            drafts.extend(merge_native_overlap(event_drafts, enabled_ids))
        return drafts

    async def persist(
        self, session: AsyncSession, drafts: list[AlertDraft]
    ) -> tuple[list[Alert], list[Alert]]:
        """Insert new alerts or bump existing ones with the same fingerprint inside the dedup window.

        Returns (created, updated).
        """
        created: list[Alert] = []
        updated: list[Alert] = []
        window = timedelta(seconds=self.settings.detection.dedup_window_seconds)
        now = utcnow()
        # False-positive feedback and allowlists (#166 / #173): "drop" = no alert, "quiet" = stored at info and
        # never published (no triage / notification / incident). Logic in tokiwa.detect.suppress.
        suppressions = await suppress.load_active(session, now) if drafts else []
        for d in drafts:
            verdict = await suppress.apply(session, suppressions, d, now) if suppressions else None
            if verdict == "drop":
                continue
            fp = d.fingerprint or f"{d.rule_id}|{d.source_ip or '-'}"
            if verdict == "quiet":  # never merge allowlisted and normal hits into one row
                fp = f"{suppress.ALLOWLISTED_TAG}|{fp}"[:128]
            row = (
                await session.execute(
                    select(AlertRow)
                    .where(AlertRow.fingerprint == fp, AlertRow.last_seen >= now - window)
                    .where(AlertRow.status.notin_([AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]))
                    .order_by(AlertRow.last_seen.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            if row is not None:
                row.count += 1
                row.last_seen = now
                merged = list(dict.fromkeys([*row.evidence_event_ids, *d.evidence_event_ids]))
                row.evidence_event_ids = merged[-200:]
                if Severity(d.severity).rank > Severity(row.severity).rank:
                    row.severity = d.severity
                if d.ai_score is not None:
                    row.ai_score = max(row.ai_score or 0.0, d.ai_score)
                row.confidence = max(row.confidence, d.confidence)
                row.tags = list(dict.fromkeys([*row.tags, *d.tags]))
                row.updated_at = now
                await session.flush()
                if verdict is None:
                    updated.append(Alert.model_validate(row))
                continue
            row = AlertRow(
                id=new_id(),
                created_at=now,
                updated_at=now,
                first_seen=now,
                last_seen=now,
                count=1,
                fingerprint=fp,
                rule_id=d.rule_id,
                detector=str(d.details.get("detector", d.rule_id)),
                title=d.title,
                description=d.description,
                severity=d.severity,
                confidence=d.confidence,
                category=d.category,
                mitre=d.mitre,
                ai_score=d.ai_score,
                source_ip=d.source_ip,
                entities=d.entities,
                evidence_event_ids=d.evidence_event_ids,
                tags=d.tags,
                details=d.details,
                status=AlertStatus.ACKNOWLEDGED if verdict else AlertStatus.NEW,
            )
            session.add(row)
            await session.flush()
            if verdict is None:
                created.append(Alert.model_validate(row))
        return created, updated

    async def publish(self, created: list[Alert], updated: list[Alert]) -> None:
        for a in created:
            await bus.publish("alert.created", a)
        for a in updated:
            await bus.publish("alert.updated", a)


_engine: DetectionEngine | None = None


def get_detection_engine() -> DetectionEngine:
    global _engine
    if _engine is None:
        _engine = DetectionEngine()
    return _engine


def reset_detection_engine() -> None:
    global _engine
    _engine = None
