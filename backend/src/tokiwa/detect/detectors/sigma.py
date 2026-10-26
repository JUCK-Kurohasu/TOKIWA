"""``sigma`` detector: evaluates every active Sigma rule (files + ``rules`` table) against each event.

One alert draft per matching rule: ``rule_id = "sigma:<rule id>"``, severity from ``level``, MITRE techniques
from ``attack.tNNNN`` tags, category from tags/logsource (see ``tokiwa.detect.sigma.mapping``). The rule's
``falsepositives`` travel in ``details`` so the triage LLM and analysts can weigh them.
"""

from __future__ import annotations

import logging

from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.sigma.evaluator import MatchResult
from tokiwa.detect.sigma.loader import SIGMA_DETECTOR_ID, LoadedRule, SigmaRuleStore
from tokiwa.detect.sigma.mapping import (
    ai_score_for,
    category_for,
    confidence_for,
    mitre_from_tags,
    severity_for,
)
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event

log = logging.getLogger(__name__)


@register_detector
class SigmaDetector(Detector):
    id = SIGMA_DETECTOR_ID
    name = "Sigma rules"
    description = (
        "Evaluates Sigma rules from rules/sigma and the rules table (status=active) against every event. "
        "Disabling this detector disables all Sigma rules; individual rules are managed on the rules API."
    )
    category = AlertCategory.OTHER
    kinds = frozenset()  # per-rule logsource filtering happens in the store
    default_severity = Severity.MEDIUM

    def __init__(self) -> None:
        self.store = SigmaRuleStore()

    def accepts(self, event: Event) -> bool:
        return bool(self.store.rules_for(event.kind))

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        out: list[AlertDraft] = []
        for lr in self.store.rules_for(event.kind):
            try:
                res = lr.rule.match(event)
            except Exception:
                log.exception("sigma rule %s failed on event %s", lr.key, event.id)
                continue
            if res is None:
                continue
            self.store.record_hit(lr)
            out.append(self._to_draft(event, lr, res))
        return out

    def _to_draft(self, event: Event, lr: LoadedRule, res: MatchResult) -> AlertDraft:
        rule = lr.rule
        entities: dict[str, str] = {}
        if event.http is not None:
            if event.http.host:
                entities["host"] = event.http.host
            if event.http.path:
                entities["path"] = event.http.path[:256]
        if event.host is not None and event.host.name:
            entities.setdefault("host", event.host.name)
        if event.llm_app is not None and event.llm_app.app:
            entities["llm_app"] = event.llm_app.app
        return self.draft(
            event,
            rule_id=lr.rule_id,
            title=rule.title,
            description=rule.description,
            severity=severity_for(rule),
            confidence=confidence_for(rule),
            category=category_for(rule),
            ai_score=ai_score_for(rule),
            mitre=mitre_from_tags(rule.tags),
            tags=["sigma", *rule.tags],
            entities=entities,
            details={
                "sigma_id": rule.id,
                "rule_ref": lr.db_id,  # rules-table id -> GET /api/v1/rules/{rule_ref}
                "rule_origin": lr.origin,
                "rule_path": lr.path,
                "level": rule.level,
                "matched": list(res.matched),
                "falsepositives": list(rule.falsepositives),
                "logsource": dict(rule.logsource),
            },
        )
