"""LLM triage service (FR-07): rules first, LLM assist, tiered escalation, evidence validation.

Pipeline for one alert / incident:

1. Build the subject + evidence context (``triage.evidence``). Below ``min_severity_for_llm`` (or with no
   evidence events) -> rule verdict only (``tier="rules"``).
2. fast tier -> escalate to deep when ``confidence < escalate_confidence_below`` or
   ``max(rule severity, verdict severity) >= escalate_severity``. A failed deep call keeps the fast verdict.
3. Evidence validation: ids that were not shown are removed and recorded in ``rejected_evidence_ids``. With no
   valid id left, retry once with an explicit reminder; still nothing -> rule verdict.
4. Budget exceeded / refusal / invalid output -> rule verdict (detection never stops).
5. Store a :class:`TriageRecord` on the row (alerts -> ``status=triaged``), publish ``*.updated``.
6. ``recommended_actions`` -> ``respond.service.propose_action`` only for targets that are source IPs seen in
   the evidence. Proposals always go through the human approval workflow (respond module).

Concurrency: at most ``triage.max_concurrent`` triages run at once; one target is never triaged twice in
parallel (auto-triggers for a busy incident are coalesced into one re-run). Incident re-triage on
``incident.updated`` happens only when the incident's material signature (severity, kill chain, AI score
bucket, boost tags, category) changed, which bounds LLM cost for long-running incidents.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select

from tokiwa.bus import bus
from tokiwa.config import TriageSettings, get_settings
from tokiwa.correlate import scoring
from tokiwa.correlate.service import correlation_lock
from tokiwa.db.models.detection import AlertRow, IncidentRow
from tokiwa.db.session import session_scope
from tokiwa.llm.base import LLMPurpose, LLMTier, StructuredRequest
from tokiwa.llm.gateway import LLMGateway, get_gateway
from tokiwa.llm.prompting import PromptTemplate
from tokiwa.respond import service as respond_service
from tokiwa.runtime import on_startup
from tokiwa.schemas.alerts import Alert, AlertStatus, Incident, IncidentStatus
from tokiwa.schemas.common import ActorType, Severity
from tokiwa.schemas.response import ActionProposal, ActionProposer
from tokiwa.schemas.triage import TriageRecord, TriageResult
from tokiwa.triage.evidence import (
    TriageContext,
    TriageSubject,
    alert_subject,
    incident_subject,
    load_context,
    normalize_action_target,
    select_alert_evidence,
    select_incident_evidence,
    validate_evidence_ids,
)
from tokiwa.triage.fallback import RULES_PROMPT_VERSION, rule_based_triage
from tokiwa.triage.prompts import RETRY_NOTE, TRIAGE_ALERT, TRIAGE_INCIDENT, build_user_prompt, system_prompt

log = logging.getLogger(__name__)

TIER_RULES = "rules"
_SIGNATURE_TAGS = frozenset({scoring.TAG_KEV, scoring.TAG_AI_AGENT, scoring.TAG_PORT_REQUEST})
_MAX_ALERTS_PER_INCIDENT = 500
_MAX_REASON_CHARS = 500
_MAX_SIGNATURES = 10_000  # bound memory of the re-triage gate (oldest entries are forgotten)


# ------------------------------------------------------------------------------------------- pure decisions


def wants_llm(severity: Severity | str, cfg: TriageSettings) -> bool:
    """Cost control: only subjects at or above ``min_severity_for_llm`` are sent to the LLM automatically."""
    return Severity(severity).at_least(cfg.min_severity_for_llm)


def should_escalate(result: TriageResult, subject_severity: Severity | str, cfg: TriageSettings) -> bool:
    """fast -> deep when the fast verdict is unsure or the stakes are high (rule or verdict severity)."""
    if result.confidence < cfg.escalate_confidence_below:
        return True
    return Severity.max(Severity(result.severity), Severity(subject_severity)).at_least(cfg.escalate_severity)


def incident_signature(inc: Incident) -> tuple[Any, ...]:
    """Material state of an incident; re-triage only when it changes (fields triage itself writes excluded)."""
    return (
        str(inc.severity),
        tuple(inc.kill_chain),
        round(inc.ai_score or 0.0, 1),
        tuple(sorted(t for t in inc.tags if t in _SIGNATURE_TAGS)),
        str(inc.category),
    )


# ------------------------------------------------------------------------------------------- service


@dataclass
class _Attempt:
    result: TriageResult | None
    tier: str
    model: str | None = None
    call_id: str | None = None
    status: str = "ok"
    rejected: list[str] = field(default_factory=list)


class TriageService:
    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._sem: asyncio.Semaphore | None = None
        self._sem_size = 0
        self._guards: dict[str, list[Any]] = {}  # key -> [Lock, refcount]
        self._dirty: set[str] = set()
        self._last_sig: dict[str, tuple[Any, ...]] = {}
        self._respond_missing_logged = False

    # -- loop-bound primitives (pytest runs one event loop per test; the server runs one loop) --

    def _ensure_loop(self) -> None:
        loop = asyncio.get_running_loop()
        if loop is not self._loop:
            self._loop = loop
            self._sem = None
            self._guards.clear()
            self._dirty.clear()

    def _semaphore(self) -> asyncio.Semaphore:
        size = max(1, get_settings().triage.max_concurrent)
        if self._sem is None or size != self._sem_size:
            self._sem = asyncio.Semaphore(size)
            self._sem_size = size
        return self._sem

    def _remember_signature(self, key: str, sig: tuple[Any, ...]) -> None:
        self._last_sig.pop(key, None)
        self._last_sig[key] = sig
        while len(self._last_sig) > _MAX_SIGNATURES:
            self._last_sig.pop(next(iter(self._last_sig)))

    def _busy(self, key: str) -> bool:
        return key in self._guards

    @asynccontextmanager
    async def _guard(self, key: str) -> AsyncIterator[None]:
        entry = self._guards.get(key)
        if entry is None:
            entry = self._guards[key] = [asyncio.Lock(), 0]
        entry[1] += 1
        try:
            async with entry[0]:
                yield
        finally:
            entry[1] -= 1
            if entry[1] <= 0 and self._guards.get(key) is entry:
                self._guards.pop(key, None)

    # -- public API --

    async def triage_alert(
        self, alert_id: str, *, tier: LLMTier | None = None, force: bool = False
    ) -> Alert | None:
        """Triage one alert and return the updated alert (None if it does not exist).

        ``force`` (API) bypasses ``auto_triage`` / ``min_severity_for_llm``; ``tier`` pins a single tier.
        """
        self._ensure_loop()
        async with self._guard(f"alert:{alert_id}"), self._semaphore():
            return await self._triage_alert(alert_id, tier=tier, force=force)

    async def triage_incident(
        self, incident_id: str, *, tier: LLMTier | None = None, force: bool = False
    ) -> Incident | None:
        self._ensure_loop()
        async with self._guard(f"incident:{incident_id}"), self._semaphore():
            return await self._triage_incident(incident_id, tier=tier, force=force, auto=False)

    async def handle_alert_created(self, alert: Alert) -> None:
        if not get_settings().triage.auto_triage:
            return
        self._ensure_loop()
        key = f"alert:{alert.id}"
        if self._busy(key):
            return
        async with self._guard(key), self._semaphore():
            await self._triage_alert(alert.id, tier=None, force=False, auto=True)

    async def handle_incident_event(self, incident: Incident) -> None:
        if not get_settings().triage.auto_triage:
            return
        if incident.status in (IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE):
            return
        self._ensure_loop()
        key = f"incident:{incident.id}"
        if self._last_sig.get(key) == incident_signature(incident):
            return
        if self._busy(key):
            self._dirty.add(key)  # coalesce: the running triage re-runs once when it finishes
            return
        async with self._guard(key):
            while True:
                self._dirty.discard(key)
                async with self._semaphore():
                    await self._triage_incident(incident.id, tier=None, force=False, auto=True)
                if key not in self._dirty:
                    break

    # -- alerts --

    async def _triage_alert(
        self, alert_id: str, *, tier: LLMTier | None, force: bool, auto: bool = False
    ) -> Alert | None:
        cfg = get_settings().triage
        async with session_scope() as session:
            row = await session.get(AlertRow, alert_id)
            if row is None:
                return None
            if auto and (row.triage is not None or row.status not in (AlertStatus.NEW, AlertStatus.TRIAGING)):
                return Alert.model_validate(row)
            subject = alert_subject(row)
            ctx = await load_context(
                session, subject, select_alert_evidence(row.evidence_event_ids or [], cfg.max_evidence_events)
            )
            use_llm = force or wants_llm(subject.severity, cfg)
            if use_llm and ctx.evidence_ids and row.status == AlertStatus.NEW:
                row.status = AlertStatus.TRIAGING

        record = await self._verdict(
            subject,
            ctx,
            tier=tier,
            use_llm=use_llm,
            template=TRIAGE_ALERT,
            purpose=LLMPurpose.TRIAGE,
            related={"alert_id": alert_id},
        )

        async with session_scope() as session:
            row = await session.get(AlertRow, alert_id)
            if row is None:
                return None
            row.triage = record.model_dump(mode="json")
            if row.status in (AlertStatus.NEW, AlertStatus.TRIAGING):
                row.status = AlertStatus.TRIAGED
            await session.flush()
            alert = Alert.model_validate(row)
        await bus.publish("alert.updated", alert)
        await self._propose_actions(record, ctx, alert_id=alert.id, incident_id=alert.incident_id)
        return alert

    # -- incidents --

    async def _triage_incident(
        self, incident_id: str, *, tier: LLMTier | None, force: bool, auto: bool
    ) -> Incident | None:
        cfg = get_settings().triage
        key = f"incident:{incident_id}"
        async with session_scope() as session:
            row = await session.get(IncidentRow, incident_id)
            if row is None:
                return None
            current = Incident.model_validate(row)
            sig = incident_signature(current)
            if auto and (
                self._last_sig.get(key) == sig
                or current.status in (IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE)
            ):
                return current
            alerts = list(
                (
                    await session.execute(
                        select(AlertRow)
                        .where(AlertRow.incident_id == incident_id)
                        .order_by(AlertRow.last_seen.desc())
                        .limit(_MAX_ALERTS_PER_INCIDENT)
                    )
                )
                .scalars()
                .all()
            )
            subject = incident_subject(row, alerts)
            ctx = await load_context(
                session, subject, select_incident_evidence(alerts, cfg.max_evidence_events)
            )
            use_llm = force or wants_llm(subject.severity, cfg)

        record = await self._verdict(
            subject,
            ctx,
            tier=tier,
            use_llm=use_llm,
            template=TRIAGE_INCIDENT,
            purpose=LLMPurpose.INCIDENT,
            related={"incident_id": incident_id},
        )

        # Under the correlation lock so a concurrent recompute cannot overwrite the verdict summary.
        async with correlation_lock(), session_scope() as session:
            row = await session.get(IncidentRow, incident_id)
            if row is None:
                return None
            row.triage = record.model_dump(mode="json")
            row.summary = record.result.summary[:4000]
            if (
                row.actor_type == ActorType.UNKNOWN
                and record.tier != TIER_RULES
                and record.result.actor_type != ActorType.UNKNOWN
            ):
                row.actor_type = record.result.actor_type
            await session.flush()
            incident = Incident.model_validate(row)
        self._remember_signature(key, sig)
        await bus.publish("incident.updated", incident)
        await self._propose_actions(record, ctx, alert_id=None, incident_id=incident.id)
        return incident

    # -- verdicts --

    def _rules_record(
        self, subject: TriageSubject, ctx: TriageContext, rejected: list[str] | None = None
    ) -> TriageRecord:
        return TriageRecord(
            result=rule_based_triage(subject, ctx.evidence_ids, ctx.source_ips),
            tier=TIER_RULES,
            model=None,
            prompt_version=RULES_PROMPT_VERSION,
            escalated=False,
            rejected_evidence_ids=list(dict.fromkeys(rejected or [])),
        )

    async def _verdict(
        self,
        subject: TriageSubject,
        ctx: TriageContext,
        *,
        tier: LLMTier | None,
        use_llm: bool,
        template: PromptTemplate,
        purpose: LLMPurpose,
        related: dict[str, str],
    ) -> TriageRecord:
        if not use_llm or not ctx.evidence_ids:
            # No evidence -> the model could not cite anything valid (requirements 7-5): rules only.
            return self._rules_record(subject, ctx)
        try:
            return await self._llm_verdict(
                subject, ctx, tier=tier, template=template, purpose=purpose, related=related
            )
        except Exception:
            log.exception("LLM triage failed for %s %s; using rule verdict", subject.kind, subject.id)
            return self._rules_record(subject, ctx)

    async def _llm_verdict(
        self,
        subject: TriageSubject,
        ctx: TriageContext,
        *,
        tier: LLMTier | None,
        template: PromptTemplate,
        purpose: LLMPurpose,
        related: dict[str, str],
    ) -> TriageRecord:
        settings = get_settings()
        gw = get_gateway()
        system = system_prompt(template, settings.llm.output_language)
        user = build_user_prompt(subject, ctx)
        first_tier = LLMTier.DEEP if tier == LLMTier.DEEP else LLMTier.FAST
        rejected: list[str] = []

        first = await self._attempt(
            gw, first_tier, system, user, template, purpose, related, ctx.evidence_ids
        )
        rejected += first.rejected
        if first.result is None:
            log.info(
                "triage %s %s: %s tier failed (%s); rule verdict",
                subject.kind,
                subject.id,
                first_tier,
                first.status,
            )
            return self._rules_record(subject, ctx, rejected)

        chosen, escalated = first, False
        if tier is None and should_escalate(first.result, subject.severity, settings.triage):
            escalated = True
            deep = await self._attempt(
                gw, LLMTier.DEEP, system, user, template, purpose, related, ctx.evidence_ids
            )
            rejected += deep.rejected
            if deep.result is not None:
                chosen = deep
            else:
                log.info(
                    "triage %s %s: deep tier failed (%s); keeping fast verdict",
                    subject.kind,
                    subject.id,
                    deep.status,
                )
        assert chosen.result is not None
        return TriageRecord(
            result=chosen.result,
            tier=chosen.tier,
            model=chosen.model,
            prompt_version=template.ref,
            llm_call_id=chosen.call_id,
            escalated=escalated,
            rejected_evidence_ids=list(dict.fromkeys(rejected)),
        )

    async def _attempt(
        self,
        gw: LLMGateway,
        tier: LLMTier,
        system: str,
        user: str,
        template: PromptTemplate,
        purpose: LLMPurpose,
        related: dict[str, str],
        allowed_ids: list[str],
    ) -> _Attempt:
        """One tier: call, validate evidence ids, retry once if none is valid."""
        rejected: list[str] = []
        for attempt in range(2):
            prompt = user if attempt == 0 else f"{user}\n\n{RETRY_NOTE}"
            res = await gw.structured(
                StructuredRequest(
                    purpose=purpose,
                    tier=tier,
                    system=system,
                    user=prompt,
                    prompt_version=template.ref,
                    related=related,
                ),
                TriageResult,
            )
            if not res.ok or res.output is None:
                return _Attempt(None, str(tier), status=str(res.status), rejected=rejected)
            valid, bad = validate_evidence_ids(res.output.evidence_ids, allowed_ids)
            rejected += bad
            if valid:
                output = res.output.model_copy(update={"evidence_ids": valid})
                return _Attempt(output, str(tier), res.model, res.call_id, "ok", rejected)
            log.info("triage: %s tier cited no valid evidence ids (attempt %d)", tier, attempt + 1)
        return _Attempt(None, str(tier), status="no_valid_evidence", rejected=rejected)

    # -- response proposals --

    async def _propose_actions(
        self, record: TriageRecord, ctx: TriageContext, *, alert_id: str | None, incident_id: str | None
    ) -> None:
        actions = record.result.recommended_actions
        if not actions:
            return
        proposer = ActionProposer.RULE if record.tier == TIER_RULES else ActionProposer.LLM
        seen: set[tuple[str, str]] = set()
        evidence_ips = ctx.source_ips
        for act in actions:
            target = normalize_action_target(act.target, evidence_ips)
            if target is None:
                log.info("triage: dropping %s proposal; target not an evidenced source IP", act.action_type)
                continue
            if (act.action_type, target) in seen:
                continue
            seen.add((act.action_type, target))
            proposal = ActionProposal(
                action_type=act.action_type,
                target=target,
                reason=act.reason[:_MAX_REASON_CHARS],
                ttl_minutes=act.ttl_minutes,
                incident_id=incident_id,
                alert_id=alert_id,
                proposed_by=proposer,
            )
            try:
                await respond_service.propose_action(proposal)
            except NotImplementedError:
                if not self._respond_missing_logged:
                    log.warning("respond module not implemented yet; triage action proposals are skipped")
                    self._respond_missing_logged = True
                return
            except Exception:
                log.exception("propose_action failed for %s %s", act.action_type, target)


_service: TriageService | None = None


def get_triage_service() -> TriageService:
    global _service
    if _service is None:
        _service = TriageService()
    return _service


async def _on_alert_created(alert: Alert) -> None:
    await get_triage_service().handle_alert_created(alert)


async def _on_incident(incident: Incident) -> None:
    await get_triage_service().handle_incident_event(incident)


@on_startup
async def _subscribe() -> None:
    bus.subscribe("alert.created", _on_alert_created)
    bus.subscribe("incident.created", _on_incident)
    bus.subscribe("incident.updated", _on_incident)
