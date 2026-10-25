"""Correlation service (FR-09): bundle alerts into incidents and keep incident aggregates current.

Flow (``alert.created`` / ``alert.updated`` subscriber):

1. Already linked alert -> recompute the incident (dedup hit, status change, AI score change ...).
2. Otherwise compute correlation keys (source IP, actor session, host+port, CVE) and look for an *open*
   incident that has an alert with a shared key inside ``triage.incident_window_minutes``.
3. Port x request (FR-09 example): a request-type alert hitting a port on which an unexpected listener
   appeared shortly before -> joins / tags the incident with ``correlated:port_request``.
4. No match -> new incident (alerts below :data:`NEW_INCIDENT_MIN_SEVERITY` only attach, never create).

Aggregates (severity / AI score / kill chain / actor type / tags) are recomputed from all linked alerts every
time, so they are idempotent and boosts never stack up across updates. ``incident.created`` /
``incident.updated`` are published only when something actually changed (avoids feedback loops with triage).

All read-modify-write work on incidents runs under :func:`correlation_lock` (single process, lab scale), which
also prevents two concurrent alerts from the same attacker creating two incidents.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.bus import bus
from tokiwa.config import get_settings
from tokiwa.correlate import killchain, scoring
from tokiwa.db.models.detection import AlertRow, IncidentRow
from tokiwa.db.models.intel import VulnRow
from tokiwa.db.models.telemetry import ActorSessionRow, EventRow
from tokiwa.db.session import session_scope
from tokiwa.pipeline.store import get_events
from tokiwa.runtime import on_startup
from tokiwa.schemas.alerts import Alert, AlertCategory, AlertStatus, Incident, IncidentStatus
from tokiwa.schemas.common import ActorType, Severity
from tokiwa.schemas.events import EventKind
from tokiwa.schemas.triage import TriageRecord
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

OPEN_INCIDENT_STATUSES: tuple[str, ...] = (
    IncidentStatus.OPEN,
    IncidentStatus.INVESTIGATING,
    IncidentStatus.CONTAINED,
)
CLOSED_ALERT_STATUSES: tuple[str, ...] = (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE)
# Alerts below this severity attach to existing incidents but never open a new one (noise control, e.g.
# info-level PORT_CHANGE "learning" alerts). Tunable.
NEW_INCIDENT_MIN_SEVERITY = Severity.LOW

_MAX_CANDIDATES = 2000  # alerts inspected when searching for a matching incident
_EVIDENCE_IDS_PER_ALERT = 20  # evidence events inspected per alert (session ids / request ports)
_MAX_LISTENERS = 200
_REQUEST_KINDS = frozenset({EventKind.HTTP, EventKind.CONNECTION, EventKind.IDS_ALERT})
# Lower = stronger evidence that two alerts belong to the same activity.
_KEY_PRIORITY = {"session": 0, "ip": 1, "hostport": 2, "cve": 3}


class _LoopLock:
    """asyncio.Lock re-created when the running loop changes (pytest runs one event loop per test)."""

    def __init__(self) -> None:
        self._lock: asyncio.Lock | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def get(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or self._loop is not loop:
            self._lock = asyncio.Lock()
            self._loop = loop
        return self._lock


_lock = _LoopLock()


def correlation_lock() -> asyncio.Lock:
    """Serializes incident read-modify-write (correlation and triage verdict writes) in this process.

    Never acquire it while holding an open DB write transaction (deadlock with SQLite's write lock).
    """
    return _lock.get()


@dataclass
class _Outcome:
    incident: Incident | None = None
    created: bool = False
    changed: bool = False
    linked_alerts: list[Alert] = field(default_factory=list)
    also_updated: list[Incident] = field(default_factory=list)


# --------------------------------------------------------------------------------------------- public API


async def correlate_alert(alert_id: str) -> Incident | None:
    """Link one alert to an incident (creating one if needed) and refresh aggregates.

    Returns the incident the alert belongs to afterwards (None when the alert stays unlinked).
    """
    async with correlation_lock(), session_scope() as session:
        outcome = await _correlate(session, alert_id)
    await _publish(outcome)
    return outcome.incident


async def recompute_incident(incident_id: str) -> Incident | None:
    """Recompute aggregates of one incident (e.g. after alerts were re-assigned)."""
    async with correlation_lock(), session_scope() as session:
        inc = await session.get(IncidentRow, incident_id)
        if inc is None:
            return None
        before = _snapshot(inc)
        await _recompute(session, inc)
        after = Incident.model_validate(inc)
    if _dump(after) != before:
        await bus.publish("incident.updated", after)
    return after


async def handle_alert(alert: Alert) -> None:
    """Bus handler for ``alert.created`` / ``alert.updated`` (the row is re-read; the payload may be stale)."""
    await correlate_alert(alert.id)


@on_startup
async def _subscribe() -> None:
    bus.subscribe("alert.created", handle_alert)
    bus.subscribe("alert.updated", handle_alert)


# --------------------------------------------------------------------------------------------- internals


def _dump(inc: Incident) -> dict[str, Any]:
    return inc.model_dump(mode="json", exclude={"updated_at"})


def _snapshot(row: IncidentRow) -> dict[str, Any]:
    return _dump(Incident.model_validate(row))


async def _publish(outcome: _Outcome) -> None:
    if outcome.incident is not None:
        if outcome.created:
            await bus.publish("incident.created", outcome.incident)
        elif outcome.changed:
            await bus.publish("incident.updated", outcome.incident)
    for inc in outcome.also_updated:
        await bus.publish("incident.updated", inc)
    for alert in outcome.linked_alerts:
        await bus.publish("alert.updated", alert)


async def _correlate(session: AsyncSession, alert_id: str) -> _Outcome:
    row = await session.get(AlertRow, alert_id)
    if row is None:
        return _Outcome()
    window = timedelta(minutes=get_settings().triage.incident_window_minutes)

    if row.incident_id:
        inc = await session.get(IncidentRow, row.incident_id)
        if inc is not None:
            linked_before = _snapshot(inc)
            out = _Outcome()
            listener = await _port_request_listener(session, row, window)
            if listener is not None:
                await _apply_port_request(session, inc, listener, out)
            await _recompute(session, inc)
            out.incident = Incident.model_validate(inc)
            out.changed = _dump(out.incident) != linked_before
            return out
        log.warning("alert %s references missing incident %s; re-correlating", row.id, row.incident_id)
        row.incident_id = None

    if row.status in CLOSED_ALERT_STATUSES:
        return _Outcome()

    session_ids = (await _session_ids_by_alert(session, [row]))[row.id]
    keys = _correlation_keys(row, session_ids)
    target = await _find_matching_incident(session, row, keys, window)
    listener = await _port_request_listener(session, row, window)
    if target is None and listener is not None and listener.incident_id:
        candidate = await session.get(IncidentRow, listener.incident_id)
        if candidate is not None and candidate.status in OPEN_INCIDENT_STATUSES:
            target = candidate

    out = _Outcome()
    before: dict[str, Any] | None = None
    if target is None:
        if listener is None and not Severity(row.severity).at_least(NEW_INCIDENT_MIN_SEVERITY):
            return _Outcome()
        target = _new_incident(row)
        session.add(target)
        out.created = True
    else:
        before = _snapshot(target)

    row.incident_id = target.id
    await session.flush()
    if listener is not None:
        await _apply_port_request(session, target, listener, out)
    await _link_sessions(session, target.id, session_ids)
    await _recompute(session, target)
    out.incident = Incident.model_validate(target)
    out.changed = before is None or _dump(out.incident) != before
    out.linked_alerts.insert(0, Alert.model_validate(row))
    return out


def _new_incident(row: AlertRow) -> IncidentRow:
    now = utcnow()
    return IncidentRow(
        id=new_id(),
        created_at=now,
        updated_at=now,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        title=row.title,
        summary="",
        severity=row.severity,
        status=IncidentStatus.OPEN,
        category=row.category,
        actor_type=ActorType.UNKNOWN,
        ai_score=row.ai_score,
        source_ips=[row.source_ip] if row.source_ip else [],
        alert_count=0,
        kill_chain=[],
        mitre=[],
        tags=[],
    )


def _chunks(items: Sequence[str], size: int = 500) -> Iterable[list[str]]:
    for i in range(0, len(items), size):
        yield list(items[i : i + size])


async def _session_ids_by_alert(session: AsyncSession, rows: Sequence[AlertRow]) -> dict[str, set[str]]:
    """Actor-session ids per alert: from ``entities/details.session_id`` and the evidence events' column."""
    ids_by_alert = {r.id: list(r.evidence_event_ids or [])[:_EVIDENCE_IDS_PER_ALERT] for r in rows}
    all_ids = sorted({i for ids in ids_by_alert.values() for i in ids})
    by_event: dict[str, str] = {}
    for chunk in _chunks(all_ids):
        res = await session.execute(
            select(EventRow.id, EventRow.session_id).where(
                EventRow.id.in_(chunk), EventRow.session_id.is_not(None)
            )
        )
        by_event.update({eid: sid for eid, sid in res.all() if sid})
    out: dict[str, set[str]] = {}
    for r in rows:
        found = {by_event[i] for i in ids_by_alert[r.id] if i in by_event}
        for src in ((r.entities or {}).get("session_id"), (r.details or {}).get("session_id")):
            if isinstance(src, str) and src:
                found.add(src)
        out[r.id] = found
    return out


def _correlation_keys(row: AlertRow, session_ids: set[str]) -> dict[str, str]:
    """``{key: kind}``; two alerts sharing any key are candidates for the same incident."""
    keys: dict[str, str] = {}
    if row.source_ip:
        keys[f"ip:{row.source_ip}"] = "ip"
    for sid in session_ids:
        keys[f"session:{sid}"] = "session"
    entities = row.entities or {}
    host, port = entities.get("host"), entities.get("port")
    if host and port:
        keys[f"hostport:{str(host).lower()}:{port}"] = "hostport"
    for cve in scoring.extract_cves(entities, row.tags or [], row.details or {}):
        keys[f"cve:{cve}"] = "cve"
    return keys


async def _find_matching_incident(
    session: AsyncSession, row: AlertRow, keys: dict[str, str], window: timedelta
) -> IncidentRow | None:
    if not keys:
        return None
    cutoff = row.last_seen - window
    candidates = (
        (
            await session.execute(
                select(AlertRow)
                .join(IncidentRow, IncidentRow.id == AlertRow.incident_id)
                .where(
                    AlertRow.id != row.id,
                    AlertRow.last_seen >= cutoff,
                    IncidentRow.status.in_(OPEN_INCIDENT_STATUSES),
                )
                .order_by(AlertRow.last_seen.desc())
                .limit(_MAX_CANDIDATES)
            )
        )
        .scalars()
        .all()
    )
    if not candidates:
        return None
    sessions = await _session_ids_by_alert(session, candidates)
    best: tuple[int, float, str] | None = None
    for cand in candidates:
        shared = keys.keys() & _correlation_keys(cand, sessions[cand.id]).keys()
        if not shared or cand.incident_id is None:
            continue
        rank = (min(_KEY_PRIORITY[keys[k]] for k in shared), -cand.last_seen.timestamp(), cand.incident_id)
        if best is None or rank < best:
            best = rank
    return await session.get(IncidentRow, best[2]) if best else None


def _is_listener_alert(row: AlertRow) -> bool:
    return row.category == AlertCategory.PORT_DEVIATION or row.rule_id.startswith("port.")


def _as_port(value: Any) -> int | None:
    try:
        port = int(str(value))
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


async def _listener_target(session: AsyncSession, row: AlertRow) -> tuple[str | None, int | None]:
    """(host, port) of a port-deviation alert: entities first, then its PORT_CHANGE evidence."""
    entities = row.entities or {}
    port = _as_port(entities.get("port"))
    host: str | None = entities.get("host") or None
    if port is None or host is None:
        for ev in await get_events(session, list(row.evidence_event_ids or [])[:5]):
            sock = ev.port.socket if ev.port else None
            if port is None and sock is not None:
                port = _as_port(sock.port)
            if host is None and ev.host and ev.host.name:
                host = ev.host.name
    return (host.lower() if host else None, port)


async def _port_request_listener(session: AsyncSession, row: AlertRow, window: timedelta) -> AlertRow | None:
    """Port-deviation alert whose port this request-type alert hit within the window after it appeared.

    Host matching is best-effort: when both sides carry a host name they must match, otherwise the port alone
    decides (Gate/HTTP events do not always know the protected host's sensor name).
    """
    if _is_listener_alert(row):
        return None
    events = await get_events(session, list(row.evidence_event_ids or [])[-_EVIDENCE_IDS_PER_ALERT:])
    targets = {
        ((e.host.name.lower() if e.host and e.host.name else None), e.destination.port)
        for e in events
        if e.kind in _REQUEST_KINDS and e.destination is not None and e.destination.port
    }
    if not targets:
        return None
    cutoff = row.last_seen - window
    listeners = (
        (
            await session.execute(
                select(AlertRow)
                .where(
                    or_(AlertRow.category == AlertCategory.PORT_DEVIATION, AlertRow.rule_id.like("port.%")),
                    AlertRow.id != row.id,
                    AlertRow.first_seen >= cutoff,
                    AlertRow.first_seen <= row.last_seen,
                    AlertRow.status != AlertStatus.FALSE_POSITIVE,
                )
                .order_by(AlertRow.first_seen.desc())
                .limit(_MAX_LISTENERS)
            )
        )
        .scalars()
        .all()
    )
    for listener in listeners:
        lhost, lport = await _listener_target(session, listener)
        if lport is None:
            continue
        for rhost, rport in targets:
            if rport == lport and (lhost is None or rhost is None or lhost == rhost):
                return listener
    return None


async def _apply_port_request(
    session: AsyncSession, target: IncidentRow, listener: AlertRow, out: _Outcome
) -> None:
    """Tag the incident(s) and pull an unlinked listener alert into the target incident."""
    _add_tag(target, scoring.TAG_PORT_REQUEST)
    if listener.incident_id is None:
        listener.incident_id = target.id
        await session.flush()
        out.linked_alerts.append(Alert.model_validate(listener))
    elif listener.incident_id != target.id:
        other = await session.get(IncidentRow, listener.incident_id)
        if other is not None and scoring.TAG_PORT_REQUEST not in (other.tags or []):
            _add_tag(other, scoring.TAG_PORT_REQUEST)
            await _recompute(session, other)
            out.also_updated.append(Incident.model_validate(other))


def _add_tag(inc: IncidentRow, tag: str) -> None:
    tags = list(inc.tags or [])
    if tag not in tags:
        tags.append(tag)
        inc.tags = tags


async def _link_sessions(session: AsyncSession, incident_id: str, session_ids: set[str]) -> None:
    """Back-link actor sessions (``actor_sessions.incident_id``) that are not linked yet."""
    if not session_ids:
        return
    await session.execute(
        update(ActorSessionRow)
        .where(ActorSessionRow.id.in_(sorted(session_ids)), ActorSessionRow.incident_id.is_(None))
        .values(incident_id=incident_id)
    )


async def _kev_cves(session: AsyncSession, cves: set[str]) -> set[str]:
    if not cves:
        return set()
    res = await session.execute(select(VulnRow.id).where(VulnRow.id.in_(sorted(cves)), VulnRow.kev.is_(True)))
    return set(res.scalars().all())


def _facts(row: AlertRow) -> scoring.AlertFacts:
    return scoring.AlertFacts(
        rule_id=row.rule_id,
        category=row.category,
        severity=row.severity,
        ai_score=row.ai_score,
        tags=list(row.tags or []),
        entities=dict(row.entities or {}),
    )


async def _recompute(session: AsyncSession, inc: IncidentRow) -> None:
    rows = list(
        (await session.execute(select(AlertRow).where(AlertRow.incident_id == inc.id))).scalars().all()
    )
    if not rows:
        return
    settings = get_settings()
    threshold = settings.detection.ai_agent_threshold
    active = [r for r in rows if r.status != AlertStatus.FALSE_POSITIVE] or rows
    facts = [_facts(r) for r in active]

    base = scoring.max_severity(r.severity for r in active)
    ai_score = scoring.max_score(r.ai_score for r in active)
    cves: set[str] = set()
    for r in active:
        cves |= scoring.extract_cves(r.entities or {}, r.tags or [], r.details or {})
    kev = await _kev_cves(session, cves)
    tags = list(inc.tags or [])
    boost = scoring.boosted_severity(
        base,
        ai_score=ai_score,
        ai_threshold=threshold,
        kev_cves=sorted(kev),
        port_request=scoring.TAG_PORT_REQUEST in tags,
    )
    for tag in boost.tags:
        if tag not in tags:
            tags.append(tag)

    classes = (
        await session.execute(
            select(ActorSessionRow.classification).where(ActorSessionRow.incident_id == inc.id)
        )
    ).scalars()
    actor = scoring.infer_actor_type(
        facts, ai_score=ai_score, ai_threshold=threshold, session_classifications=[str(c) for c in classes]
    )
    if actor == ActorType.UNKNOWN and inc.triage:
        # Rules could not attribute: accept a (non-rule) LLM verdict as the tie-breaker (requirements §6-8).
        try:
            record = TriageRecord.model_validate(inc.triage)
        except ValueError:
            record = None
        if record is not None and record.tier != "rules":
            actor = ActorType(record.result.actor_type)

    ordered = sorted(rows, key=lambda r: r.first_seen)
    top = sorted(active, key=lambda r: (-Severity(r.severity).rank, r.first_seen))[0]
    source_ips = list(dict.fromkeys(r.source_ip for r in ordered if r.source_ip))
    kill_chain = killchain.order_tactics(
        t for r in active for t in killchain.tactics_for_alert(r.mitre or [], r.category)
    )

    inc.severity = boost.severity
    inc.ai_score = ai_score
    inc.kill_chain = kill_chain
    inc.mitre = list(dict.fromkeys(m for r in ordered for m in (r.mitre or [])))
    inc.source_ips = source_ips
    inc.alert_count = len(rows)
    inc.first_seen = min(r.first_seen for r in rows)
    inc.last_seen = max(r.last_seen for r in rows)
    inc.category = scoring.primary_category(facts)
    inc.actor_type = actor
    inc.tags = tags
    lang = settings.llm.output_language
    inc.title = _title(top.title, source_ips, len(rows), lang)
    if not inc.triage:
        inc.summary = _summary(len(rows), boost, kill_chain, source_ips, lang)
    await session.flush()


def _title(top_title: str, source_ips: list[str], n: int, lang: str) -> str:
    prefix = f"[{source_ips[0]}] " if source_ips else ""
    more = n - 1
    suffix = ""
    if more > 0:
        suffix = f" 他{more}件" if lang == "ja" else f" (+{more} more)"
    return (prefix + top_title[:400] + suffix)[:512]


def _summary(n: int, boost: scoring.BoostResult, kill_chain: list[str], ips: list[str], lang: str) -> str:
    tactics = ", ".join(kill_chain)
    sources = ", ".join(ips[:5])
    if lang == "ja":
        text = (
            f"{n}件のアラートを相関（最大重大度: {boost.severity}、戦術: {tactics or 'なし'}、"
            f"送信元: {sources or '不明'}）。"
        )
        if boost.reasons:
            text += " 引き上げ理由: " + "; ".join(boost.reasons)
        return text
    text = (
        f"{n} correlated alert(s) (max severity: {boost.severity}, tactics: {tactics or 'none'}, "
        f"sources: {sources or 'unknown'})."
    )
    if boost.reasons:
        text += " Boosted: " + "; ".join(boost.reasons)
    return text
