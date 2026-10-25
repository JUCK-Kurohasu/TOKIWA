"""Evidence selection, compaction and validation for triage (FR-07, requirements 7-5).

Why compaction: the LLM only needs the parts of an event that carry signal. For HTTP that is the request line,
a short body prefix, a few headers, status and timing. Everything else (``raw``, full header maps, labels) is
dropped before redaction + the untrusted-data envelope, which keeps prompts cheap and shrinks the injection
surface.

Why validation: the model may cite ids that were never shown (hallucination or injected text). Only ids of
events that were actually put into the prompt are accepted; the rest are recorded as rejected.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.correlate.scoring import extract_cves
from tokiwa.db.models.detection import AlertRow, IncidentRow
from tokiwa.db.models.intel import VulnRow
from tokiwa.db.models.telemetry import ActorSessionRow
from tokiwa.pipeline.store import get_events
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind

BODY_HEAD_CHARS = 512
# Request headers worth showing to the model (values are redacted by untrusted_block()).
HTTP_HEADER_ALLOW = (
    "user-agent",
    "referer",
    "origin",
    "content-type",
    "accept",
    "accept-language",
    "accept-encoding",
    "x-forwarded-for",
    "x-requested-with",
    "next-action",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-ch-ua",
)
_NON_HTTP_EXCLUDE = {
    "id",
    "timestamp",
    "ingested_at",
    "kind",
    "dataset",
    "source",
    "destination",
    "host",
    "session_id",
    "tags",
    "labels",
    "sensor_id",
    "asset_id",
    "raw",  # never sent to the LLM (forensics only)
    "http",
}
MAX_SUBJECT_ALERTS = 20
MAX_SESSIONS = 5
MAX_VULNS = 10


class SubjectAlert(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: Severity
    category: str
    ai_score: float | None = None
    confidence: float = 0.7
    count: int = 1
    mitre: list[str] = Field(default_factory=list)


class TriageSubject(BaseModel):
    """What is being triaged, as shown to the model (inside an untrusted envelope) and to the rule fallback.

    The mock LLM responder parses this block back out of the prompt, so the fallback and the mock produce the
    same verdict for the same input.
    """

    kind: Literal["alert", "incident"]
    id: str
    title: str
    description: str = ""
    severity: Severity
    category: str
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    ai_score: float | None = None
    actor_type: str | None = None  # rule-based attribution (incidents)
    mitre: list[str] = Field(default_factory=list)
    kill_chain: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    entities: dict[str, str] = Field(default_factory=dict)
    cves: list[str] = Field(default_factory=list)
    count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    alerts: list[SubjectAlert] = Field(default_factory=list)


def _subject_alert(row: AlertRow) -> SubjectAlert:
    return SubjectAlert(
        id=row.id,
        rule_id=row.rule_id,
        title=row.title[:300],
        severity=Severity(row.severity),
        category=row.category,
        ai_score=row.ai_score,
        confidence=row.confidence,
        count=row.count,
        mitre=list(row.mitre or [])[:10],
    )


def alert_subject(row: AlertRow) -> TriageSubject:
    return TriageSubject(
        kind="alert",
        id=row.id,
        title=row.title[:500],
        description=(row.description or "")[:2000],
        severity=Severity(row.severity),
        category=row.category,
        confidence=row.confidence,
        ai_score=row.ai_score,
        mitre=list(row.mitre or []),
        rule_ids=[row.rule_id],
        source_ips=[row.source_ip] if row.source_ip else [],
        tags=list(row.tags or []),
        entities=dict(row.entities or {}),
        cves=sorted(extract_cves(row.entities or {}, row.tags or [], row.details or {})),
        count=row.count,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
    )


def incident_subject(row: IncidentRow, alerts: Sequence[AlertRow]) -> TriageSubject:
    ordered = sorted(alerts, key=lambda a: (-Severity(a.severity).rank, -a.last_seen.timestamp()))
    entities: dict[str, str] = {}
    cves: set[str] = set()
    tags: list[str] = list(row.tags or [])
    for a in reversed(ordered):  # most severe alert wins on key collisions
        entities.update(a.entities or {})
        cves |= extract_cves(a.entities or {}, a.tags or [], a.details or {})
        tags.extend(t for t in (a.tags or []) if t not in tags)
    confidences = [a.confidence for a in alerts] or [0.7]
    return TriageSubject(
        kind="incident",
        id=row.id,
        title=row.title[:500],
        description=(row.summary or "")[:2000],
        severity=Severity(row.severity),
        category=row.category,
        confidence=max(confidences),
        ai_score=row.ai_score,
        actor_type=row.actor_type,
        mitre=list(row.mitre or []),
        kill_chain=list(row.kill_chain or []),
        rule_ids=list(dict.fromkeys(a.rule_id for a in ordered)),
        source_ips=list(row.source_ips or []),
        tags=tags[:50],
        entities=entities,
        cves=sorted(cves),
        count=row.alert_count,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        alerts=[_subject_alert(a) for a in ordered[:MAX_SUBJECT_ALERTS]],
    )


def _preference(ids: Sequence[str]) -> list[str]:
    """First evidence (the trigger) then newest -> oldest."""
    if not ids:
        return []
    return list(dict.fromkeys([ids[0], *reversed(ids[1:])]))


def select_alert_evidence(ids: Sequence[str], limit: int) -> list[str]:
    return _preference(ids)[: max(0, limit)]


def select_incident_evidence(alerts: Sequence[AlertRow], limit: int) -> list[str]:
    """Round-robin over alerts (most severe first) so every alert contributes before any gets a second slot."""
    ordered = sorted(alerts, key=lambda a: (-Severity(a.severity).rank, -a.last_seen.timestamp()))
    queues = [_preference(list(a.evidence_event_ids or [])) for a in ordered]
    out: list[str] = []
    seen: set[str] = set()
    depth = 0
    while len(out) < limit and any(depth < len(q) for q in queues):
        for q in queues:
            if depth < len(q) and q[depth] not in seen:
                seen.add(q[depth])
                out.append(q[depth])
                if len(out) >= limit:
                    break
        depth += 1
    return out


def _endpoint(ep: Any) -> dict[str, Any]:
    return {
        k: v
        for k, v in ep.model_dump(mode="json", exclude_none=True).items()
        if k in ("ip", "port", "geo_country", "asn_org")
    }


def compact_event(event: Event) -> dict[str, Any]:
    """Signal-bearing subset of an event for the prompt (still untrusted: wrap with untrusted_block)."""
    d: dict[str, Any] = {
        "id": event.id,
        "ts": event.timestamp.isoformat(),
        "kind": str(event.kind),
        "dataset": event.dataset,
    }
    if event.source is not None:
        d["src"] = _endpoint(event.source)
    if event.destination is not None:
        d["dst"] = _endpoint(event.destination)
    if event.host is not None and event.host.name:
        d["host"] = event.host.name
    if event.session_id:
        d["session_id"] = event.session_id
    if event.tags:
        d["tags"] = event.tags[:10]
    if event.http is not None:
        h = event.http
        http: dict[str, Any] = {
            "method": h.method,
            "host": h.host,
            "path": h.path,
            "query": h.query,
            "status": h.status,
            "duration_ms": h.duration_ms,
            "response_size": h.response_size,
            "request_body_size": h.request_body_size,
            "content_type": h.content_type,
        }
        headers = {k.lower(): v for k, v in h.headers.items() if k.lower() in HTTP_HEADER_ALLOW}
        if h.user_agent and "user-agent" not in headers:
            headers["user-agent"] = h.user_agent
        if headers:
            http["headers"] = headers
        if h.header_order:
            http["header_order"] = h.header_order[:30]
        if h.request_body:
            http["body_head"] = h.request_body[:BODY_HEAD_CHARS]
        d["http"] = {k: v for k, v in http.items() if v not in (None, "", [], {})}
    if event.kind != EventKind.HTTP or event.http is None:
        d.update(event.model_dump(mode="json", exclude_none=True, exclude=_NON_HTTP_EXCLUDE))
    return d


def validate_evidence_ids(cited: Iterable[str], allowed: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split cited ids into (valid, rejected). Order is preserved and duplicates removed."""
    allowed_set = set(allowed)
    valid: list[str] = []
    rejected: list[str] = []
    for raw in cited:
        eid = str(raw).strip()
        if not eid:
            continue
        bucket = valid if eid in allowed_set else rejected
        if eid not in bucket:
            bucket.append(eid)
    return valid, rejected


def _norm_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def normalize_action_target(target: str, evidence_ips: Iterable[str]) -> str | None:
    """Return the canonical IP if ``target`` is a single IP that appears as a *source* IP in the evidence.

    Deliberately strict (AGENTS.md §2-2): CIDRs, hostnames, URLs and destination (our own) addresses are
    refused, so model text can never widen the blast radius of a proposal.
    """
    ip = _norm_ip(target)
    if ip is None:
        return None
    allowed = {n for n in (_norm_ip(x) for x in evidence_ips) if n}
    return ip if ip in allowed else None


@dataclass
class TriageContext:
    """Everything the prompt (and the action validator) is built from."""

    evidence_ids: list[str] = field(default_factory=list)  # ids of events actually loaded and shown
    events: list[Event] = field(default_factory=list)
    sessions: list[dict[str, Any]] = field(default_factory=list)
    vulns: list[dict[str, Any]] = field(default_factory=list)

    @property
    def source_ips(self) -> list[str]:
        return list(dict.fromkeys(e.source.ip for e in self.events if e.source is not None and e.source.ip))


async def load_context(
    session: AsyncSession, subject: TriageSubject, candidate_ids: Sequence[str]
) -> TriageContext:
    events = await get_events(session, list(candidate_ids))
    events.sort(key=lambda e: e.timestamp)
    ctx = TriageContext(evidence_ids=[e.id for e in events], events=events)

    session_ids = list(dict.fromkeys(e.session_id for e in events if e.session_id))
    if subject.entities.get("session_id"):
        session_ids.insert(0, subject.entities["session_id"])
    if session_ids:
        rows = (
            (await session.execute(select(ActorSessionRow).where(ActorSessionRow.id.in_(session_ids[:50]))))
            .scalars()
            .all()
        )
        rows = sorted(rows, key=lambda r: -(r.ai_score or 0.0))[:MAX_SESSIONS]
        ctx.sessions = [
            {
                "id": r.id,
                "source_ip": r.source_ip,
                "user_agent": r.user_agent,
                "first_seen": r.first_seen.isoformat(),
                "last_seen": r.last_seen.isoformat(),
                "request_count": r.request_count,
                "error_count": r.error_count,
                "unique_paths": r.unique_paths,
                "ai_score": r.ai_score,
                "classification": r.classification,
                "features": r.features,
            }
            for r in rows
        ]
    if subject.cves:
        vulns = (
            (await session.execute(select(VulnRow).where(VulnRow.id.in_(subject.cves[:50])))).scalars().all()
        )
        vulns = sorted(vulns, key=lambda v: (not v.kev, -(v.epss or 0.0)))[:MAX_VULNS]
        ctx.vulns = [
            {
                "id": v.id,
                "title": (v.title or "")[:300],
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "epss": v.epss,
                "kev": v.kev,
                "kev_ransomware": v.kev_ransomware,
                "cwe": v.cwe,
                "published": v.published.isoformat() if v.published else None,
            }
            for v in vulns
        ]
    return ctx
