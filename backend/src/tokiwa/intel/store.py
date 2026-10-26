"""Merge vulnerability records from many feeds into ``vulns`` and news into ``intel_items``.

ID normalisation
----------------
- A record is keyed by its CVE id whenever one is known (``id`` itself or any alias); GHSA / JVNDB / OSV ids
  then live in ``aliases``. Records without a CVE keep their own id (``GHSA-…``, ``JVNDB-…``, ``PYSEC-…``).
- *Alias folding*: when a CVE-keyed record lists an alias that is stored as its own row (e.g. a GHSA advisory
  stored before GitHub assigned the CVE), that row is folded into the CVE row and deleted; ``vuln_matches``
  pointing at the old id are re-pointed. Conversely a non-CVE record whose id is already an alias of a CVE row
  is merged into that CVE row instead of creating a duplicate.

Field ownership / precedence (``FIELD_PRECEDENCE``; first = most trusted)
-------------------------------------------------------------------------
Each field group remembers which source set it (``data["_prov"]``). An incoming value replaces the stored one
when the stored group is empty, has no provenance, or the incoming source ranks the same or higher. Hence a
source can always refresh its own values, and e.g. NVD's CVSS is never overwritten by GHSA's.

=============  =========================================  ================================================
group          precedence                                 rationale
=============  =========================================  ================================================
cvss           nvd > ghsa > osv > jvn > research          NVD is the CVE program's scoring authority;
severity       nvd > ghsa > osv > jvn > research          GHSA reviews per package; OSV gives vectors only
description    nvd > ghsa > osv > kev > jvn > research    canonical English CVE text first
title          kev > ghsa > osv > nvd > jvn > research    NVD has no title; KEV/GHSA names are curated
published      nvd > ghsa > osv > jvn > kev > research    CVE publication date
kev*           kev > nvd                                  CISA catalog is authoritative; NVD mirrors it
epss*          epss                                       only FIRST computes EPSS
=============  =========================================  ================================================

``modified`` is the max over sources; ``aliases / sources / cwe / affected / references`` are unions (capped);
``data`` is merged per top-level key (each source owns ``data[<source>]``). Unknown sources rank last.
A missing severity is derived from the chosen CVSS score.

Events
------
``upsert_vulns`` reports, and ``publish_updates`` publishes on bus topic ``intel.vuln_updated`` (payload:
``VulnRecord`` whose ``data["update_reasons"]`` lists the reasons; the stored row is not modified):

- ``kev_added``: the kev flag turned on and ``kev_date_added`` is within ``KEV_RECENT_DAYS`` (keeps the very first
  full KEV import from flooding subscribers with ~1.5k old entries);
- ``epss_spike``: a previously known EPSS score rose to >= ``intel.epss_alert_threshold`` from below it, or by at
  least ``EPSS_SPIKE_DELTA`` while above it. A first-ever score does not count (no baseline).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import String, cast, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.bus import bus
from tokiwa.config import get_settings
from tokiwa.db.models.intel import AssetRow, IntelItemRow, VulnMatchRow, VulnRow
from tokiwa.db.session import session_scope
from tokiwa.intel.base import IntelItemIn
from tokiwa.intel.sources._common import (
    is_cve,
    normalize_vuln_id,
    severity_from_score,
    software_from_cpe,
    unique,
)
from tokiwa.schemas.intel import IntelItem, SoftwareItem, VulnRecord
from tokiwa.util import new_id, sha256_hex, utcnow

log = logging.getLogger(__name__)

TOPIC_VULN_UPDATED = "intel.vuln_updated"

KEV_RECENT_DAYS = 14
EPSS_SPIKE_DELTA = 0.1
MAX_EVENTS_PER_UPSERT = 200
MAX_ALIASES = 50
MAX_AFFECTED = 300
MAX_REFERENCES = 150
MAX_EPSS_TARGETS = 5000
_CHUNK = 400
_ALIAS_LIKE_CHUNK = 40
PROV_KEY = "_prov"

FIELD_PRECEDENCE: dict[str, tuple[str, ...]] = {
    "cvss": ("nvd", "ghsa", "osv", "jvn", "research"),
    "severity": ("nvd", "ghsa", "osv", "jvn", "research"),
    "description": ("nvd", "ghsa", "osv", "kev", "jvn", "research"),
    "title": ("kev", "ghsa", "osv", "nvd", "jvn", "research"),
    "published": ("nvd", "ghsa", "osv", "jvn", "kev", "research"),
    "kev": ("kev", "nvd"),
    "epss": ("epss",),
}
GROUP_FIELDS: dict[str, tuple[str, ...]] = {
    "cvss": ("cvss_score", "cvss_vector"),
    "severity": ("severity",),
    "description": ("description",),
    "title": ("title",),
    "published": ("published",),
    "kev": ("kev", "kev_date_added", "kev_due_date", "kev_ransomware"),
    "epss": ("epss", "epss_percentile"),
}
COLUMNS = (
    "aliases",
    "sources",
    "title",
    "description",
    "published",
    "modified",
    "cvss_score",
    "cvss_vector",
    "severity",
    "epss",
    "epss_percentile",
    "kev",
    "kev_date_added",
    "kev_due_date",
    "kev_ransomware",
    "cwe",
    "affected",
    "references",
    "data",
)

State = dict[str, Any]


@dataclass
class VulnUpdate:
    vuln: VulnRecord
    reasons: list[str]


@dataclass
class UpsertResult:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    merged_aliases: int = 0
    ids: list[str] = field(default_factory=list)
    updates: list[VulnUpdate] = field(default_factory=list)


@dataclass
class ItemUpsertResult:
    created: int = 0
    skipped: int = 0


# ---------------------------------------------------------------------------- normalisation


def canonicalize(record: VulnRecord) -> VulnRecord:
    """Return a copy keyed by CVE when one is known, with normalised/unique aliases and sources."""
    rid = normalize_vuln_id(record.id)
    aliases = [normalize_vuln_id(a) for a in record.aliases if a]
    if not is_cve(rid):
        cves = [a for a in aliases if is_cve(a)]
        if cves:
            aliases = [rid, *aliases]
            rid = cves[0]
    return record.model_copy(
        update={
            "id": rid,
            "aliases": [a for a in unique(aliases) if a != rid][:MAX_ALIASES],
            "sources": unique(record.sources),
        }
    )


def _rank(group: str, source: str | None) -> int:
    order = FIELD_PRECEDENCE[group]
    return order.index(source) if source in order else len(order)


def _has(group: str, st: State) -> bool:
    if group == "kev":
        return st.get("kev") is True
    return any(st.get(f) not in (None, "") for f in GROUP_FIELDS[group])


def _empty_state() -> State:
    st: State = {c: None for c in COLUMNS}
    st.update(aliases=[], sources=[], cwe=[], affected=[], references=[], data={}, kev=False)
    return st


def _row_state(row: VulnRow) -> State:
    return {c: getattr(row, c) for c in COLUMNS}


def _record_state(rec: VulnRecord) -> State:
    st = _empty_state()
    st.update(
        aliases=list(rec.aliases),
        sources=list(rec.sources),
        title=rec.title,
        description=rec.description,
        published=rec.published,
        modified=rec.modified,
        cvss_score=rec.cvss_score,
        cvss_vector=rec.cvss_vector,
        severity=rec.severity.value if rec.severity is not None else None,
        epss=rec.epss,
        epss_percentile=rec.epss_percentile,
        kev=rec.kev,
        kev_date_added=rec.kev_date_added,
        kev_due_date=rec.kev_due_date,
        kev_ransomware=rec.kev_ransomware,
        cwe=list(rec.cwe),
        affected=[a.model_dump() for a in rec.affected],
        references=list(rec.references),
    )
    if st["severity"] is None and rec.cvss_score is not None:
        # Keep score and severity consistent per source; otherwise a higher-precedence score could end up
        # paired with a lower-precedence source's severity.
        derived = severity_from_score(rec.cvss_score)
        st["severity"] = derived.value if derived else None
    src = rec.sources[0] if rec.sources else "unknown"
    prov = {g: src for g in GROUP_FIELDS if _has(g, st)}
    st["data"] = {**{k: v for k, v in rec.data.items() if k != PROV_KEY}, PROV_KEY: prov}
    return st


def _affected_key(a: dict[str, Any]) -> tuple[str, ...]:
    return (
        str(a.get("vendor") or "").lower(),
        str(a.get("product") or "").lower(),
        str(a.get("version") or ""),
        str(a.get("cpe") or ""),
        str(a.get("ecosystem") or "").lower(),
    )


def _valid_affected(a: Any) -> dict[str, Any] | None:
    """``SoftwareItem.product`` is required (``VulnRecord.model_validate`` fails otherwise). Entries written by
    other modules with only a CPE get the product derived from it; entries without either are dropped."""
    if not isinstance(a, dict):
        return None
    if a.get("product"):
        return a
    derived = software_from_cpe(str(a.get("cpe") or ""))
    if derived is None:
        return None
    return {
        **a,
        "product": derived.product,
        "vendor": a.get("vendor") or derived.vendor,
        "version": a.get("version") or derived.version,
    }


def _union_affected(*lists: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    out: list[dict[str, Any]] = []
    for lst in lists:
        for raw in lst or []:
            a = _valid_affected(raw)
            if a is None:
                continue
            key = _affected_key(a)
            if key in seen:
                continue
            seen.add(key)
            out.append(a)
            if len(out) >= MAX_AFFECTED:
                return out
    return out


def _max_dt(a: datetime | None, b: datetime | None) -> datetime | None:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def merge_states(base: State, inc: State) -> State:
    """Merge ``inc`` into ``base`` following FIELD_PRECEDENCE (pure function; inputs are not mutated)."""
    out = dict(base)
    base_prov: dict[str, str] = dict((base.get("data") or {}).get(PROV_KEY) or {})
    inc_prov: dict[str, str] = dict((inc.get("data") or {}).get(PROV_KEY) or {})
    fallback = (inc.get("sources") or ["unknown"])[0]
    for group, fields in GROUP_FIELDS.items():
        if not _has(group, inc):
            continue
        inc_src = inc_prov.get(group) or fallback
        base_src = base_prov.get(group)
        if _has(group, base) and base_src is not None and _rank(group, inc_src) > _rank(group, base_src):
            continue
        for f in fields:
            out[f] = inc.get(f)
        base_prov[group] = inc_src
    if not _has("severity", out) and out.get("cvss_score") is not None:
        derived = severity_from_score(out["cvss_score"])
        out["severity"] = derived.value if derived else None
        if "cvss" in base_prov:
            base_prov["severity"] = base_prov["cvss"]
    out["kev"] = bool(out.get("kev"))
    out["modified"] = _max_dt(base.get("modified"), inc.get("modified"))
    out["aliases"] = unique([*(base.get("aliases") or []), *(inc.get("aliases") or [])])[:MAX_ALIASES]
    out["sources"] = unique([*(base.get("sources") or []), *(inc.get("sources") or [])])
    out["cwe"] = unique([*(base.get("cwe") or []), *(inc.get("cwe") or [])])
    out["affected"] = _union_affected(base.get("affected") or [], inc.get("affected") or [])
    out["references"] = unique([*(base.get("references") or []), *(inc.get("references") or [])])[
        :MAX_REFERENCES
    ]
    data = dict(base.get("data") or {})
    data.update({k: v for k, v in (inc.get("data") or {}).items() if k != PROV_KEY})
    data[PROV_KEY] = base_prov
    out["data"] = data
    return out


def _events(before: State | None, after: State, now: datetime, epss_threshold: float) -> list[str]:
    reasons: list[str] = []
    if after.get("kev") and not (before and before.get("kev")):
        added = after.get("kev_date_added")
        if added is None or now - added <= timedelta(days=KEV_RECENT_DAYS):
            reasons.append("kev_added")
    old = before.get("epss") if before else None
    new = after.get("epss")
    if (
        old is not None
        and new is not None
        and new >= epss_threshold
        and (old < epss_threshold or new - old >= EPSS_SPIKE_DELTA)
    ):
        reasons.append("epss_spike")
    return reasons


def state_to_record(vuln_id: str, st: State) -> VulnRecord:
    return VulnRecord.model_validate({"id": vuln_id, **st})


# ---------------------------------------------------------------------------- vulns


async def _load_rows(session: AsyncSession, ids: Iterable[str]) -> dict[str, VulnRow]:
    wanted = list(dict.fromkeys(ids))
    rows: dict[str, VulnRow] = {}
    for i in range(0, len(wanted), _CHUNK):
        chunk = wanted[i : i + _CHUNK]
        res = await session.execute(select(VulnRow).where(VulnRow.id.in_(chunk)))
        for row in res.scalars():
            rows[row.id] = row
    return rows


def _alias_like(alias: str) -> Any:
    return cast(VulnRow.aliases, String).contains(f'"{alias}"', autoescape=True)


async def _rows_by_alias(session: AsyncSession, aliases: Sequence[str]) -> dict[str, VulnRow]:
    """alias -> row whose ``aliases`` contains it (CVE rows preferred)."""
    found: dict[str, VulnRow] = {}
    for i in range(0, len(aliases), _ALIAS_LIKE_CHUNK):
        chunk = list(aliases[i : i + _ALIAS_LIKE_CHUNK])
        res = await session.execute(select(VulnRow).where(or_(*(_alias_like(a) for a in chunk))))
        for row in res.scalars():
            for a in chunk:
                if a in (row.aliases or []) and (a not in found or is_cve(row.id)):
                    found[a] = row
    return found


async def upsert_vulns(
    session: AsyncSession,
    records: Sequence[VulnRecord],
    *,
    now: datetime | None = None,
    epss_threshold: float | None = None,
) -> UpsertResult:
    """Merge ``records`` into ``vulns`` (no commit; caller owns the transaction). See module docstring."""
    now = now or utcnow()
    threshold = get_settings().intel.epss_alert_threshold if epss_threshold is None else epss_threshold
    result = UpsertResult()
    if not records:
        return result
    canon = [canonicalize(r) for r in records]
    wanted = {r.id for r in canon}
    wanted |= {a for r in canon if is_cve(r.id) for a in r.aliases if not is_cve(a)}
    rows = await _load_rows(session, wanted)

    orphans = unique(r.id for r in canon if not is_cve(r.id) and r.id not in rows)
    if orphans:
        by_alias = await _rows_by_alias(session, orphans)
        redirected: list[VulnRecord] = []
        for r in canon:
            target = by_alias.get(r.id)
            if target is not None:
                rows.setdefault(target.id, target)
                r = r.model_copy(update={"id": target.id, "aliases": unique([r.id, *r.aliases])})
            redirected.append(r)
        canon = redirected

    originals = {rid: _row_state(row) for rid, row in rows.items()}
    states: dict[str, State] = {rid: dict(st) for rid, st in originals.items()}
    folded: dict[str, str] = {}  # old id -> new CVE id
    reasons: dict[str, list[str]] = {}

    for rec in canon:
        base = states.get(rec.id)
        if is_cve(rec.id):
            for alias in rec.aliases:
                if alias != rec.id and not is_cve(alias) and alias in states and alias not in folded:
                    old = states.pop(alias)
                    base = merge_states(old, base) if base is not None else old
                    folded[alias] = rec.id
        after = merge_states(base if base is not None else _empty_state(), _record_state(rec))
        after["aliases"] = [a for a in after["aliases"] if a != rec.id]
        states[rec.id] = after
        for reason in _events(base, after, now, threshold):
            if reason not in reasons.setdefault(rec.id, []):
                reasons[rec.id].append(reason)

    for old_id, new_id_ in folded.items():
        if old_id in rows:
            await session.delete(rows[old_id])
            await session.execute(
                update(VulnMatchRow).where(VulnMatchRow.vuln_id == old_id).values(vuln_id=new_id_)
            )
        result.merged_aliases += 1
    if folded:
        await session.flush()  # deletes first: a folded id must not collide with later inserts

    for rid, st in states.items():
        row = rows.get(rid)
        if row is None:
            session.add(VulnRow(id=rid, updated_at=now, **st))
            result.created += 1
        elif st != originals.get(rid):
            for col in COLUMNS:
                setattr(row, col, st[col])
            row.updated_at = now
            result.updated += 1
        else:
            result.unchanged += 1
        result.ids.append(rid)
    await session.flush()

    for rid, rs in reasons.items():
        if rid in states:
            result.updates.append(VulnUpdate(vuln=state_to_record(rid, states[rid]), reasons=rs))
    return result


async def publish_updates(updates: Sequence[VulnUpdate]) -> int:
    """Publish ``intel.vuln_updated`` (call after the transaction committed so subscribers see the rows)."""
    if len(updates) > MAX_EVENTS_PER_UPSERT:
        log.warning("intel: %d vuln updates; publishing the first %d", len(updates), MAX_EVENTS_PER_UPSERT)
    sent = 0
    for upd in updates[:MAX_EVENTS_PER_UPSERT]:
        payload = upd.vuln.model_copy(update={"data": {**upd.vuln.data, "update_reasons": list(upd.reasons)}})
        await bus.publish(TOPIC_VULN_UPDATED, payload)
        sent += 1
    return sent


# ---------------------------------------------------------------------------- news items


def url_hash(url: str | None, source: str, title: str) -> str:
    """sha256 of the normalised URL (scheme/host lower-cased, fragment dropped); title-based when no URL."""
    if url and url.strip():
        parts = urlsplit(url.strip())
        norm = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))
        return sha256_hex(norm)
    return sha256_hex(f"{source}\n{title.strip()}")


async def upsert_items(
    session: AsyncSession, items: Sequence[IntelItemIn], *, now: datetime | None = None
) -> ItemUpsertResult:
    """Insert news items that are not stored yet (dedup by ``url_hash``, also within the batch)."""
    now = now or utcnow()
    result = ItemUpsertResult()
    batch: dict[str, IntelItemIn] = {}
    for it in items:
        h = url_hash(it.url, it.source, it.title)
        if h in batch:
            result.skipped += 1
            continue
        batch[h] = it
    hashes = list(batch)
    existing: set[str] = set()
    for i in range(0, len(hashes), _CHUNK):
        res = await session.execute(
            select(IntelItemRow.url_hash).where(IntelItemRow.url_hash.in_(hashes[i : i + _CHUNK]))
        )
        existing.update(h for h in res.scalars() if h)
    for h, it in batch.items():
        if h in existing:
            result.skipped += 1
            continue
        session.add(
            IntelItemRow(
                id=new_id(),
                source=it.source[:64],
                url=it.url,
                url_hash=h,
                title=it.title[:1000],
                summary=it.summary,
                published=it.published,
                fetched_at=now,
                vuln_ids=unique(normalize_vuln_id(v) for v in it.vuln_ids),
                tags=list(it.tags),
            )
        )
        result.created += 1
    await session.flush()
    return result


# ---------------------------------------------------------------------------- queries (API / CLI)


def _like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def query_vulns(
    session: AsyncSession,
    *,
    q: str | None = None,
    kev: bool | None = None,
    min_epss: float | None = None,
    min_cvss: float | None = None,
    matched: bool | None = None,
    source: str | None = None,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[VulnRecord], int]:
    """Filtered page of vulns, ordered KEV -> EPSS -> CVSS -> modified (NULLs last)."""
    stmt = select(VulnRow)
    if q:
        pattern = f"%{_like(q.strip())}%"
        stmt = stmt.where(
            or_(
                VulnRow.id.ilike(pattern, escape="\\"),
                VulnRow.title.ilike(pattern, escape="\\"),
                VulnRow.description.ilike(pattern, escape="\\"),
                cast(VulnRow.aliases, String).ilike(pattern, escape="\\"),
            )
        )
    if kev is not None:
        stmt = stmt.where(VulnRow.kev.is_(kev))
    if min_epss is not None:
        stmt = stmt.where(VulnRow.epss >= min_epss)
    if min_cvss is not None:
        stmt = stmt.where(VulnRow.cvss_score >= min_cvss)
    if severity:
        stmt = stmt.where(VulnRow.severity == severity)
    if source:
        stmt = stmt.where(cast(VulnRow.sources, String).contains(f'"{source}"', autoescape=True))
    if matched is not None:
        exists = (
            select(VulnMatchRow.id)
            .where(VulnMatchRow.vuln_id == VulnRow.id, VulnMatchRow.status != "false_positive")
            .exists()
        )
        stmt = stmt.where(exists if matched else ~exists)
    total = (await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    stmt = stmt.order_by(
        VulnRow.kev.desc(),
        VulnRow.epss.desc().nulls_last(),
        VulnRow.cvss_score.desc().nulls_last(),
        VulnRow.modified.desc().nulls_last(),
        VulnRow.id,
    )
    rows = (await session.execute(stmt.limit(limit).offset(offset))).scalars().all()
    return [VulnRecord.model_validate(r) for r in rows], int(total)


async def get_vuln_row(session: AsyncSession, vuln_id: str) -> VulnRow | None:
    """Lookup by id (case-normalised) or by alias (GHSA / JVNDB id of a CVE row)."""
    vid = normalize_vuln_id(vuln_id)
    row = await session.get(VulnRow, vid)
    if row is not None:
        return row
    found = await _rows_by_alias(session, [vid])
    return found.get(vid)


async def query_items(
    session: AsyncSession,
    *,
    source: str | None = None,
    q: str | None = None,
    vuln_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[IntelItem], int]:
    stmt = select(IntelItemRow)
    if source:
        if ":" in source:
            stmt = stmt.where(IntelItemRow.source == source)
        else:  # "rss" matches every "rss:<host>"
            stmt = stmt.where(
                or_(
                    IntelItemRow.source == source, IntelItemRow.source.like(f"{_like(source)}:%", escape="\\")
                )
            )
    if q:
        pattern = f"%{_like(q.strip())}%"
        stmt = stmt.where(
            or_(
                IntelItemRow.title.ilike(pattern, escape="\\"),
                IntelItemRow.summary.ilike(pattern, escape="\\"),
            )
        )
    if vuln_id:
        stmt = stmt.where(
            cast(IntelItemRow.vuln_ids, String).contains(f'"{normalize_vuln_id(vuln_id)}"', autoescape=True)
        )
    total = (await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    stmt = stmt.order_by(IntelItemRow.published.desc().nulls_last(), IntelItemRow.fetched_at.desc())
    rows = (await session.execute(stmt.limit(limit).offset(offset))).scalars().all()
    return [IntelItem.model_validate(r) for r in rows], int(total)


# ---------------------------------------------------------------------------- sync helpers


async def epss_targets(collected: Iterable[str] = (), *, limit: int = MAX_EPSS_TARGETS) -> list[str]:
    """CVE ids to (re)score: touched this run, never scored, KEV / asset-matched, then a rolling refresh."""
    ordered: list[str] = [c for c in collected if is_cve(c)]
    async with session_scope() as s:
        never = await s.execute(
            select(VulnRow.id)
            .where(VulnRow.epss.is_(None), VulnRow.id.like("CVE-%"))
            .order_by(VulnRow.modified.desc().nulls_last())
            .limit(1000)
        )
        ordered += list(never.scalars())
        kev = await s.execute(select(VulnRow.id).where(VulnRow.kev.is_(True)).limit(3000))
        ordered += list(kev.scalars())
        matched = await s.execute(
            select(VulnMatchRow.vuln_id).where(VulnMatchRow.status != "false_positive").distinct().limit(3000)
        )
        ordered += [v for v in matched.scalars() if is_cve(v)]
        rolling = await s.execute(
            select(VulnRow.id)
            .where(VulnRow.epss.is_not(None), VulnRow.id.like("CVE-%"))
            .order_by(VulnRow.updated_at.asc())
            .limit(500)
        )
        ordered += list(rolling.scalars())
    return unique(ordered)[:limit]


async def asset_packages() -> list[SoftwareItem]:
    """Inventory software usable for OSV queries (needs ecosystem + product + version)."""
    out: list[SoftwareItem] = []
    async with session_scope() as s:
        res = await s.execute(select(AssetRow.software))
        for software in res.scalars():
            for raw in software or []:
                try:
                    item = SoftwareItem.model_validate(raw)
                except ValueError:
                    continue
                if item.ecosystem and item.version:
                    out.append(item)
    return out


async def known_osv_ids() -> set[str]:
    out: set[str] = set()
    async with session_scope() as s:
        res = await s.execute(
            select(VulnRow.data).where(cast(VulnRow.sources, String).contains('"osv"', autoescape=True))
        )
        for data in res.scalars():
            osv_id = ((data or {}).get("osv") or {}).get("id")
            if osv_id:
                out.add(str(osv_id))
    return out
