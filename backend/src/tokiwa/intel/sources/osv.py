"""OSV.dev — vulnerabilities for the open-source packages in the asset inventory.

API (https://google.github.io/osv.dev/api/ and https://osv.dev/docs/osv_service_v1.swagger.json, checked
2026-10-22):
- ``POST https://api.osv.dev/v1/querybatch`` with ``{"queries": [{"package": {"name", "ecosystem"},
  "version"}]}``; up to 1000 queries per request. ``results[i]`` answers ``queries[i]`` and contains only
  ``vulns[{id, modified}]`` (plus ``next_page_token`` when a query has more results; re-send that query with
  ``page_token``).
- Full records: ``GET https://api.osv.dev/v1/vulns/{id}`` (OSV schema https://ossf.github.io/osv-schema/):
  ``id, modified, published, withdrawn, aliases[], summary, details, severity[{type: CVSS_V3|CVSS_V4|…,
  score: <vector string>}], affected[{package{ecosystem,name,purl}, ranges[{type, events[{introduced|fixed|
  last_affected|limit}]}], versions[], database_specific, ecosystem_specific}], references[{type,url}],
  database_specific{severity, cwe_ids, …}``.
- No API key. TODO(verify): documented rate limits / fair-use policy and the data licence statement (OSV
  aggregates sources with their own licences; most are CC-BY 4.0).

Scope: OSV is only queried for asset software that has ``ecosystem`` + ``product`` + ``version`` (no assets ->
the source is skipped). ``intel.sync`` passes the package list through :meth:`OsvSource.prepare`.
OSV ``severity[].score`` is a CVSS *vector*; we keep it as ``cvss_vector`` without computing a numeric score
(NVD/GHSA usually provide one; store precedence prefers them). Ranges/versions are kept in
``data["osv"]["affected"]`` for ``intel.matcher``; ``data["osv"]["matched_packages"]`` records which inventory
packages produced the hit.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any
from urllib.parse import quote

import httpx

from tokiwa.config import Settings
from tokiwa.intel.base import IntelSource, SourceResult, register_source
from tokiwa.intel.sources._common import (
    FetchError,
    Sleep,
    default_sleep,
    fetch,
    is_cve,
    normalize_vuln_id,
    parse_dt,
    severity_from_text,
    unique,
    unique_software,
)
from tokiwa.schemas.intel import SoftwareItem, VulnRecord

log = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1"
MAX_QUERIES_PER_BATCH = 1000
MAX_PAGE_ROUNDS = 3
MAX_DETAIL_FETCHES = 300
MAX_VERSIONS_KEPT = 200
DETAIL_CONCURRENCY = 4


def osv_queries(packages: list[SoftwareItem]) -> list[dict[str, Any]]:
    """Unique querybatch entries for packages that have ecosystem + name + version."""
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for p in packages:
        if not (p.ecosystem and p.product and p.version):
            continue
        key = (p.ecosystem, p.product, p.version)
        if key in seen:
            continue
        seen.add(key)
        out.append({"package": {"name": p.product, "ecosystem": p.ecosystem}, "version": p.version})
    return out


def parse_osv_vuln(vuln: dict[str, Any], matched: list[dict[str, Any]] | None = None) -> VulnRecord | None:
    if vuln.get("withdrawn"):
        return None
    osv_id = normalize_vuln_id(str(vuln["id"]))
    aliases = [normalize_vuln_id(str(a)) for a in vuln.get("aliases") or []]
    cves = [a for a in [osv_id, *aliases] if is_cve(a)]
    record_id = cves[0] if cves else osv_id
    vector = None
    for sev in vuln.get("severity") or []:
        if str(sev.get("type", "")).startswith("CVSS_V3") and sev.get("score"):
            vector = str(sev["score"])
            break
    if vector is None:
        vector = next((str(s["score"]) for s in vuln.get("severity") or [] if s.get("score")), None)
    db = vuln.get("database_specific") or {}
    affected: list[SoftwareItem] = []
    affected_data: list[dict[str, Any]] = []
    for a in vuln.get("affected") or []:
        pkg = a.get("package") or {}
        if pkg.get("name"):
            affected.append(SoftwareItem(product=str(pkg["name"]), ecosystem=pkg.get("ecosystem")))
        versions = a.get("versions") or []
        affected_data.append(
            {
                "package": pkg,
                "ranges": a.get("ranges") or [],
                "versions": versions[:MAX_VERSIONS_KEPT],
                "versions_truncated": len(versions) > MAX_VERSIONS_KEPT,
            }
        )
    return VulnRecord(
        id=record_id,
        aliases=unique(a for a in [osv_id, *aliases] if a != record_id),
        sources=["osv"],
        title=(vuln.get("summary") or "").strip() or None,
        description=(vuln.get("details") or "").strip() or None,
        published=parse_dt(vuln.get("published")),
        modified=parse_dt(vuln.get("modified")),
        cvss_vector=vector,
        severity=severity_from_text(db.get("severity")),
        cwe=unique(str(c).upper() for c in db.get("cwe_ids") or []),
        affected=unique_software(affected),
        references=unique(str(r.get("url")) for r in vuln.get("references") or [] if r.get("url")),
        data={"osv": {"id": osv_id, "affected": affected_data, "matched_packages": matched or []}},
    )


@register_source
class OsvSource(IntelSource):
    id = "osv"
    name = "OSV.dev"
    attribution = "OSV.dev open source vulnerability database"
    api = OSV_API

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.sleep: Sleep = default_sleep
        self.packages: list[SoftwareItem] = []
        # OSV ids already stored; their details are only re-fetched when OSV reports a newer ``modified``.
        self.known_osv_ids: set[str] = set()

    async def prepare(self, collected_cves: set[str]) -> None:
        from tokiwa.intel.store import asset_packages, known_osv_ids

        self.packages = await asset_packages()
        self.known_osv_ids = await known_osv_ids()

    async def _querybatch(
        self, client: httpx.AsyncClient, queries: list[dict[str, Any]], result: SourceResult
    ) -> dict[str, tuple[datetime | None, list[dict[str, Any]]]]:
        hits: dict[str, tuple[datetime | None, list[dict[str, Any]]]] = {}
        for start in range(0, len(queries), MAX_QUERIES_PER_BATCH):
            pending = queries[start : start + MAX_QUERIES_PER_BATCH]
            for _round in range(MAX_PAGE_ROUNDS):
                if not pending:
                    break
                try:
                    resp = await fetch(
                        client,
                        "POST",
                        f"{self.api}/querybatch",
                        json_body={"queries": pending},
                        headers={"Accept": "application/json"},
                        sleep=self.sleep,
                    )
                    results = resp.json().get("results") or []
                except (FetchError, ValueError, AttributeError) as exc:
                    result.errors.append(f"osv: querybatch: {exc}")
                    break
                follow: list[dict[str, Any]] = []
                for query, res in zip(pending, results, strict=False):
                    pkg = {**query["package"], "version": query.get("version")}
                    for v in (res or {}).get("vulns") or []:
                        vid = str(v.get("id", ""))
                        if not vid:
                            continue
                        modified, matched = hits.get(vid, (None, []))
                        hits[vid] = (parse_dt(v.get("modified")) or modified, [*matched, pkg])
                    token = (res or {}).get("next_page_token")
                    if token:
                        follow.append(
                            {**{k: v for k, v in query.items() if k != "page_token"}, "page_token": token}
                        )
                pending = follow
        return hits

    async def fetch(self, client: httpx.AsyncClient, since: datetime | None) -> SourceResult:
        result = SourceResult()
        queries = osv_queries(self.packages)
        if not queries:
            log.info("osv: no asset packages with ecosystem+version; skipped")
            return result
        hits = await self._querybatch(client, queries, result)
        todo = [
            vid
            for vid, (modified, _) in hits.items()
            if not (
                vid in self.known_osv_ids and since is not None and modified is not None and modified <= since
            )
        ]
        if len(todo) > MAX_DETAIL_FETCHES:
            result.errors.append(f"osv: {len(todo)} vulns matched; fetched the first {MAX_DETAIL_FETCHES}")
            todo = todo[:MAX_DETAIL_FETCHES]
        sem = asyncio.Semaphore(DETAIL_CONCURRENCY)

        async def one(vid: str) -> None:
            async with sem:
                try:
                    resp = await fetch(
                        client, "GET", f"{self.api}/vulns/{quote(vid, safe='')}", sleep=self.sleep
                    )
                    rec = parse_osv_vuln(resp.json(), hits[vid][1])
                except (FetchError, KeyError, TypeError, ValueError) as exc:
                    result.errors.append(f"osv: {vid}: {exc}")
                    return
                if rec is not None:
                    result.vulns.append(rec)

        await asyncio.gather(*(one(v) for v in todo))
        log.info("osv: %d packages, %d vulns matched, %d fetched", len(queries), len(hits), len(result.vulns))
        return result
