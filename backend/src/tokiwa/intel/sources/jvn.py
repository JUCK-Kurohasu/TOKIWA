"""JVN iPedia via the MyJVN API (``getVulnOverviewList``) — Japanese vulnerability overviews.

API (https://jvndb.jvn.jp/apis/ , https://jvndb.jvn.jp/apis/myjvn/ ; checked 2026-10-22 as far as reachable):
- ``GET https://jvndb.jvn.jp/myjvn?method=getVulnOverviewList&feed=hnd&…`` returns JVNRSS 3.2
  (RSS 1.0 / RDF + ``mod_sec`` 3.0 namespace ``http://jvn.jp/rss/mod_sec/3.0/``). Items carry ``title, link,
  description, sec:identifier (JVNDB-YYYY-NNNNNN), sec:references[@source,@id] (CVE / JVN / vendor),
  sec:cpe[@version,@vendor,@product] (CPE 2.2 URI), sec:cvss[@score,@severity,@vector,@version,@type],
  dcterms:issued, dcterms:modified``. A ``status:Status`` element
  (``http://jvndb.jvn.jp/myjvn/Status``) reports ``retCd/errCd/errMsg`` and paging ``totalRes/totalResRet/
  firstRes``.
- Paging: ``startItem`` (1-based) + ``maxCountItem`` (max 50). Without date parameters only items from the
  past week are returned.
- TODO(verify): exact names/semantics of the date filters used for the incremental pull
  (``rangeDatePublic=n``, ``rangeDateFirstPublished=n``, ``datePublishedStart{Y,M,D}`` / ``datePublishedEnd…``
  = last *update* date) and the ``status:Status`` attribute names; the parameter reference page was not
  reachable from the build sandbox. Also TODO(verify): IPA announced a large renewal of JVN iPedia / MyJVN
  from April 2026 (JSON feeds, CVSS v4, API rate limiting). If the classic ``hnd`` feed is retired, swap the
  request/parse functions; the mapping to ``VulnRecord`` stays the same.
- Terms: JVN iPedia content may be reused with source attribution (IPA). TODO(verify) the current wording.

Mapping: one ``VulnRecord`` per referenced CVE (a JVNDB entry can cover several CVEs), keyed by CVE with the
JVNDB id in ``aliases``; entries without a CVE are keyed by the JVNDB id. Japanese title/summary are kept in
``data["jvn"]`` and only fill ``title``/``description`` when no higher-precedence source has one (see
``intel.store``), so the UI can show the Japanese text from ``data.jvn`` regardless.
XML is parsed with the stdlib parser after rejecting any DTD/entity declaration (no XXE / entity expansion).
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from tokiwa.config import Settings
from tokiwa.intel.base import IntelSource, SourceResult, register_source
from tokiwa.intel.sources._common import (
    FetchError,
    Sleep,
    cpe22_to_23,
    default_sleep,
    fetch,
    is_cve,
    normalize_vuln_id,
    parse_dt,
    severity_from_score,
    severity_from_text,
    software_from_cpe,
    to_float,
    unique,
    unique_software,
)
from tokiwa.schemas.intel import SoftwareItem, VulnRecord
from tokiwa.util import utcnow

log = logging.getLogger(__name__)

MYJVN_URL = "https://jvndb.jvn.jp/myjvn"
MAX_COUNT_ITEM = 50
MAX_PAGES_PER_RUN = 20
REQUEST_DELAY_SECONDS = 2.0  # politeness; MyJVN announced rate limiting with the 2026 renewal
JST = timezone(timedelta(hours=9), "JST")  # JVN dates are Japan time; date filters are interpreted in JST

NS = {
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "rss": "http://purl.org/rss/1.0/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "sec": "http://jvn.jp/rss/mod_sec/3.0/",
    "status": "http://jvndb.jvn.jp/myjvn/Status",
}


class JvnApiError(Exception):
    pass


def jvn_params(
    since: datetime | None, lookback_days: int, now: datetime, start_item: int
) -> dict[str, str | int]:
    start = since if since is not None else now - timedelta(days=lookback_days)
    start = min(start, now).astimezone(JST)
    end = now.astimezone(JST)
    return {
        "method": "getVulnOverviewList",
        "feed": "hnd",
        "lang": "ja",
        "startItem": start_item,
        "maxCountItem": MAX_COUNT_ITEM,
        # Filter by last update date only (public / first-published unrestricted).
        "rangeDatePublic": "n",
        "rangeDateFirstPublished": "n",
        "datePublishedStartY": start.year,
        "datePublishedStartM": start.month,
        "datePublishedStartD": start.day,
        "datePublishedEndY": end.year,
        "datePublishedEndM": end.month,
        "datePublishedEndD": end.day,
    }


def _parse_xml(content: bytes) -> ET.Element:
    head = content[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in content.lower():
        raise JvnApiError("refusing XML with DTD/entity declarations")
    return ET.fromstring(content)  # noqa: S314 - no DTD => no external/expanding entities


def _text(el: ET.Element, path: str) -> str | None:
    found = el.find(path, NS)
    if found is None or found.text is None:
        return None
    return found.text.strip() or None


def parse_jvn_status(root: ET.Element) -> dict[str, Any]:
    st = root.find("status:Status", NS)
    if st is None:
        return {}
    return dict(st.attrib)


def _best_cvss(item: ET.Element) -> tuple[float | None, str | None, str | None, list[dict[str, Any]]]:
    entries: list[dict[str, Any]] = []
    for c in item.findall("sec:cvss", NS):
        entries.append(
            {
                "version": c.get("version"),
                "score": to_float(c.get("score")),
                "severity": c.get("severity"),
                "vector": c.get("vector"),
                "type": c.get("type"),
            }
        )

    def rank(e: dict[str, Any]) -> tuple[int, float]:
        version = e.get("version") or ""
        order = {"3.1": 0, "3.0": 1, "4.0": 2, "2.0": 3}.get(version, 4)
        return (order, -(e["score"] or 0.0))

    usable = sorted((e for e in entries if e["score"] is not None), key=rank)
    if not usable:
        return None, None, None, entries
    best = usable[0]
    return best["score"], best["vector"], best["severity"], entries


def parse_jvn_items(root: ET.Element) -> list[VulnRecord]:
    out: list[VulnRecord] = []
    for item in root.findall("rss:item", NS):
        jvndb_id = _text(item, "sec:identifier")
        if not jvndb_id:
            continue
        jvndb_id = normalize_vuln_id(jvndb_id)
        title = _text(item, "rss:title")
        summary = _text(item, "rss:description")
        link = _text(item, "rss:link")
        cves: list[str] = []
        other_refs: list[dict[str, Any]] = []
        ref_urls: list[str] = []
        for ref in item.findall("sec:references", NS):
            src = (ref.get("source") or "").upper()
            rid = (ref.get("id") or "").strip()
            if ref.text and ref.text.strip():
                ref_urls.append(ref.text.strip())
            if src == "CVE" and is_cve(normalize_vuln_id(rid)):
                cves.append(normalize_vuln_id(rid))
            elif rid:
                other_refs.append({"source": ref.get("source"), "id": rid})
        affected: list[SoftwareItem] = []
        for cpe_el in item.findall("sec:cpe", NS):
            cpe23 = cpe22_to_23(cpe_el.text or "")
            sw = software_from_cpe(cpe23) if cpe23 else None
            if sw is None and cpe_el.get("product"):
                sw = SoftwareItem(vendor=cpe_el.get("vendor"), product=str(cpe_el.get("product")))
            if sw is not None:
                affected.append(sw)
        score, vector, sev_text, cvss_entries = _best_cvss(item)
        severity = severity_from_text(sev_text) or severity_from_score(score)
        jvn_data = {
            "id": jvndb_id,
            "title": title,
            "summary": summary,
            "url": link,
            "cvss": cvss_entries,
            "references": other_refs,
            "lang": "ja",
        }
        common: dict[str, Any] = {
            "sources": ["jvn"],
            "title": title,
            "description": summary,
            "published": parse_dt(_text(item, "dcterms:issued")),
            "modified": parse_dt(_text(item, "dcterms:modified") or _text(item, "dc:date")),
            "cvss_score": score,
            "cvss_vector": vector,
            "severity": severity,
            "affected": unique_software(affected),
            "references": unique([link or "", *ref_urls]),
            "data": {"jvn": jvn_data},
        }
        for rid in unique(cves) or [jvndb_id]:
            aliases = [jvndb_id] if rid != jvndb_id else []
            out.append(VulnRecord(id=rid, aliases=aliases, **common))
    return out


@register_source
class JvnSource(IntelSource):
    id = "jvn"
    name = "JVN iPedia (MyJVN API)"
    attribution = "出典: JVN iPedia（IPA）"
    url = MYJVN_URL

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.sleep: Sleep = default_sleep
        self.now = utcnow

    async def fetch(self, client: httpx.AsyncClient, since: datetime | None) -> SourceResult:
        result = SourceResult()
        now = self.now()
        start_item = 1
        for page in range(MAX_PAGES_PER_RUN):
            if page:
                await self.sleep(REQUEST_DELAY_SECONDS)
            params = jvn_params(since, self.settings.intel.nvd_lookback_days, now, start_item)
            try:
                resp = await fetch(client, "GET", self.url, params=params, sleep=self.sleep)
                root = _parse_xml(resp.content)
            except (FetchError, JvnApiError, ET.ParseError) as exc:
                result.errors.append(f"jvn: {exc}")
                return result
            status = parse_jvn_status(root)
            ret_cd = status.get("retCd", "0")
            if ret_cd not in ("", "0"):
                result.errors.append(f"jvn: API error {status.get('errCd')}: {status.get('errMsg')}")
                return result
            items = parse_jvn_items(root)
            result.vulns.extend(items)
            total = int(status.get("totalRes") or 0)
            returned = int(status.get("totalResRet") or len(root.findall("rss:item", NS)))
            start_item += returned
            if returned <= 0 or start_item > total:
                break
        else:
            result.errors.append(f"jvn: page cap ({MAX_PAGES_PER_RUN}) reached")
        log.info("jvn: %d records", len(result.vulns))
        return result
