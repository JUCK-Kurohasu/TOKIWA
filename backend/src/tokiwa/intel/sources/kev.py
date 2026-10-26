"""CISA Known Exploited Vulnerabilities (KEV) catalog.

Source / format (checked 2026-10-22):
- Catalog page: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (JSON, CSV and a JSON Schema are
  published there; mirrored at https://github.com/cisagov/kev-data).
- JSON feed: ``https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json``
  Envelope ``{title, catalogVersion, dateReleased, count, vulnerabilities[]}``; each entry has ``cveID,
  vendorProject, product, vulnerabilityName, dateAdded (YYYY-MM-DD), shortDescription, requiredAction,
  dueDate (YYYY-MM-DD), knownRansomwareCampaignUse ("Known" | "Unknown"), notes, cwes[]``.
- No API key, no published rate limit (it is a static file). License: U.S. Government work; the
  cisagov/kev-data mirror is CC0-1.0. TODO(verify): confirm the mirror licence and whether the CISA CDN honours
  ``If-Modified-Since`` (we send it; a 200 is handled exactly like a first fetch).

Why the whole catalog is returned on every (changed) fetch instead of only ``dateAdded >= since``:
CISA also edits existing entries (``knownRansomwareCampaignUse`` Unknown→Known, ``notes``, ``dueDate``).
The catalog is small (~1.5k entries), and ``intel.store`` skips rows whose merged value did not change, so a
full pass is cheap and keeps those edits. "Newly added" is derived by the store from the kev flag transition
plus ``dateAdded`` recency (see ``store.KEV_RECENT_DAYS``).
Removal of an entry from the catalog (rare) is not propagated. TODO(verify): decide whether to clear kev then.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

from tokiwa.config import Settings
from tokiwa.intel.base import IntelSource, SourceResult, register_source
from tokiwa.intel.sources._common import (
    Sleep,
    default_sleep,
    extract_urls,
    fetch,
    http_date,
    is_cve,
    normalize_vuln_id,
    parse_dt,
    unique,
)
from tokiwa.schemas.intel import SoftwareItem, VulnRecord

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _ransomware(value: Any) -> bool | None:
    """``Known`` -> True, ``Unknown`` -> False (CISA: no known ransomware use), anything else -> None."""
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if v == "known":
        return True
    if v == "unknown":
        return False
    return None


def parse_kev_entry(entry: dict[str, Any]) -> VulnRecord:
    cve = normalize_vuln_id(str(entry["cveID"]))
    if not is_cve(cve):
        raise ValueError(f"invalid cveID {entry.get('cveID')!r}")
    vendor = (entry.get("vendorProject") or "").strip() or None
    product = (entry.get("product") or "").strip()
    notes = entry.get("notes") or ""
    cwes = [c for c in (entry.get("cwes") or []) if isinstance(c, str) and c.upper().startswith("CWE-")]
    return VulnRecord(
        id=cve,
        sources=["kev"],
        title=(entry.get("vulnerabilityName") or "").strip() or None,
        description=(entry.get("shortDescription") or "").strip() or None,
        kev=True,
        kev_date_added=parse_dt(entry.get("dateAdded")),
        kev_due_date=parse_dt(entry.get("dueDate")),
        kev_ransomware=_ransomware(entry.get("knownRansomwareCampaignUse")),
        cwe=unique(c.upper() for c in cwes),
        affected=[SoftwareItem(vendor=vendor, product=product)] if product else [],
        references=extract_urls(notes),
        data={
            "kev": {
                "vendor_project": vendor,
                "product": product or None,
                "required_action": entry.get("requiredAction"),
                "notes": notes or None,
                "known_ransomware_campaign_use": entry.get("knownRansomwareCampaignUse"),
            }
        },
    )


def parse_kev_catalog(doc: dict[str, Any]) -> SourceResult:
    result = SourceResult()
    entries = doc.get("vulnerabilities")
    if not isinstance(entries, list):
        result.errors.append("kev: 'vulnerabilities' array missing")
        return result
    for entry in entries:
        try:
            result.vulns.append(parse_kev_entry(entry))
        except (KeyError, TypeError, ValueError) as exc:
            result.errors.append(f"kev: skipped malformed entry: {exc}")
    return result


@register_source
class KevSource(IntelSource):
    id = "kev"
    name = "CISA Known Exploited Vulnerabilities"
    attribution = "CISA Known Exploited Vulnerabilities Catalog (cisa.gov)"
    url = KEV_URL

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.sleep: Sleep = default_sleep

    async def fetch(self, client: httpx.AsyncClient, since: datetime | None) -> SourceResult:
        headers = {"Accept": "application/json"}
        if since is not None:
            headers["If-Modified-Since"] = http_date(since)
        resp = await fetch(client, "GET", self.url, headers=headers, sleep=self.sleep)
        if resp.status_code == 304:
            log.info("kev: catalog not modified since %s", since)
            return SourceResult()
        doc = resp.json()
        result = parse_kev_catalog(doc)
        log.info("kev: catalog %s with %d entries", doc.get("catalogVersion"), len(result.vulns))
        return result
