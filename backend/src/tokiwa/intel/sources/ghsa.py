"""GitHub Security Advisories (global advisory database) via the REST API.

API (https://docs.github.com/en/rest/security-advisories/global-advisories, checked 2026-10-22):
- ``GET https://api.github.com/advisories``. Without other parameters it returns GitHub-reviewed, non-malware
  advisories. Parameters used: ``type=reviewed`` (reviewed | malware | unreviewed), ``per_page`` (max 100,
  default 30), ``sort`` (updated | published | epss_percentage | epss_percentile; default published),
  ``direction``, and ``updated`` with GitHub date-range syntax (``>=YYYY-MM-DD``).
  TODO(verify): the ``updated`` filter name/semantics were not visible in the doc excerpts we could reach
  from the sandbox (``modified``, "updated or published", may be the better choice).
- Pagination is cursor based through the ``Link`` response header (``rel="next"``), which we follow verbatim.
- Headers: ``Accept: application/vnd.github+json``, ``X-GitHub-Api-Version: 2022-11-28``; token optional
  (``Authorization: Bearer``). Rate limits: 60 requests/hour unauthenticated, 5,000/hour with a token
  (GitHub REST rate-limit docs) -> page caps below.
- Advisory fields used: ``ghsa_id, cve_id, html_url, summary, description, type, severity
  (critical|high|medium|low|unknown), identifiers[{type,value}], references[] (URL strings), published_at,
  updated_at, withdrawn_at, vulnerabilities[{package{ecosystem,name}, vulnerable_version_range,
  first_patched_version, vulnerable_functions}], cvss_severities{cvss_v3,cvss_v4: {vector_string, score}},
  cwes[{cwe_id,name}]``. The legacy ``cvss`` object is deprecated (removal announced for 2025-10-01) and is
  read only as a fallback.
- Data licence: the GitHub Advisory Database is CC-BY 4.0 (github/advisory-database). TODO(verify) wording.

Mapping: CVE id when present (GHSA id goes to aliases), else the GHSA id. Package ecosystems are mapped to OSV
ecosystem names so ``SoftwareItem.ecosystem`` is consistent across GHSA/OSV/assets. Version ranges are kept in
``data["ghsa"]["vulnerabilities"]`` for ``intel.matcher``. Withdrawn advisories are skipped.
Known limitation: pages are read newest-first up to a cap (3 without token, 20 with), so on days with bulk
re-reviews the oldest updates of the window can be skipped (logged as a warning).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

import httpx

from tokiwa.config import Settings
from tokiwa.intel.base import IntelSource, SourceResult, register_source
from tokiwa.intel.sources._common import (
    FetchError,
    Sleep,
    default_sleep,
    fetch,
    normalize_vuln_id,
    parse_dt,
    severity_from_score,
    severity_from_text,
    to_float,
    unique,
    unique_software,
)
from tokiwa.schemas.intel import SoftwareItem, VulnRecord
from tokiwa.util import utcnow

log = logging.getLogger(__name__)

GHSA_URL = "https://api.github.com/advisories"
API_VERSION = "2022-11-28"
PER_PAGE = 100
MAX_PAGES_NO_TOKEN = 3  # 60 req/h shared with anything else on this IP
MAX_PAGES_WITH_TOKEN = 20
REQUEST_DELAY_SECONDS = 1.0

# GitHub ecosystem enum -> OSV ecosystem name (https://ossf.github.io/osv-schema/#affectedpackage-field).
ECOSYSTEM_MAP = {
    "npm": "npm",
    "pip": "PyPI",
    "rubygems": "RubyGems",
    "maven": "Maven",
    "nuget": "NuGet",
    "composer": "Packagist",
    "go": "Go",
    "rust": "crates.io",
    "erlang": "Hex",
    "pub": "Pub",
    "swift": "SwiftURL",
    "actions": "GitHub Actions",
}


def ghsa_params(since: datetime | None, lookback_days: int, now: datetime) -> dict[str, str | int]:
    start = since if since is not None else now - timedelta(days=lookback_days)
    # Date granularity (no time): re-reads up to one day, which the store absorbs as "unchanged".
    return {
        "type": "reviewed",
        "per_page": PER_PAGE,
        "sort": "updated",
        "direction": "desc",
        "updated": f">={start.date().isoformat()}",
    }


def _cvss(adv: dict[str, Any]) -> tuple[float | None, str | None]:
    sev = adv.get("cvss_severities") or {}
    for key in ("cvss_v3", "cvss_v4"):
        c = sev.get(key) or {}
        score = to_float(c.get("score"))
        if c.get("vector_string") and score:
            return score, c["vector_string"]
    legacy = adv.get("cvss") or {}
    score = to_float(legacy.get("score"))
    if legacy.get("vector_string") and score:
        return score, legacy["vector_string"]
    return None, None


def _first_patched(value: Any) -> str | None:
    if isinstance(value, dict):  # older/other GitHub payloads use {"identifier": "1.2.3"}
        value = value.get("identifier")
    return str(value) if value else None


def parse_ghsa_advisory(adv: dict[str, Any]) -> VulnRecord | None:
    if adv.get("withdrawn_at"):
        return None
    ghsa_id = normalize_vuln_id(str(adv["ghsa_id"]))
    cve_id = normalize_vuln_id(adv["cve_id"]) if adv.get("cve_id") else None
    identifiers = [
        normalize_vuln_id(str(i.get("value"))) for i in adv.get("identifiers") or [] if i.get("value")
    ]
    score, vector = _cvss(adv)
    severity = severity_from_text(adv.get("severity")) or severity_from_score(score)
    affected: list[SoftwareItem] = []
    vulns_data: list[dict[str, Any]] = []
    for v in adv.get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        name = pkg.get("name")
        eco_raw = str(pkg.get("ecosystem") or "")
        ecosystem = ECOSYSTEM_MAP.get(eco_raw.lower(), eco_raw or None)
        if name:
            affected.append(SoftwareItem(product=str(name), ecosystem=ecosystem))
        vulns_data.append(
            {
                "ecosystem": ecosystem,
                "package": name,
                "vulnerable_version_range": v.get("vulnerable_version_range"),
                "first_patched_version": _first_patched(v.get("first_patched_version")),
                "vulnerable_functions": v.get("vulnerable_functions") or [],
            }
        )
    record_id = cve_id or ghsa_id
    return VulnRecord(
        id=record_id,
        aliases=unique(a for a in [ghsa_id, cve_id, *identifiers] if a and a != record_id),
        sources=["ghsa"],
        title=(adv.get("summary") or "").strip() or None,
        description=(adv.get("description") or "").strip() or None,
        published=parse_dt(adv.get("published_at")),
        modified=parse_dt(adv.get("updated_at")),
        cvss_score=score,
        cvss_vector=vector,
        severity=severity,
        cwe=unique(str(c.get("cwe_id")).upper() for c in adv.get("cwes") or [] if c.get("cwe_id")),
        affected=unique_software(affected),
        references=unique([*(str(r) for r in adv.get("references") or [] if r), adv.get("html_url") or ""]),
        data={
            "ghsa": {
                "id": ghsa_id,
                "url": adv.get("html_url"),
                "type": adv.get("type"),
                "severity": adv.get("severity"),
                "vulnerabilities": vulns_data,
            }
        },
    )


@register_source
class GhsaSource(IntelSource):
    id = "ghsa"
    name = "GitHub Security Advisories"
    attribution = "GitHub Advisory Database (CC-BY 4.0)"
    url = GHSA_URL

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.sleep: Sleep = default_sleep
        self.now = utcnow

    def _token(self) -> str | None:
        tok = self.settings.intel.github_token
        return tok.get_secret_value() if tok is not None and tok.get_secret_value() else None

    async def fetch(self, client: httpx.AsyncClient, since: datetime | None) -> SourceResult:
        result = SourceResult()
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION}
        token = self._token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        max_pages = MAX_PAGES_WITH_TOKEN if token else MAX_PAGES_NO_TOKEN
        url: str | None = self.url
        params: dict[str, str | int] | None = ghsa_params(
            since, self.settings.intel.nvd_lookback_days, self.now()
        )
        pages = 0
        while url and pages < max_pages:
            if pages:
                await self.sleep(REQUEST_DELAY_SECONDS)
            pages += 1
            try:
                resp = await fetch(client, "GET", url, params=params, headers=headers, sleep=self.sleep)
                advisories = resp.json()
            except (FetchError, ValueError) as exc:
                result.errors.append(f"ghsa: {exc}")
                return result
            if not isinstance(advisories, list):
                result.errors.append("ghsa: unexpected response (expected a JSON array)")
                return result
            for adv in advisories:
                try:
                    rec = parse_ghsa_advisory(adv)
                except (KeyError, TypeError, ValueError) as exc:
                    result.errors.append(f"ghsa: skipped malformed advisory: {exc}")
                    continue
                if rec is not None:
                    result.vulns.append(rec)
            url = resp.links.get("next", {}).get("url")
            params = None  # the next link already carries the cursor and filters
        if url:
            # Newest-first order: what is skipped are the *oldest* updates of this window. Acceptable for the
            # normal 6 h cadence; configure intel.github_token (20 pages) for bulk-update days.
            log.warning("ghsa: page cap (%d) reached; older updates in this window were skipped", max_pages)
        log.info("ghsa: %d advisories in %d page(s)", len(result.vulns), pages)
        return result
