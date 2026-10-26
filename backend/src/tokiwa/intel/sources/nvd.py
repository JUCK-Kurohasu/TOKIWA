"""NIST NVD CVE API 2.0 — incremental pull by last-modified date.

API (https://nvd.nist.gov/developers/vulnerabilities and /developers/start-here, checked 2026-10-22):
- ``GET https://services.nvd.nist.gov/rest/json/cves/2.0``
- ``lastModStartDate`` + ``lastModEndDate``: "If filtering by the last modified date, both ... are REQUIRED.
  The maximum allowable range when using any date range parameters is 120 consecutive days." Extended
  ISO-8601 with offset, e.g. ``2021-08-04T13:00:00.000+01:00`` (``+`` must be URL-encoded; httpx does).
- Paging: ``resultsPerPage`` (CVE endpoint max 2000) + ``startIndex``; increment ``startIndex`` until it
  reaches ``totalResults``.
- API key (optional) is sent in the ``apiKey`` request *header*. Rate limits: 5 requests / rolling 30 s
  without a key, 50 / rolling 30 s with a key; NVD recommends sleeping between requests (6 s commonly used)
  and running incremental syncs no more than once every two hours.
- Response: ``{resultsPerPage, startIndex, totalResults, format: "NVD_CVE", version: "2.0", timestamp,
  vulnerabilities: [{cve: {...}}]}``; ``cve`` has ``id, sourceIdentifier, published, lastModified, vulnStatus,
  descriptions[{lang,value}], metrics{cvssMetricV40|V31|V30|V2: [{source, type: Primary|Secondary,
  cvssData{version, vectorString, baseScore, baseSeverity?}, baseSeverity? (v2)}]}, weaknesses[{source, type,
  description[{lang,value}]}], configurations[{nodes[{operator, negate, cpeMatch[{vulnerable, criteria,
  versionStartIncluding|Excluding, versionEndIncluding|Excluding, matchCriteriaId}]}]}], references[{url,
  source, tags}]`` and, for KEV entries, ``cisaExploitAdd, cisaActionDue, cisaRequiredAction,
  cisaVulnerabilityName``.
- Terms of use (https://nvd.nist.gov/developers/terms-of-use): applications are asked to display "This product
  uses the NVD API but is not endorsed or certified by the NVD." (exposed via ``attribution``).

Mapping decisions (tunable constants below):
- ``CVSS_PREFERENCE``: v3.1 first (what most prioritisation still keys on), then v4.0, v3.0, v2; Primary (NVD)
  before Secondary (CNA) within a version. All metrics are kept in ``data["nvd"]["cvss"]`` for the UI.
- ``affected`` holds vulnerable CPEs as ``SoftwareItem`` (version only when the CPE pins one). Version *ranges*
  are not representable in ``SoftwareItem``; they are kept verbatim (NVD key names) in
  ``data["nvd"]["cpe_matches"]`` for ``intel.matcher``. Both lists are capped (huge configs such as the Linux
  kernel have thousands of entries).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from tokiwa.config import Settings
from tokiwa.intel.base import IntelSource, SourceResult, register_source
from tokiwa.intel.sources._common import (
    RETRY_STATUSES,
    FetchError,
    Sleep,
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
from tokiwa.util import ensure_utc, utcnow

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
MAX_RANGE = timedelta(days=120)  # documented maximum for lastMod* ranges
WINDOW_OVERLAP = timedelta(minutes=10)  # re-read a little before the last sync to tolerate clock skew
DELAY_NO_KEY_SECONDS = 6.0  # 5 req / 30 s
DELAY_WITH_KEY_SECONDS = 0.8  # 50 req / 30 s (0.6 s) + margin
THROTTLE_RETRY_DELAY_SECONDS = 30.0  # one rolling window
MAX_PAGES_PER_RUN = 100
MAX_AFFECTED = 200
MAX_CPE_MATCHES = 500
MAX_REFERENCES = 100
# NVD answers 403 (and sometimes 503) when the rolling window is exceeded, so 403 is retried here.
NVD_RETRY_STATUSES = RETRY_STATUSES | {403}
CVSS_PREFERENCE = ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2")
_METRIC_LABEL = {"cvssMetricV40": "v40", "cvssMetricV31": "v31", "cvssMetricV30": "v30", "cvssMetricV2": "v2"}


def nvd_datetime(dt: datetime) -> str:
    """Extended ISO-8601 with milliseconds and explicit UTC offset, as in NVD's documented examples."""
    return ensure_utc(dt).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ensure_utc(dt).microsecond // 1000:03d}+00:00"


def nvd_windows(since: datetime | None, now: datetime, lookback_days: int) -> list[tuple[datetime, datetime]]:
    """[start, end] windows of at most 120 days covering (since - overlap | now - lookback) .. now."""
    start = ensure_utc(since) - WINDOW_OVERLAP if since is not None else now - timedelta(days=lookback_days)
    start = min(start, now)
    windows: list[tuple[datetime, datetime]] = []
    cursor = start
    while cursor < now:
        end = min(cursor + MAX_RANGE - timedelta(seconds=1), now)
        windows.append((cursor, end))
        cursor = end
    if not windows:
        windows.append((start, now))
    return windows


def nvd_params(start: datetime, end: datetime, start_index: int = 0) -> dict[str, str | int]:
    return {
        "lastModStartDate": nvd_datetime(start),
        "lastModEndDate": nvd_datetime(end),
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex": start_index,
    }


def _metric_summary(metric: dict[str, Any]) -> dict[str, Any]:
    data = metric.get("cvssData") or {}
    score = to_float(data.get("baseScore"))
    sev = data.get("baseSeverity") or metric.get("baseSeverity")  # v2 keeps baseSeverity on the metric
    return {
        "version": data.get("version"),
        "score": score,
        "vector": data.get("vectorString"),
        "severity": (sev or "").lower() or None,
        "source": metric.get("source"),
        "type": metric.get("type"),
    }


def select_cvss(metrics: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]]]:
    """Return (preferred metric summary, all summaries by version label)."""
    best: dict[str, Any] | None = None
    all_metrics: dict[str, dict[str, Any]] = {}
    for key in CVSS_PREFERENCE:
        entries = [m for m in (metrics.get(key) or []) if isinstance(m, dict)]
        if not entries:
            continue
        entries.sort(key=lambda m: 0 if m.get("type") == "Primary" else 1)
        summaries = [_metric_summary(m) for m in entries]
        all_metrics[_METRIC_LABEL[key]] = summaries[0]
        if best is None:
            best = next((s for s in summaries if s["score"] is not None), None)
    return best, all_metrics


def _cwes(weaknesses: list[dict[str, Any]]) -> list[str]:
    ordered = sorted(weaknesses, key=lambda w: 0 if w.get("type") == "Primary" else 1)
    out: list[str] = []
    for w in ordered:
        for d in w.get("description") or []:
            value = str(d.get("value", ""))
            if value.upper().startswith("CWE-"):  # skips NVD-CWE-Other / NVD-CWE-noinfo
                out.append(value.upper())
    return unique(out)


def _cpe_matches(configurations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for config in configurations:
        for node in config.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue  # platform/running-on CPEs (e.g. the OS under an app) are not "affected"
                entry = {"criteria": m.get("criteria")}
                for key in (
                    "versionStartIncluding",
                    "versionStartExcluding",
                    "versionEndIncluding",
                    "versionEndExcluding",
                ):
                    if m.get(key):
                        entry[key] = m[key]
                if m.get("matchCriteriaId"):
                    entry["matchCriteriaId"] = m["matchCriteriaId"]
                out.append(entry)
    return out


def parse_nvd_cve(cve: dict[str, Any]) -> VulnRecord:
    cve_id = normalize_vuln_id(str(cve["id"]))
    if not is_cve(cve_id):
        raise ValueError(f"invalid CVE id {cve.get('id')!r}")
    descriptions = cve.get("descriptions") or []
    description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
    if description is None and descriptions:
        description = descriptions[0].get("value")
    best, all_metrics = select_cvss(cve.get("metrics") or {})
    score = best["score"] if best else None
    severity = (severity_from_text(best["severity"]) if best else None) or severity_from_score(score)
    matches = _cpe_matches(cve.get("configurations") or [])
    affected: list[SoftwareItem] = []
    for m in matches:
        item = software_from_cpe(str(m.get("criteria") or ""))
        if item is not None:
            affected.append(item)
    kev_added = parse_dt(cve.get("cisaExploitAdd"))
    return VulnRecord(
        id=cve_id,
        sources=["nvd"],
        title=None,  # NVD has no title; kev/ghsa/osv/jvn provide one (see store precedence)
        description=description,
        published=parse_dt(cve.get("published")),
        modified=parse_dt(cve.get("lastModified")),
        cvss_score=score,
        cvss_vector=best["vector"] if best else None,
        severity=severity,
        kev=kev_added is not None,
        kev_date_added=kev_added,
        kev_due_date=parse_dt(cve.get("cisaActionDue")),
        cwe=_cwes(cve.get("weaknesses") or []),
        affected=unique_software(affected, MAX_AFFECTED),
        references=unique(str(r.get("url")) for r in (cve.get("references") or []) if r.get("url"))[
            :MAX_REFERENCES
        ],
        data={
            "nvd": {
                "vuln_status": cve.get("vulnStatus"),
                "source_identifier": cve.get("sourceIdentifier"),
                "cvss": all_metrics,
                "cpe_matches": matches[:MAX_CPE_MATCHES],
                "cpe_matches_truncated": len(matches) > MAX_CPE_MATCHES,
                "cisa_vulnerability_name": cve.get("cisaVulnerabilityName"),
                "cisa_required_action": cve.get("cisaRequiredAction"),
            }
        },
    )


@register_source
class NvdSource(IntelSource):
    id = "nvd"
    name = "NIST NVD CVE API 2.0"
    attribution = "This product uses the NVD API but is not endorsed or certified by the NVD."
    url = NVD_URL

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.sleep: Sleep = default_sleep
        self.now = utcnow

    def _api_key(self) -> str | None:
        key = self.settings.intel.nvd_api_key
        return key.get_secret_value() if key is not None and key.get_secret_value() else None

    def request_delay(self) -> float:
        return DELAY_WITH_KEY_SECONDS if self._api_key() else DELAY_NO_KEY_SECONDS

    async def fetch(self, client: httpx.AsyncClient, since: datetime | None) -> SourceResult:
        result = SourceResult()
        headers = {"Accept": "application/json"}
        key = self._api_key()
        if key:
            headers["apiKey"] = key
        now = self.now().astimezone(UTC)
        requests = 0
        for start, end in nvd_windows(since, now, self.settings.intel.nvd_lookback_days):
            start_index = 0
            while True:
                if requests >= MAX_PAGES_PER_RUN:
                    result.errors.append(
                        f"nvd: stopped after {MAX_PAGES_PER_RUN} pages; remaining window resumes next run"
                    )
                    return result
                if requests:
                    await self.sleep(self.request_delay())
                requests += 1
                try:
                    resp = await fetch(
                        client,
                        "GET",
                        self.url,
                        params=nvd_params(start, end, start_index),
                        headers=headers,
                        retry_statuses=NVD_RETRY_STATUSES,
                        base_delay=THROTTLE_RETRY_DELAY_SECONDS,
                        sleep=self.sleep,
                    )
                    doc = resp.json()
                except (FetchError, ValueError) as exc:
                    result.errors.append(f"nvd: {exc}")
                    return result
                items = doc.get("vulnerabilities") or []
                for item in items:
                    try:
                        result.vulns.append(parse_nvd_cve(item["cve"]))
                    except (KeyError, TypeError, ValueError) as exc:
                        result.errors.append(f"nvd: skipped malformed CVE: {exc}")
                total = int(doc.get("totalResults") or 0)
                page_size = int(doc.get("resultsPerPage") or len(items))
                start_index += page_size
                if not items or page_size <= 0 or start_index >= total:
                    break
        log.info("nvd: %d CVEs in %d request(s)", len(result.vulns), requests)
        return result
