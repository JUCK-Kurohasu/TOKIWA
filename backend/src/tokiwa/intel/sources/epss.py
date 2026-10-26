"""FIRST Exploit Prediction Scoring System (EPSS) scores for the CVEs TOKIWA already knows.

API (https://api.first.org/epss, checked 2026-10-22; the v1 endpoint is labelled beta):
- ``GET https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B``. "Multiple values are supported separated by
  commas. The maximum size accepted for this parameter is 2000 characters (including commas)."
- Response envelope ``{status, status-code, version, access, total, offset, limit, data[]}``; each row
  ``{cve, epss, percentile, date}`` where ``epss``/``percentile`` are *strings* (e.g. ``"0.957320000"``) and
  ``date`` is ``YYYY-MM-DD``. The default page ``limit`` is 100, so batches are capped at 100 CVEs and the
  explicit ``limit`` equals the batch size.
- No key. TODO(verify): official rate limit and the maximum accepted ``limit``; we send <= 100 CVEs per call
  and pause ``REQUEST_DELAY_SECONDS`` between calls. Terms: EPSS is published free of charge by FIRST;
  TODO(verify) the exact attribution wording requested at https://www.first.org/epss/ .

Why targeted lookups instead of the daily full CSV (epss_scores-current.csv.gz): TOKIWA only needs scores for
CVEs present in its ``vulns`` table (KEV, NVD window, assets via OSV/GHSA). ``intel.sync`` computes the target
list (CVEs touched in this run + rows without a score + KEV/asset-matched rows + a rolling refresh) and passes
it through :meth:`EpssSource.prepare`; this keeps the source itself free of DB access and easy to test.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import datetime
from typing import Any

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
    to_float,
)
from tokiwa.schemas.intel import VulnRecord

log = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"
MAX_CVES_PER_REQUEST = 100
MAX_CVE_PARAM_CHARS = 2000
REQUEST_DELAY_SECONDS = 0.5


def epss_batches(
    cves: Iterable[str], *, max_items: int = MAX_CVES_PER_REQUEST, max_chars: int = MAX_CVE_PARAM_CHARS
) -> list[list[str]]:
    """Split CVE ids into batches that respect both the 2000-character ``cve`` limit and the page size."""
    batches: list[list[str]] = []
    current: list[str] = []
    length = 0
    for cve in dict.fromkeys(normalize_vuln_id(c) for c in cves):
        if not is_cve(cve):
            continue
        extra = len(cve) + (1 if current else 0)
        if current and (len(current) >= max_items or length + extra > max_chars):
            batches.append(current)
            current, length = [], 0
            extra = len(cve)
        current.append(cve)
        length += extra
    if current:
        batches.append(current)
    return batches


def parse_epss_rows(doc: dict[str, Any]) -> list[VulnRecord]:
    out: list[VulnRecord] = []
    for row in doc.get("data") or []:
        cve = normalize_vuln_id(str(row.get("cve", "")))
        epss = to_float(row.get("epss"))
        if not is_cve(cve) or epss is None:
            continue
        out.append(
            VulnRecord(
                id=cve,
                sources=["epss"],
                epss=epss,
                epss_percentile=to_float(row.get("percentile")),
                data={"epss": {"date": row.get("date")}},
            )
        )
    return out


@register_source
class EpssSource(IntelSource):
    id = "epss"
    name = "FIRST EPSS"
    attribution = "EPSS scores by FIRST (first.org/epss)"
    url = EPSS_URL
    run_last = True  # needs the CVE ids gathered by the other sources in the same sync run

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.sleep: Sleep = default_sleep
        self.targets: list[str] = []

    async def prepare(self, collected_cves: set[str]) -> None:
        from tokiwa.intel.store import epss_targets

        self.targets = await epss_targets(collected_cves)

    async def fetch(self, client: httpx.AsyncClient, since: datetime | None) -> SourceResult:
        result = SourceResult()
        for i, batch in enumerate(epss_batches(self.targets)):
            if i:
                await self.sleep(REQUEST_DELAY_SECONDS)
            try:
                resp = await fetch(
                    client,
                    "GET",
                    self.url,
                    params={"cve": ",".join(batch), "limit": len(batch)},
                    headers={"Accept": "application/json"},
                    sleep=self.sleep,
                )
                result.vulns.extend(parse_epss_rows(resp.json()))
            except (FetchError, ValueError) as exc:
                result.errors.append(f"epss: batch {i}: {exc}")
        log.info("epss: %d scores for %d targets", len(result.vulns), len(self.targets))
        return result
