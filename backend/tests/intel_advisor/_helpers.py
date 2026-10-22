"""Fixture rows for intel-advisor tests (the vulns table is normally filled by intel-feeds)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from tokiwa.db.models.intel import AssetRow, VulnMatchRow, VulnRow
from tokiwa.db.session import session_scope
from tokiwa.util import new_id, utcnow

APACHE_AFFECTED: list[dict[str, Any]] = [
    {
        "cpe": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "2.4.0",
        "versionEndExcluding": "2.4.59",
        "vulnerable": True,
    }
]
APACHE_SW = {"vendor": "Apache Software Foundation", "product": "HTTP Server", "version": "2.4.58"}

VALID_SIGMA = """\
title: Encoded path traversal against Apache HTTP Server
id: 5f0c1a52-0a1e-4c1a-9a43-3f5a0d6a0001
status: experimental
description: Detects encoded path traversal sequences in the request URI.
logsource:
  category: webserver
  product: tokiwa
detection:
  selection:
    cs-uri-stem|contains:
      - '/.%2e/'
      - '%2e%2e/'
  condition: selection
falsepositives:
  - Unlikely
level: high
tags:
  - attack.initial_access
  - attack.t1190
"""

BROKEN_YAML_SIGMA = "title: [unclosed\ndetection: {selection: {a: b}\n"

NO_CONDITION_SIGMA = """\
title: Missing condition
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains: 'x'
level: medium
"""


async def add_vuln(
    vuln_id: str,
    *,
    kev: bool = False,
    epss: float | None = None,
    cvss: float | None = 7.5,
    title: str | None = None,
    description: str = "A vulnerability.",
    affected: list[dict[str, Any]] | None = None,
    references: list[str] | None = None,
    cwe: list[str] | None = None,
    sources: list[str] | None = None,
) -> None:
    async with session_scope() as s:
        s.add(
            VulnRow(
                id=vuln_id,
                aliases=[],
                sources=sources or ["nvd"],
                title=title or f"{vuln_id} title",
                description=description,
                cvss_score=cvss,
                severity="high" if cvss and cvss >= 7 else None,
                epss=epss,
                kev=kev,
                kev_date_added=utcnow() if kev else None,
                cwe=cwe or [],
                affected=affected if affected is not None else [],
                references=references or [],
                data={},
                updated_at=utcnow(),
            )
        )


async def add_asset(
    name: str = "web-1",
    *,
    software: list[dict[str, Any]] | None = None,
    ips: list[str] | None = None,
    hostname: str | None = None,
    criticality: str = "high",
) -> str:
    asset_id = new_id()
    async with session_scope() as s:
        s.add(
            AssetRow(
                id=asset_id,
                name=name,
                kind="host",
                hostname=hostname,
                ips=ips or [],
                software=software or [],
                criticality=criticality,
                tags=[],
            )
        )
    return asset_id


async def get_vuln(vuln_id: str) -> VulnRow | None:
    async with session_scope() as s:
        return await s.get(VulnRow, vuln_id)


async def matches(vuln_id: str | None = None) -> list[VulnMatchRow]:
    async with session_scope() as s:
        stmt = select(VulnMatchRow)
        if vuln_id:
            stmt = stmt.where(VulnMatchRow.vuln_id == vuln_id)
        return list((await s.execute(stmt.order_by(VulnMatchRow.created_at))).scalars())
