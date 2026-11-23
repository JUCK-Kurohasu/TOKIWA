"""Audit #132 (UI): the exposures list says when the vulnerability behind a match was withdrawn by its feed.

The matcher auto-closes such matches with its generic note; the UI shows a "withdrawn" badge from these fields.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from tokiwa.db.models.intel import AssetRow, VulnRow
from tokiwa.db.session import session_scope
from tokiwa.intel.matcher import run_matching
from tokiwa.intel.sources.ghsa import parse_ghsa_advisory
from tokiwa.intel.store import apply_withdrawals, upsert_vulns
from tokiwa.schemas.intel import VulnRecord
from tokiwa.util import new_id

NOW = datetime(2026, 11, 22, tzinfo=UTC)
WITHDRAWN = "2026-11-20T00:00:00Z"
API = "/api/v1/intel"


def ghsa(ghsa_id: str, *, cve: str | None = None, withdrawn: bool = False) -> VulnRecord:
    rec = parse_ghsa_advisory(
        {
            "ghsa_id": ghsa_id,
            "cve_id": cve,
            "summary": "fixture advisory",
            "type": "reviewed",
            "severity": "high",
            "identifiers": [{"value": ghsa_id, "type": "GHSA"}],
            "published_at": "2026-11-01T00:00:00Z",
            "updated_at": WITHDRAWN if withdrawn else "2026-11-01T00:00:00Z",
            "withdrawn_at": WITHDRAWN if withdrawn else None,
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "pip", "name": "flaskish"},
                    "vulnerable_version_range": "< 1.2.0",
                    "first_patched_version": "1.2.0",
                }
            ],
        },
        include_withdrawn=True,
    )
    assert rec is not None
    return rec


async def _setup(*records: VulnRecord) -> None:
    async with session_scope() as s:
        await upsert_vulns(s, list(records), now=NOW, epss_threshold=0.1)
        s.add(
            AssetRow(
                id=new_id(),
                name="web-1",
                kind="host",
                ips=[],
                software=[{"product": "flaskish", "ecosystem": "PyPI", "version": "1.0.0"}],
                criticality="high",
                tags=[],
            )
        )
    await run_matching(publish=False)


async def _withdraw(rec: VulnRecord, vuln_id: str) -> None:
    async with session_scope() as s:
        await apply_withdrawals(s, [rec], now=NOW)
    await run_matching(vuln_ids=[vuln_id], publish=False)


async def _matches(client: httpx.AsyncClient, headers: dict[str, str]) -> list[dict[str, Any]]:
    r = await client.get(f"{API}/matches", headers=headers)
    assert r.status_code == 200, r.text
    return list(r.json()["items"])


async def test_matches_carry_the_withdrawal_of_their_vulnerability(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    gid = "GHSA-aaaa-bbbb-cccc"
    await _setup(ghsa(gid))
    [m] = await _matches(client, admin_headers)
    assert m["status"] == "open" and m["vuln_withdrawn_at"] is None and m["vuln_withdrawn"] == {}

    await _withdraw(ghsa(gid, withdrawn=True), gid)
    [m] = await _matches(client, admin_headers)
    assert m["status"] == "mitigated"
    assert m["vuln_withdrawn_at"] == WITHDRAWN and m["vuln_withdrawn"] == {gid: WITHDRAWN}

    # PATCH returns the same shape
    r = await client.patch(f"{API}/matches/{m['id']}", json={"status": "accepted"}, headers=admin_headers)
    assert r.status_code == 200 and r.json()["vuln_withdrawn_at"] == WITHDRAWN


async def test_partial_withdrawal_keeps_row_level_flag_empty(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    """A CVE row that NVD also vouches for: the GHSA is marked withdrawn, the vulnerability itself is not."""
    cve, gid = "CVE-2026-11111", "GHSA-dddd-eeee-ffff"
    await _setup(VulnRecord(id=cve, sources=["nvd"], affected=[]), ghsa(gid, cve=cve))
    async with session_scope() as s:
        row = await s.get(VulnRow, cve)
        assert row is not None and row.affected
    await _withdraw(ghsa(gid, cve=cve, withdrawn=True), cve)
    r = await client.get(f"{API}/vulns/{cve}", headers=admin_headers)
    assert r.status_code == 200 and r.json()["vuln"]["data"]["withdrawn"] == {gid: WITHDRAWN}
    for m in await _matches(client, admin_headers):
        assert m["vuln_withdrawn_at"] is None and m["vuln_withdrawn"] == {gid: WITHDRAWN}
