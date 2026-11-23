"""Audit #132: a GHSA / OSV advisory withdrawn after it was stored closes the exposures based on it.

Fixture-only: records are built from the GHSA / OSV payload shapes used by tests/fixtures/intel.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select

from tokiwa.db.models.intel import AssetRow, VulnMatchRow, VulnRow
from tokiwa.db.session import session_scope
from tokiwa.intel.matcher import AUTO_CLOSED_PREFIX, run_matching
from tokiwa.intel.sources.ghsa import parse_ghsa_advisory
from tokiwa.intel.sources.osv import parse_osv_vuln
from tokiwa.intel.store import WITHDRAWN_AT_KEY, WITHDRAWN_KEY, apply_withdrawals, upsert_vulns
from tokiwa.schemas.intel import VulnRecord
from tokiwa.util import new_id

pytestmark = pytest.mark.usefixtures("db")
NOW = datetime(2026, 11, 22, tzinfo=UTC)
WITHDRAWN = "2026-11-20T00:00:00Z"
APACHE_CPE = {
    "cpe": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "2.4.0",
    "versionEndExcluding": "2.4.59",
}
APACHE_SW = {"vendor": "Apache Software Foundation", "product": "HTTP Server", "version": "2.4.58"}
PKG_SW = {"product": "flaskish", "ecosystem": "PyPI", "version": "1.0.0"}


def ghsa(ghsa_id: str, *, cve: str | None = None, withdrawn: bool = False, package: str = "flaskish") -> dict:
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve,
        "html_url": f"https://github.com/advisories/{ghsa_id}",
        "summary": "fixture advisory",
        "type": "reviewed",
        "severity": "high",
        "identifiers": [{"value": ghsa_id, "type": "GHSA"}],
        "published_at": "2026-11-01T00:00:00Z",
        "updated_at": WITHDRAWN if withdrawn else "2026-11-01T00:00:00Z",
        "withdrawn_at": WITHDRAWN if withdrawn else None,
        "vulnerabilities": [
            {
                "package": {"ecosystem": "pip", "name": package},
                "vulnerable_version_range": "< 1.2.0",
                "first_patched_version": "1.2.0",
            }
        ],
    }


def parsed(adv: dict[str, Any]) -> VulnRecord:
    rec = parse_ghsa_advisory(adv, include_withdrawn=True)
    assert rec is not None
    return rec


async def upsert(*records: VulnRecord) -> None:
    async with session_scope() as s:
        await upsert_vulns(s, list(records), now=NOW, epss_threshold=0.1)


async def withdraw(*records: VulnRecord) -> Any:
    async with session_scope() as s:
        return await apply_withdrawals(s, list(records), now=NOW)


async def add_asset(*software: dict[str, Any]) -> str:
    asset_id = new_id()
    async with session_scope() as s:
        s.add(
            AssetRow(
                id=asset_id,
                name="web-1",
                kind="host",
                ips=[],
                software=list(software),
                criticality="high",
                tags=[],
            )
        )
    return asset_id


async def load(vuln_id: str) -> VulnRow:
    async with session_scope() as s:
        row = await s.get(VulnRow, vuln_id)
    assert row is not None
    return row


async def match_rows(vuln_id: str) -> list[VulnMatchRow]:
    async with session_scope() as s:
        res = await s.execute(select(VulnMatchRow).where(VulnMatchRow.vuln_id == vuln_id))
        return list(res.scalars())


def test_parsers_keep_withdrawn_records_only_on_request() -> None:
    assert (
        parse_ghsa_advisory(ghsa("GHSA-aaaa-bbbb-cccc", withdrawn=True)) is None
    )  # old behaviour by default
    rec = parsed(ghsa("GHSA-aaaa-bbbb-cccc", withdrawn=True))
    assert rec.data["ghsa"]["withdrawn_at"] == WITHDRAWN and rec.affected[0].product == "flaskish"
    osv = parse_osv_vuln(
        {
            "id": "PYSEC-2026-1",
            "withdrawn": WITHDRAWN,
            "affected": [{"package": {"name": "x", "ecosystem": "PyPI"}}],
        },
        include_withdrawn=True,
    )
    assert osv is not None and osv.data["osv"]["withdrawn_at"] == WITHDRAWN
    assert parse_osv_vuln({"id": "PYSEC-2026-1", "withdrawn": WITHDRAWN}) is None


async def test_withdrawn_ghsa_only_advisory_closes_its_exposure() -> None:
    gid = "GHSA-aaaa-bbbb-cccc"
    await upsert(parsed(ghsa(gid)))
    await add_asset(PKG_SW)
    await run_matching(publish=False)
    (m,) = await match_rows(gid)
    assert m.status == "open"

    res = await withdraw(parsed(ghsa(gid, withdrawn=True)))
    assert res.updated == 1 and res.updates[0].reasons == ["withdrawn"]
    row = await load(gid)
    assert row.affected == [] and row.data[WITHDRAWN_AT_KEY] == WITHDRAWN
    assert row.data[WITHDRAWN_KEY] == {gid: WITHDRAWN}

    await run_matching(vuln_ids=[gid], publish=False)  # what intel.vuln_updated(withdrawn) triggers
    (m,) = await match_rows(gid)
    assert m.status == "mitigated" and m.reason.startswith(AUTO_CLOSED_PREFIX)

    assert (await withdraw(parsed(ghsa(gid, withdrawn=True)))).updated == 0  # idempotent

    # Re-published (un-withdrawn): marks cleared, package data back, the match reopens.
    await upsert(parsed(ghsa(gid)))
    row = await load(gid)
    assert WITHDRAWN_KEY not in row.data and WITHDRAWN_AT_KEY not in row.data and row.affected
    await run_matching(vuln_ids=[gid], publish=False)
    (m,) = await match_rows(gid)
    assert m.status == "open"


async def test_cve_row_keeps_nvd_cpe_data_when_its_ghsa_is_withdrawn() -> None:
    cve, gid = "CVE-2026-11111", "GHSA-dddd-eeee-ffff"
    await upsert(VulnRecord(id=cve, sources=["nvd"], affected=[]))
    async with session_scope() as s:  # NVD CPE configuration as the nvd source stores it
        row = await s.get(VulnRow, cve)
        assert row is not None
        row.affected = [{**APACHE_CPE, "product": "http_server", "vendor": "apache"}]
    await upsert(parsed(ghsa(gid, cve=cve)))
    await add_asset(APACHE_SW, PKG_SW)
    await run_matching(publish=False)
    assert [m.status for m in await match_rows(cve)] == ["open"]
    before = await load(cve)
    assert any(a.get("ecosystem") == "PyPI" for a in before.affected)

    await withdraw(parsed(ghsa(gid, cve=cve, withdrawn=True)))
    row = await load(cve)
    assert not any(a.get("ecosystem") for a in row.affected)  # the GHSA package entry is gone
    assert any(a.get("cpe") == APACHE_CPE["cpe"] for a in row.affected)  # NVD's stays
    assert WITHDRAWN_AT_KEY not in row.data and row.data[WITHDRAWN_KEY] == {gid: WITHDRAWN}
    await run_matching(vuln_ids=[cve], publish=False)
    assert [m.status for m in await match_rows(cve)] == ["open"]  # the CPE exposure stays open


async def test_duplicate_withdrawn_in_favour_of_another_advisory_keeps_the_row() -> None:
    cve = "CVE-2026-22222"
    await upsert(parsed(ghsa("GHSA-1111-2222-3333", cve=cve)), parsed(ghsa("GHSA-4444-5555-6666", cve=cve)))
    row = await load(cve)
    assert row.data["ghsa"]["id"] == "GHSA-4444-5555-6666"  # the feed's data came from the second advisory
    affected = list(row.affected)
    await withdraw(parsed(ghsa("GHSA-1111-2222-3333", cve=cve, withdrawn=True)))
    row = await load(cve)
    assert row.affected == affected and WITHDRAWN_AT_KEY not in row.data
    assert row.data[WITHDRAWN_KEY] == {"GHSA-1111-2222-3333": WITHDRAWN}


async def test_withdrawal_of_an_unknown_advisory_creates_nothing() -> None:
    res = await withdraw(parsed(ghsa("GHSA-7777-8888-9999", cve="CVE-2026-33333", withdrawn=True)))
    assert res.updated == 0 and res.created == 0
    async with session_scope() as s:
        assert (await s.execute(select(VulnRow))).scalars().all() == []
