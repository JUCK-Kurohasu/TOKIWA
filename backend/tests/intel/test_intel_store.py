"""Merge rules of tokiwa.intel.store (precedence, unions, alias folding, events, news de-dup, queries)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select

from tokiwa.bus import bus
from tokiwa.db.models.intel import VulnMatchRow, VulnRow
from tokiwa.db.session import session_scope
from tokiwa.intel.base import IntelItemIn
from tokiwa.intel.store import (
    canonicalize,
    publish_updates,
    query_items,
    query_vulns,
    upsert_items,
    upsert_vulns,
)
from tokiwa.schemas.common import Severity
from tokiwa.schemas.intel import SoftwareItem, VulnRecord

pytestmark = pytest.mark.usefixtures("db")
NOW = datetime(2026, 10, 22, tzinfo=UTC)


def rec(id_: str, source: str, **kw: Any) -> VulnRecord:
    return VulnRecord(id=id_, sources=[source], **kw)


async def upsert(*records: VulnRecord, now: datetime = NOW) -> Any:
    async with session_scope() as s:
        return await upsert_vulns(s, list(records), now=now, epss_threshold=0.1)


async def load(id_: str) -> VulnRow | None:
    async with session_scope() as s:
        return await s.get(VulnRow, id_)


def test_canonicalize_prefers_cve() -> None:
    r = canonicalize(rec("ghsa-JFH8-c2jp-5v3q", "osv", aliases=["cve-2021-44228", "GHSA-jfh8-c2jp-5v3q"]))
    assert r.id == "CVE-2021-44228" and r.aliases == ["GHSA-jfh8-c2jp-5v3q"]


async def test_cvss_precedence_nvd_over_ghsa_both_orders() -> None:
    ghsa = rec(
        "CVE-2024-1", "ghsa", cvss_score=7.5, cvss_vector="GHSA-V", severity=Severity.HIGH, title="ghsa title"
    )
    nvd = rec("CVE-2024-1", "nvd", cvss_score=9.8, cvss_vector="NVD-V", description="nvd text")
    await upsert(ghsa)
    await upsert(nvd)  # higher precedence overwrites
    row = await load("CVE-2024-1")
    assert row is not None and (row.cvss_score, row.cvss_vector, row.severity) == (9.8, "NVD-V", "critical")
    assert row.title == "ghsa title" and row.description == "nvd text"
    assert row.sources == ["ghsa", "nvd"] and row.data["_prov"]["cvss"] == "nvd"
    await upsert(rec("CVE-2024-1", "ghsa", cvss_score=5.0, cvss_vector="GHSA-V2", description="ghsa text"))
    row = await load("CVE-2024-1")
    assert row is not None and row.cvss_score == 9.8 and row.description == "nvd text"  # not downgraded
    await upsert(
        rec("CVE-2024-1", "nvd", cvss_score=8.8, cvss_vector="NVD-V2")
    )  # source refreshes its own value
    row = await load("CVE-2024-1")
    assert row is not None and row.cvss_score == 8.8


async def test_kev_precedence_unions_and_modified_max() -> None:
    nvd = rec(
        "CVE-2024-3400",
        "nvd",
        kev=True,
        kev_date_added=datetime(2024, 4, 12, tzinfo=UTC),
        modified=datetime(2026, 10, 21, tzinfo=UTC),
        cwe=["CWE-77"],
        references=["https://a"],
        affected=[SoftwareItem(vendor="paloaltonetworks", product="pan-os", version="10.2.0")],
    )
    kev = rec(
        "CVE-2024-3400",
        "kev",
        kev=True,
        kev_date_added=datetime(2024, 4, 12, tzinfo=UTC),
        kev_due_date=datetime(2024, 4, 19, tzinfo=UTC),
        kev_ransomware=False,
        cwe=["CWE-77", "CWE-20"],
        references=["https://a", "https://b"],
        affected=[SoftwareItem(vendor="Palo Alto Networks", product="PAN-OS")],
        modified=datetime(2025, 1, 1, tzinfo=UTC),
    )
    res = await upsert(nvd, kev)
    assert (res.created, res.updated) == (1, 0)
    row = await load("CVE-2024-3400")
    assert row is not None
    assert row.kev and row.kev_due_date == datetime(2024, 4, 19, tzinfo=UTC) and row.kev_ransomware is False
    assert row.data["_prov"]["kev"] == "kev"
    assert row.cwe == ["CWE-77", "CWE-20"] and row.references == ["https://a", "https://b"]
    assert len(row.affected) == 2
    assert row.modified == datetime(2026, 10, 21, tzinfo=UTC)
    # NVD without KEV data never clears the flag; identical input is reported as unchanged.
    res = await upsert(rec("CVE-2024-3400", "nvd", kev=False))
    row = await load("CVE-2024-3400")
    assert row is not None and row.kev
    res = await upsert(kev)
    assert (res.created, res.updated, res.unchanged) == (0, 0, 1)


async def test_alias_folding_and_reverse_alias_lookup() -> None:
    await upsert(rec("GHSA-9wx4-h78v-vm56", "ghsa", title="agent sdk injection", severity=Severity.HIGH))
    async with session_scope() as s:
        s.add(VulnMatchRow(vuln_id="GHSA-9wx4-h78v-vm56", asset_id="a1", reason="pkg", confidence=0.9))
    # GitHub later assigns a CVE: the GHSA row is folded into the CVE row, matches follow.
    res = await upsert(rec("CVE-2026-30000", "ghsa", aliases=["GHSA-9wx4-h78v-vm56"], description="d"))
    assert res.merged_aliases == 1
    assert await load("GHSA-9wx4-h78v-vm56") is None
    row = await load("CVE-2026-30000")
    assert row is not None and row.title == "agent sdk injection" and row.aliases == ["GHSA-9wx4-h78v-vm56"]
    async with session_scope() as s:
        match_ids = (await s.execute(select(VulnMatchRow.vuln_id))).scalars().all()
        assert match_ids == ["CVE-2026-30000"]
    # A JVNDB-keyed record whose id is already an alias of a CVE row merges into it (no duplicate).
    await upsert(rec("CVE-2026-20001", "nvd", aliases=["JVNDB-2026-000101"], description="en"))
    await upsert(rec("JVNDB-2026-000101", "jvn", title="日本語タイトル", description="日本語"))
    assert await load("JVNDB-2026-000101") is None
    row = await load("CVE-2026-20001")
    assert row is not None and row.title == "日本語タイトル" and row.description == "en"


async def test_events_kev_added_recent_only_and_epss_spike() -> None:
    res = await upsert(
        rec("CVE-2026-10001", "kev", kev=True, kev_date_added=datetime(2026, 10, 20, tzinfo=UTC)),
        rec("CVE-2021-44228", "kev", kev=True, kev_date_added=datetime(2021, 12, 10, tzinfo=UTC)),
        rec("CVE-2024-5", "epss", epss=0.02),
    )
    assert [(u.vuln.id, u.reasons) for u in res.updates] == [("CVE-2026-10001", ["kev_added"])]
    res = await upsert(rec("CVE-2024-5", "epss", epss=0.35), rec("CVE-2026-10001", "kev", kev=True))
    assert [(u.vuln.id, u.reasons) for u in res.updates] == [("CVE-2024-5", ["epss_spike"])]
    res = await upsert(rec("CVE-2024-5", "epss", epss=0.40))  # +0.05 while above threshold: no event
    assert res.updates == []
    res = await upsert(rec("CVE-2024-5", "epss", epss=0.55))  # +0.15: spike
    assert res.updates[0].reasons == ["epss_spike"]

    received: list[VulnRecord] = []

    async def handler(payload: VulnRecord) -> None:
        received.append(payload)

    bus.subscribe("intel.vuln_updated", handler)
    assert await publish_updates(res.updates) == 1
    await bus.drain()
    assert received[0].id == "CVE-2024-5" and received[0].data["update_reasons"] == ["epss_spike"]
    row = await load("CVE-2024-5")
    assert row is not None and "update_reasons" not in row.data  # not persisted


async def test_news_dedup_by_url_hash() -> None:
    items = [
        IntelItemIn(source="rss:a", url="https://Example.com/post#x", title="t1", vuln_ids=["cve-2024-1"]),
        IntelItemIn(source="rss:a", url="https://example.com/post", title="t1 dup"),
        IntelItemIn(source="rss:b", url=None, title="no link"),
    ]
    async with session_scope() as s:
        first = await upsert_items(s, items)
    async with session_scope() as s:
        second = await upsert_items(s, items)
    assert (first.created, first.skipped) == (2, 1)
    assert (second.created, second.skipped) == (0, 3)
    async with session_scope() as s:
        page, total = await query_items(s, source="rss")
        assert total == 2 and page[0].vuln_ids in (["CVE-2024-1"], [])
        _, total_a = await query_items(s, source="rss:a", vuln_id="CVE-2024-1")
        assert total_a == 1


async def test_query_vulns_filters_and_default_order() -> None:
    await upsert(
        rec("CVE-2024-1", "nvd", cvss_score=9.8, modified=NOW),
        rec("CVE-2024-2", "kev", kev=True),
        rec("CVE-2024-3", "nvd", cvss_score=5.0, title="openssh race"),
        rec("CVE-2024-4", "epss", epss=0.9),
        rec("CVE-2024-5", "epss", epss=0.2),
    )
    async with session_scope() as s:
        s.add(VulnMatchRow(vuln_id="CVE-2024-3", asset_id="a1", reason="cpe", confidence=0.8))
    async with session_scope() as s:
        items, total = await query_vulns(s)
        assert total == 5
        assert [v.id for v in items] == ["CVE-2024-2", "CVE-2024-4", "CVE-2024-5", "CVE-2024-1", "CVE-2024-3"]
        assert [v.id for v in (await query_vulns(s, kev=True))[0]] == ["CVE-2024-2"]
        assert [v.id for v in (await query_vulns(s, min_epss=0.5))[0]] == ["CVE-2024-4"]
        assert [v.id for v in (await query_vulns(s, min_cvss=9.0))[0]] == ["CVE-2024-1"]
        assert [v.id for v in (await query_vulns(s, matched=True))[0]] == ["CVE-2024-3"]
        assert [v.id for v in (await query_vulns(s, q="OpenSSH"))[0]] == ["CVE-2024-3"]
        assert (await query_vulns(s, limit=2, offset=4))[1] == 5


async def test_affected_entries_always_have_product() -> None:
    """Rows written by other modules may hold CPE-only entries; merging must keep VulnRecord-valid data."""
    async with session_scope() as s:
        s.add(
            VulnRow(
                id="CVE-2024-7",
                sources=["research"],
                affected=[
                    {"cpe": "cpe:2.3:a:openbsd:openssh:9.7:*:*:*:*:*:*:*"},
                    {"vendor": "x"},  # nothing to derive a product from -> dropped
                ],
            )
        )
    await upsert(rec("CVE-2024-7", "nvd", affected=[SoftwareItem(product="openssh", vendor="openbsd")]))
    row = await load("CVE-2024-7")
    assert row is not None and all(a.get("product") for a in row.affected)
    vuln = VulnRecord.model_validate(row)
    assert {(a.vendor, a.product, a.version) for a in vuln.affected} == {
        ("openbsd", "openssh", "9.7"),
        ("openbsd", "openssh", None),
    }
