"""Matcher: version comparison, CPE ranges, name fallback, false-match avoidance, DB upsert + bus."""

from __future__ import annotations

from typing import Any

import pytest

from tokiwa.bus import bus
from tokiwa.db.models.intel import AssetRow, VulnMatchRow
from tokiwa.db.session import session_scope
from tokiwa.intel import matcher
from tokiwa.intel.matcher import (
    AUTO_CLOSED_PREFIX,
    compare_versions,
    extract_vuln_ids,
    match_asset_to_vuln,
    match_software,
    open_exposures,
    parse_cpe,
    product_key,
    run_matching,
    vendor_key,
)
from tokiwa.schemas.intel import VulnMatch, VulnRecord

from ._helpers import APACHE_AFFECTED, APACHE_SW, add_asset, add_vuln, matches

CPE_ANY = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0", "1.0.0", 0),
        ("1.10", "1.9", 1),
        ("2.4.58", "2.4.59", -1),
        ("1.0rc1", "1.0", -1),
        ("1.0.1", "1.0rc1", 1),
        ("1.0a1", "1.0b1", -1),
        ("1.0.dev1", "1.0a1", -1),
        ("1.0.post1", "1.0", 1),
        ("8.0p1", "8.0", 1),
        ("8.0p1", "8.1p1", -1),
        ("1.1.1w", "1.1.1", 1),  # OpenSSL letter releases are post-releases
        ("1.1.1a", "1.1.1", 1),
        ("2.4.58-1ubuntu1", "2.4.58", 1),
        ("1:1.0", "2.0", 1),  # epoch
        ("v2.0.0", "2.0", 0),
        ("1.0.0-alpha", "1.0.0-alpha.1", -1),
        ("1.0.0-beta", "1.0.0-alpha.1", 1),
        ("1.0~rc1", "1.0", -1),
        ("20240101", "20231231", 1),
        ("abc", "1.0", None),
        ("*", "1.0", None),
        (None, "1.0", None),
    ],
)
def test_compare_versions(a: Any, b: Any, expected: int | None) -> None:
    assert compare_versions(a, b) == expected
    if expected is not None:
        assert compare_versions(b, a) == -expected


def test_parse_cpe_23_22_and_escapes() -> None:
    c = parse_cpe("cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*")
    assert c is not None and (c.vendor, c.product, c.version) == ("apache", "http_server", "2.4.58")
    esc = parse_cpe(r"cpe:2.3:a:foo:bar\:baz:1.0:*:*:*:*:*:*:*")
    assert esc is not None and esc.product == "bar:baz"
    old = parse_cpe("cpe:/a:openbsd:openssh:8.0:p1")
    assert old is not None and old.full_version() == "8.0p1" and old.target_sw == "*"
    assert parse_cpe("not-a-cpe") is None
    assert parse_cpe(None) is None


def test_name_normalization() -> None:
    assert vendor_key("The Apache Software Foundation") == "apache"
    assert vendor_key("Microsoft Corporation") == "microsoft"
    assert product_key("Apache HTTP Server") == "http_server"
    assert product_key("httpd") == "http_server"
    assert product_key("apache_tomcat", "apache") == "tomcat"
    assert product_key("Node.js") == "node_js" == product_key("nodejs")


def test_cpe_range_match() -> None:
    m = match_software(APACHE_SW, APACHE_AFFECTED[0])
    assert m is not None
    assert m.method == "cpe" and m.confidence == matcher.CONF_RANGE
    assert "apache:http_server" in m.reason and ">=2.4.0,<2.4.59" in m.reason and "2.4.58" in m.reason


@pytest.mark.parametrize(
    ("version", "affected_extra", "matches_"),
    [
        ("2.4.59", {"versionEndExcluding": "2.4.59"}, False),
        ("2.4.59", {"versionEndIncluding": "2.4.59"}, True),
        ("2.3.9", {"versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.59"}, False),
        ("2.4.0", {"versionStartExcluding": "2.4.0", "versionEndExcluding": "2.4.59"}, False),
        ("2.4.1", {"versionStartExcluding": "2.4.0", "versionEndExcluding": "2.4.59"}, True),
        ("2.4.58-1ubuntu1", {"versionEndExcluding": "2.4.59"}, True),
    ],
)
def test_cpe_range_boundaries(version: str, affected_extra: dict[str, str], matches_: bool) -> None:
    sw = {"vendor": "apache", "product": "http_server", "version": version}
    result = match_software(sw, {"cpe": CPE_ANY, **affected_extra})
    assert (result is not None) is matches_


def test_cpe_exact_version_with_update() -> None:
    affected = {"cpe": "cpe:2.3:a:openbsd:openssh:8.0:p1:*:*:*:*:*:*"}
    hit = match_software({"cpe": "cpe:2.3:a:openbsd:openssh:8.0:p1:*:*:*:*:*:*"}, affected)
    assert hit is not None and hit.confidence == matcher.CONF_EXACT and hit.method == "cpe"
    assert (
        match_software({"vendor": "OpenBSD", "product": "OpenSSH", "version": "8.0p1"}, affected) is not None
    )
    assert match_software({"vendor": "openbsd", "product": "openssh", "version": "8.1p1"}, affected) is None


def test_cpe_all_versions_and_unknown_version() -> None:
    all_versions = match_software(
        {"vendor": "apache", "product": "http_server", "version": "2.4.1"}, {"cpe": CPE_ANY}
    )
    assert all_versions is not None and all_versions.confidence == matcher.CONF_ALL_VERSIONS_CPE
    unknown = match_software({"vendor": "apache", "product": "http_server"}, APACHE_AFFECTED[0])
    assert unknown is not None and unknown.confidence == matcher.CONF_UNKNOWN_VERSION
    assert "unknown" in unknown.reason


def test_unparseable_version_gives_low_confidence() -> None:
    m = match_software(
        {"vendor": "apache", "product": "http_server", "version": "custom-build"}, APACHE_AFFECTED[0]
    )
    assert m is not None
    assert m.confidence == matcher.CONF_INCONCLUSIVE < 0.5
    assert "inconclusive" in m.reason


def test_name_fallback_is_less_confident_than_cpe() -> None:
    name_only = match_software({"product": "httpd", "version": "2.4.58"}, APACHE_AFFECTED[0])
    assert name_only is not None and name_only.method == "name"
    with_vendor = match_software(
        {"vendor": "apache", "product": "apache2", "version": "2.4.58"},
        {"vendor": "Apache", "product": "HTTP Server", "versionEndExcluding": "2.4.59"},
    )
    assert with_vendor is not None and with_vendor.method == "name"
    assert name_only.confidence < with_vendor.confidence < matcher.CONF_RANGE


def test_osv_ranges_and_ecosystem() -> None:
    affected = {
        "product": "requests",
        "ecosystem": "PyPI",
        "ranges": [
            {"type": "GIT", "events": [{"introduced": "abc123"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]},
        ],
    }
    hit = match_software({"product": "requests", "ecosystem": "PyPI", "version": "2.25.0"}, affected)
    assert hit is not None and "ecosystem" in hit.reason
    assert match_software({"product": "requests", "ecosystem": "PyPI", "version": "2.31.0"}, affected) is None
    # same package name in a different ecosystem is a different package
    assert match_software({"product": "requests", "ecosystem": "npm", "version": "2.25.0"}, affected) is None
    last = {"product": "lib", "vendor": "acme", "introduced": "1.0", "last_affected": "1.4"}
    assert match_software({"product": "lib", "vendor": "acme", "version": "1.4"}, last) is not None
    assert match_software({"product": "lib", "vendor": "acme", "version": "1.5"}, last) is None


def test_constraint_expressions_and_explicit_versions() -> None:
    affected = {"vendor": "f5", "product": "nginx", "version": "<1.20.0 || >=1.25.0,<1.25.4"}
    sw = {"vendor": "F5 Networks", "product": "nginx"}
    assert match_software({**sw, "version": "1.19.9"}, affected) is not None
    assert match_software({**sw, "version": "1.22.1"}, affected) is None
    assert match_software({**sw, "version": "1.25.3"}, affected) is not None
    listed = {"vendor": "acme", "product": "widget", "versions": ["1.0.0", "1.0.1"]}
    exact = match_software({"vendor": "acme", "product": "widget", "version": "1.0.1"}, listed)
    assert exact is not None and "listed" in exact.reason
    assert match_software({"vendor": "acme", "product": "widget", "version": "1.0.2"}, listed) is None


@pytest.mark.parametrize(
    ("software", "affected"),
    [
        # vendor mismatch: same product name, different vendors
        ({"vendor": "acme", "product": "portal", "version": "1.0"}, {"vendor": "other", "product": "portal"}),
        # generic product name without vendor/ecosystem confirmation
        ({"product": "server", "version": "1.0"}, {"product": "server", "version": "1.0"}),
        # substring product names must not match (nginx-ui is not nginx)
        ({"product": "nginx-ui", "version": "1.25.0"}, {"vendor": "f5", "product": "nginx"}),
        # different CPE part (os vs application)
        (
            {"cpe": "cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*"},
            {"cpe": "cpe:2.3:a:linux:linux_kernel:*:*:*:*:*:*:*:*"},
        ),
        # NVD platform-only (non-vulnerable) entry
        (APACHE_SW, {**APACHE_AFFECTED[0], "vulnerable": False}),
        # name only + unknown version is too weak to store
        ({"product": "nginx"}, {"product": "nginx", "version": "<1.25.4"}),
    ],
)
def test_false_matches_are_avoided(software: dict[str, Any], affected: dict[str, Any]) -> None:
    assert match_software(software, affected) is None


def test_best_match_wins() -> None:
    software = [{"product": "httpd", "version": "2.4.58"}, APACHE_SW]
    best = match_asset_to_vuln(software, APACHE_AFFECTED)
    assert best is not None and best.match.method == "cpe" and best.software == APACHE_SW


def test_extract_vuln_ids() -> None:
    rec = VulnRecord(id="CVE-2024-0003")
    payloads: list[Any] = [
        "CVE-2024-0001",
        {"id": "CVE-2024-0002"},
        rec,
        {"vuln_ids": ["CVE-2024-0004", "CVE-2024-0001"]},
        [{"vuln_id": "CVE-2024-0005"}],
    ]
    assert extract_vuln_ids(payloads) == [
        "CVE-2024-0001",
        "CVE-2024-0002",
        "CVE-2024-0003",
        "CVE-2024-0004",
        "CVE-2024-0005",
    ]
    assert extract_vuln_ids(None) == []


@pytest.mark.usefixtures("db")
async def test_run_matching_upsert_publish_close_reopen() -> None:
    published: list[VulnMatch] = []

    async def collect(vm: VulnMatch) -> None:
        published.append(vm)

    bus.subscribe("intel.vuln_matched", collect)
    await add_vuln("CVE-2099-0001", kev=True, affected=APACHE_AFFECTED)
    await add_vuln("CVE-2099-0002", affected=[{"vendor": "acme", "product": "widget", "version": "9.9"}])
    asset_id = await add_asset("web-1", software=[APACHE_SW])
    await add_asset("db-1", software=[{"vendor": "postgresql", "product": "postgresql", "version": "16.1"}])

    summary = await run_matching()
    await bus.drain()
    assert len(summary.created) == 1
    [row] = await matches()
    assert (row.vuln_id, row.asset_id, row.status) == ("CVE-2099-0001", asset_id, "open")
    assert row.confidence == matcher.CONF_RANGE and "CPE match" in row.reason
    assert row.software == APACHE_SW
    assert [p.vuln_id for p in published] == ["CVE-2099-0001"]

    # idempotent: second pass creates nothing and publishes nothing
    again = await run_matching(vuln_ids=["CVE-2099-0001"])
    await bus.drain()
    assert again.created == [] and len(await matches()) == 1 and len(published) == 1

    # asset patched -> auto-closed
    async with session_scope() as s:
        asset = await s.get(AssetRow, asset_id)
        assert asset is not None
        asset.software = [{**APACHE_SW, "version": "2.4.62"}]
    closed = await run_matching(asset_ids=[asset_id])
    assert closed.closed == 1
    [row] = await matches()
    assert row.status == "mitigated" and row.reason.startswith(AUTO_CLOSED_PREFIX)

    # downgraded again -> reopened and re-published
    async with session_scope() as s:
        asset = await s.get(AssetRow, asset_id)
        assert asset is not None
        asset.software = [APACHE_SW]
    reopened = await run_matching(asset_ids=[asset_id])
    await bus.drain()
    assert reopened.reopened == 1 and len(published) == 2
    [row] = await matches()
    assert row.status == "open" and not row.reason.startswith(AUTO_CLOSED_PREFIX)


@pytest.mark.usefixtures("db")
async def test_analyst_status_is_preserved() -> None:
    await add_vuln("CVE-2099-0003", affected=APACHE_AFFECTED)
    asset_id = await add_asset("web-2", software=[APACHE_SW])
    await run_matching()
    [row] = await matches()
    async with session_scope() as s:
        m = await s.get(VulnMatchRow, row.id)
        assert m is not None
        m.status = "false_positive"
    await run_matching()
    async with session_scope() as s:
        asset = await s.get(AssetRow, asset_id)
        assert asset is not None
        asset.software = [{**APACHE_SW, "version": "2.4.62"}]
    await run_matching()
    [row2] = await matches()
    assert row2.status == "false_positive"


@pytest.mark.usefixtures("db")
async def test_deleted_asset_matches_are_removed_by_full_pass() -> None:
    await add_vuln("CVE-2099-0004", affected=APACHE_AFFECTED)
    asset_id = await add_asset("web-3", software=[APACHE_SW])
    await run_matching()
    async with session_scope() as s:
        asset = await s.get(AssetRow, asset_id)
        await s.delete(asset)
    await run_matching()
    assert await matches() == []


@pytest.mark.usefixtures("db")
async def test_open_exposures_only_kev_or_high_epss() -> None:
    await add_vuln("CVE-2099-0010", kev=True, affected=APACHE_AFFECTED)
    await add_vuln("CVE-2099-0011", epss=0.5, affected=APACHE_AFFECTED)
    await add_vuln("CVE-2099-0012", epss=0.01, affected=APACHE_AFFECTED)
    asset_id = await add_asset("web-4", software=[APACHE_SW])
    await run_matching()
    async with session_scope() as s:
        exp = await open_exposures(s, [asset_id], epss_threshold=0.1)
    assert [v["vuln_id"] for v in exp[asset_id]] == ["CVE-2099-0010", "CVE-2099-0011"]
    assert exp[asset_id][0]["kev"] is True
