"""Fixture parsing + request-parameter tests for every intel source (no network: httpx.MockTransport)."""

from __future__ import annotations

import gzip
import json
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from tokiwa.config import Settings
from tokiwa.intel.sources import _common
from tokiwa.intel.sources.epss import EpssSource, epss_batches
from tokiwa.intel.sources.ghsa import GhsaSource, ghsa_params
from tokiwa.intel.sources.jvn import JvnSource, jvn_params
from tokiwa.intel.sources.kev import KevSource
from tokiwa.intel.sources.nvd import NvdSource, nvd_datetime, nvd_params, nvd_windows
from tokiwa.intel.sources.osv import OsvSource
from tokiwa.intel.sources.rss import RssSource, parse_feed
from tokiwa.schemas.common import Severity
from tokiwa.schemas.intel import SoftwareItem

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "intel"
NOW = datetime(2026, 10, 22, 3, 0, tzinfo=UTC)


def _client(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _by_id(vulns: list[Any]) -> dict[str, Any]:
    return {v.id: v for v in vulns}


# --------------------------------------------------------------------------- common helpers


def test_common_helpers() -> None:
    assert _common.normalize_vuln_id(" cve-2024-3400 ") == "CVE-2024-3400"
    assert _common.normalize_vuln_id("ghsa-JFH8-c2jp-5v3q") == "GHSA-jfh8-c2jp-5v3q"
    assert _common.extract_cves("x cve-2024-3400 y CVE-2024-3400, CVE-2021-44228") == [
        "CVE-2024-3400",
        "CVE-2021-44228",
    ]
    assert (
        _common.cpe22_to_23("cpe:/a:example:web_console") == "cpe:2.3:a:example:web_console:*:*:*:*:*:*:*:*"
    )
    sw = _common.software_from_cpe("cpe:2.3:o:paloaltonetworks:pan-os:10.2.0:-:*:*:*:*:*:*")
    assert sw is not None and (sw.vendor, sw.product, sw.version) == ("paloaltonetworks", "pan-os", "10.2.0")
    assert _common.severity_from_text("MODERATE") is Severity.MEDIUM
    assert _common.severity_from_score(9.8) is Severity.CRITICAL
    assert _common.parse_dt("2024-01-10T14:15+09:00") == datetime(2024, 1, 10, 5, 15, tzinfo=UTC)
    assert _common.parse_dt("2024-04-12T08:15:06.230") == datetime(2024, 4, 12, 8, 15, 6, 230000, tzinfo=UTC)


async def test_fetch_retries_then_fails_and_caps_size(no_sleep: list[float]) -> None:
    calls = {"n": 0}

    def flaky(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, headers={"Retry-After": "7"})

    async with _client(flaky) as c:
        with pytest.raises(_common.FetchError, match="HTTP 503"):
            await _common.fetch(c, "GET", "https://example.test/x?secret=no")
    assert calls["n"] == 3 and no_sleep == [7.0, 7.0]

    async with _client(lambda r: httpx.Response(200, content=b"x" * 100)) as c:
        with pytest.raises(_common.FetchError, match="exceeds"):
            await _common.fetch(c, "GET", "https://example.test/big", max_bytes=10)


@pytest.mark.parametrize("encoding", ["gzip", "deflate"])
async def test_fetch_decodes_compressed_responses_once(encoding: str) -> None:
    # Real feeds (CISA, GitHub, RSS hosts) answer compressed. fetch() rebuilds the response from the already
    # decoded body, so it must drop Content-Encoding or httpx tries to decompress a second time.
    body = json.dumps({"ok": True, "pad": "x" * 500}).encode()
    packed = gzip.compress(body) if encoding == "gzip" else zlib.compress(body)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Encoding": encoding, "ETag": '"v1"', "Content-Type": "application/json"},
            content=packed,
        )

    async with _client(handler) as c:
        resp = await _common.fetch(c, "GET", "https://example.test/feed.json")
        assert resp.json()["ok"] is True
        assert "content-encoding" not in resp.headers
        assert resp.headers["etag"] == '"v1"'  # conditional GETs still see the validators
        # The size cap applies to the decoded body, which also bounds decompression bombs.
        with pytest.raises(_common.FetchError, match="exceeds"):
            await _common.fetch(c, "GET", "https://example.test/feed.json", max_bytes=len(packed))


# --------------------------------------------------------------------------- KEV


async def test_kev_parse_and_conditional_get(settings: Settings, feeds: Any) -> None:
    src = KevSource(settings)
    async with feeds.client() as c:
        res = await src.fetch(c, None)
    assert not res.errors
    v = _by_id(res.vulns)
    assert set(v) == {"CVE-2024-3400", "CVE-2023-4966", "CVE-2021-44228", "CVE-2026-10001"}
    pan = v["CVE-2024-3400"]
    assert pan.kev and pan.sources == ["kev"]
    assert pan.kev_date_added == datetime(2024, 4, 12, tzinfo=UTC)
    assert pan.kev_due_date == datetime(2024, 4, 19, tzinfo=UTC)
    assert pan.kev_ransomware is False  # "Unknown"
    assert v["CVE-2023-4966"].kev_ransomware is True  # "Known"
    assert pan.cwe == ["CWE-77"]
    assert pan.references == [
        "https://security.paloaltonetworks.com/CVE-2024-3400",
        "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
    ]
    assert pan.affected[0].vendor == "Palo Alto Networks" and pan.affected[0].product == "PAN-OS"
    assert "If-Modified-Since" not in feeds.calls[0].headers

    feeds.set(
        "www.cisa.gov",
        "/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        lambda r: httpx.Response(304),
    )
    async with feeds.client() as c:
        res = await src.fetch(c, datetime(2026, 10, 21, 12, 0, tzinfo=UTC))
    assert res.vulns == [] and not res.errors
    assert feeds.calls[-1].headers["If-Modified-Since"] == "Wed, 21 Oct 2026 12:00:00 GMT"


async def test_kev_gzip_feed(settings: Settings, feeds: Any) -> None:
    raw = (FIXTURES / "kev" / "known_exploited_vulnerabilities.json").read_bytes()
    feeds.set(
        "www.cisa.gov",
        "/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        lambda r: httpx.Response(200, headers={"Content-Encoding": "gzip"}, content=gzip.compress(raw)),
    )
    async with feeds.client() as c:
        res = await KevSource(settings).fetch(c, None)
    assert not res.errors
    assert "CVE-2024-3400" in _by_id(res.vulns)


# --------------------------------------------------------------------------- EPSS


def test_epss_batches_respect_char_and_count_limits() -> None:
    cves = [f"CVE-2024-{i:05d}" for i in range(250)]  # 14 chars each
    batches = epss_batches(cves)
    assert all(len(b) <= 100 for b in batches)
    assert all(len(",".join(b)) <= 2000 for b in batches)
    assert sum(len(b) for b in batches) == 250
    long_ids = [f"CVE-2024-{i:07d}" for i in range(150)]  # 16 chars -> 2000-char limit binds before 100
    assert all(len(",".join(b)) <= 2000 for b in epss_batches(long_ids, max_items=1000))
    assert epss_batches(["GHSA-xxxx-yyyy-zzzz", "cve-2024-1111", "CVE-2024-1111"]) == [["CVE-2024-1111"]]


async def test_epss_parse_targets(settings: Settings, feeds: Any) -> None:
    src = EpssSource(settings)
    src.targets = ["CVE-2024-3400", "CVE-2021-44228", "CVE-2099-0001"]
    async with feeds.client() as c:
        res = await src.fetch(c, None)
    v = _by_id(res.vulns)
    assert set(v) == {"CVE-2024-3400", "CVE-2021-44228"}  # unknown CVE simply has no score
    assert v["CVE-2024-3400"].epss == pytest.approx(0.94358)
    assert v["CVE-2024-3400"].epss_percentile == pytest.approx(0.99945)
    assert v["CVE-2024-3400"].data["epss"]["date"] == "2026-10-21"
    req = feeds.requests_to("api.first.org")[0]
    assert req.url.params["cve"] == "CVE-2024-3400,CVE-2021-44228,CVE-2099-0001"
    assert req.url.params["limit"] == "3"


# --------------------------------------------------------------------------- NVD


def test_nvd_windows_and_params() -> None:
    # Initial run: lookback window only.
    w = nvd_windows(None, NOW, 3)
    assert w == [(NOW - timedelta(days=3), NOW)]
    # Incremental: since minus overlap.
    since = NOW - timedelta(hours=6)
    (start, end), *rest = nvd_windows(since, NOW, 3)
    assert not rest and end == NOW and start == since - timedelta(minutes=10)
    # Long outage: split into <=120-day windows that cover the whole range.
    w = nvd_windows(NOW - timedelta(days=200), NOW, 3)
    assert len(w) == 2
    assert all(e - s <= timedelta(days=120) for s, e in w)
    assert w[0][0] == NOW - timedelta(days=200, minutes=10) and w[-1][1] == NOW
    p = nvd_params(NOW - timedelta(days=3), NOW, 2000)
    assert p == {
        "lastModStartDate": "2026-10-19T03:00:00.000+00:00",
        "lastModEndDate": "2026-10-22T03:00:00.000+00:00",
        "resultsPerPage": 2000,
        "startIndex": 2000,
    }
    assert nvd_datetime(datetime(2026, 1, 2, 3, 4, 5, 678900, tzinfo=UTC)) == "2026-01-02T03:04:05.678+00:00"
    url = httpx.Request("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0", params=p).url
    assert "%2B00%3A00" in str(url)  # '+' must be percent-encoded


async def test_nvd_paging_mapping_and_rate_limit(
    settings: Settings, feeds: Any, no_sleep: list[float]
) -> None:
    src = NvdSource(settings)
    src.now = lambda: NOW
    async with feeds.client() as c:
        res = await src.fetch(c, None)
    assert not res.errors
    reqs = feeds.requests_to("services.nvd.nist.gov")
    assert [r.url.params["startIndex"] for r in reqs] == ["0", "2"]
    assert "apiKey" not in reqs[0].headers
    assert no_sleep == [6.0]  # one pause between the two pages without an API key
    v = _by_id(res.vulns)
    assert set(v) == {"CVE-2024-3400", "CVE-2024-6387", "CVE-2021-44228"}
    pan = v["CVE-2024-3400"]
    assert pan.cvss_score == 9.8  # v3.1 Primary (NVD) preferred over CNA 10.0 and v4.0
    assert pan.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert pan.severity is Severity.CRITICAL
    assert pan.data["nvd"]["cvss"]["v40"]["score"] == 10.0
    assert pan.cwe == ["CWE-77", "CWE-20"]  # Primary first, NVD-CWE-* skipped
    assert pan.kev and pan.kev_date_added == datetime(2024, 4, 12, tzinfo=UTC)
    assert pan.modified == datetime(2026, 10, 21, 16, 53, 46, 187000, tzinfo=UTC)
    assert pan.description is not None and pan.description.startswith("A command injection")
    assert {(a.product, a.version) for a in pan.affected} == {("pan-os", "10.2.0"), ("pan-os", None)}
    ranged = [m for m in pan.data["nvd"]["cpe_matches"] if "versionEndExcluding" in m]
    assert ranged == [
        {
            "criteria": "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "11.0.0",
            "versionEndExcluding": "11.0.4",
            "matchCriteriaId": "D1E1A5A8-6F2E-4E4F-9A3B-2B7A1C1D0002",
        }
    ]
    ssh = v["CVE-2024-6387"]
    assert ssh.cvss_score == 8.1 and ssh.severity is Severity.HIGH and not ssh.kev
    assert [a.product for a in ssh.affected] == ["openssh"]  # non-vulnerable platform CPE excluded
    log4j = v["CVE-2021-44228"]
    assert log4j.cvss_score == 10.0 and log4j.data["nvd"]["cvss"]["v2"]["severity"] == "high"


async def test_nvd_api_key_header_delay_and_error(
    settings: Settings, feeds: Any, no_sleep: list[float]
) -> None:
    from pydantic import SecretStr

    settings.intel.nvd_api_key = SecretStr("test-key-not-real")
    src = NvdSource(settings)
    src.now = lambda: NOW
    async with feeds.client() as c:
        await src.fetch(c, None)
    assert feeds.requests_to("services.nvd.nist.gov")[0].headers["apiKey"] == "test-key-not-real"
    assert no_sleep == [0.8]

    feeds.set("services.nvd.nist.gov", "/rest/json/cves/2.0", lambda r: httpx.Response(500))
    async with feeds.client() as c:
        res = await src.fetch(c, None)
    assert res.vulns == [] and res.errors and "HTTP 500" in res.errors[0]
    assert "test-key-not-real" not in res.errors[0]


# --------------------------------------------------------------------------- GHSA


async def test_ghsa_params_paging_and_mapping(settings: Settings, feeds: Any) -> None:
    assert ghsa_params(datetime(2026, 10, 21, 18, 0, tzinfo=UTC), 3, NOW) == {
        "type": "reviewed",
        "per_page": 100,
        "sort": "updated",
        "direction": "desc",
        "updated": ">=2026-10-21",
    }
    src = GhsaSource(settings)
    src.now = lambda: NOW
    async with feeds.client() as c:
        res = await src.fetch(c, None)
    assert not res.errors
    reqs = feeds.requests_to("api.github.com")
    assert len(reqs) == 2
    assert reqs[0].headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert "Authorization" not in reqs[0].headers
    assert reqs[0].url.params["updated"] == ">=2026-10-19"
    assert reqs[1].url.params["after"] == "Y3Vyc29yOnYyOpK0"  # followed the Link header verbatim
    v = _by_id(res.vulns)
    assert set(v) == {"CVE-2021-44228", "GHSA-9wx4-h78v-vm56", "CVE-2021-45046"}  # withdrawn skipped
    log4j = v["CVE-2021-44228"]
    assert log4j.aliases == ["GHSA-jfh8-c2jp-5v3q"]
    assert log4j.cvss_score == 10.0 and log4j.severity is Severity.CRITICAL
    assert log4j.affected == [SoftwareItem(product="org.apache.logging.log4j:log4j-core", ecosystem="Maven")]
    assert log4j.data["ghsa"]["vulnerabilities"][0]["vulnerable_version_range"] == ">= 2.13.0, < 2.15.0"
    assert log4j.data["ghsa"]["vulnerabilities"][0]["first_patched_version"] == "2.15.0"
    no_cve = v["GHSA-9wx4-h78v-vm56"]
    assert no_cve.cvss_score == 8.6 and no_cve.cvss_vector.startswith("CVSS:4.0/")  # type: ignore[union-attr]
    assert no_cve.affected[0].ecosystem == "PyPI"


async def test_ghsa_token_header(settings: Settings, feeds: Any) -> None:
    from pydantic import SecretStr

    settings.intel.github_token = SecretStr("ghp_test_not_real")
    async with feeds.client() as c:
        await GhsaSource(settings).fetch(c, None)
    assert feeds.requests_to("api.github.com")[0].headers["Authorization"] == "Bearer ghp_test_not_real"


# --------------------------------------------------------------------------- OSV


async def test_osv_querybatch_and_details(settings: Settings, feeds: Any) -> None:
    src = OsvSource(settings)
    async with feeds.client() as c:
        empty = await src.fetch(c, None)
    assert empty.vulns == [] and not empty.errors and feeds.calls == []  # no packages -> skipped

    src.packages = [
        SoftwareItem(product="org.apache.logging.log4j:log4j-core", version="2.14.1", ecosystem="Maven"),
        SoftwareItem(product="requests", version="2.32.3", ecosystem="PyPI"),
        SoftwareItem(product="nginx", version="1.25.0"),  # no ecosystem -> not queried
    ]
    async with feeds.client() as c:
        res = await src.fetch(c, None)
    assert not res.errors
    body = json.loads(feeds.requests_to("api.osv.dev")[0].content)
    assert body == {
        "queries": [
            {
                "package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"},
                "version": "2.14.1",
            },
            {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.32.3"},
        ]
    }
    v = _by_id(res.vulns)
    assert set(v) == {"CVE-2021-44228", "CVE-2021-45046"}
    log4j = v["CVE-2021-44228"]
    assert log4j.aliases == ["GHSA-jfh8-c2jp-5v3q"]
    assert log4j.cvss_score is None and log4j.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert log4j.severity is Severity.CRITICAL
    assert log4j.data["osv"]["matched_packages"][0]["version"] == "2.14.1"
    assert log4j.data["osv"]["affected"][0]["ranges"][0]["events"] == [
        {"introduced": "2.13.0"},
        {"fixed": "2.15.0"},
    ]

    # Incremental: known OSV ids not modified since the last sync are not re-fetched.
    feeds.calls.clear()
    src.known_osv_ids = {"GHSA-jfh8-c2jp-5v3q", "GHSA-7rjr-3q55-vv33"}
    async with feeds.client() as c:
        res = await src.fetch(c, datetime(2026, 2, 1, tzinfo=UTC))
    fetched = [r.url.path for r in feeds.calls if r.url.path.startswith("/v1/vulns/")]
    assert fetched == ["/v1/vulns/GHSA-jfh8-c2jp-5v3q"]  # modified 2026-10-21 > since


# --------------------------------------------------------------------------- JVN


def test_jvn_params_use_japan_dates() -> None:
    since = datetime(2026, 10, 20, 16, 30, tzinfo=UTC)  # = 2026-10-21 01:30 JST
    p = jvn_params(since, 3, NOW, 1)
    assert p["method"] == "getVulnOverviewList" and p["feed"] == "hnd" and p["maxCountItem"] == 50
    assert (p["datePublishedStartY"], p["datePublishedStartM"], p["datePublishedStartD"]) == (2026, 10, 21)
    assert (p["datePublishedEndY"], p["datePublishedEndM"], p["datePublishedEndD"]) == (2026, 10, 22)
    assert p["rangeDatePublic"] == "n" and p["rangeDateFirstPublished"] == "n"


async def test_jvn_paging_and_mapping(settings: Settings, feeds: Any) -> None:
    src = JvnSource(settings)
    src.now = lambda: NOW
    async with feeds.client() as c:
        res = await src.fetch(c, None)
    assert not res.errors
    assert [r.url.params["startItem"] for r in feeds.requests_to("jvndb.jvn.jp")] == ["1", "3"]
    v = _by_id(res.vulns)
    # one record per CVE of a multi-CVE JVNDB entry; CVE-less entry keyed by JVNDB id
    assert set(v) == {"CVE-2026-20001", "CVE-2026-20002", "JVNDB-2026-012345", "CVE-2024-3400"}
    a = v["CVE-2026-20001"]
    assert a.aliases == ["JVNDB-2026-000101"] and a.sources == ["jvn"]
    assert a.cvss_score == 9.8 and a.severity is Severity.CRITICAL  # v3.0 preferred over v2
    assert a.data["jvn"]["title"] == "Example Web Console における複数の脆弱性"
    assert a.affected[0].cpe == "cpe:2.3:a:example:web_console:*:*:*:*:*:*:*:*"
    assert a.modified == datetime(2026, 10, 21, 5, 15, tzinfo=UTC)
    router = v["JVNDB-2026-012345"]
    assert router.aliases == [] and router.affected[0].version == "1.0.2"


async def test_jvn_error_status_and_dtd_rejected(settings: Settings, feeds: Any) -> None:
    src = JvnSource(settings)
    feeds.set(
        "jvndb.jvn.jp",
        "/myjvn",
        lambda r: httpx.Response(200, content=(FIXTURES / "jvn/error.xml").read_bytes()),
    )
    async with feeds.client() as c:
        res = await src.fetch(c, None)
    assert res.vulns == [] and res.errors == ["jvn: API error 1001: Invalid parameter: maxCountItem"]

    evil = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "y">]><r>&x;</r>'
    feeds.set("jvndb.jvn.jp", "/myjvn", lambda r: httpx.Response(200, content=evil))
    async with feeds.client() as c:
        res = await src.fetch(c, None)
    assert res.vulns == [] and "DTD" in res.errors[0]


# --------------------------------------------------------------------------- RSS


def test_rss_parse_rdf_rss2_atom() -> None:
    items, err = parse_feed(
        (FIXTURES / "rss/jpcert.rdf").read_bytes(), "https://www.jpcert.or.jp/rss/jpcert.rdf"
    )
    assert err is None and len(items) == 2
    assert items[0].source == "rss:www.jpcert.or.jp"
    assert items[0].vuln_ids == ["CVE-2026-10001"]
    assert items[1].vuln_ids == ["CVE-2024-3400", "CVE-2024-6387"]  # lower-case id normalised
    assert items[1].summary is not None and "<p>" not in items[1].summary
    assert items[0].published == datetime(2026, 10, 21, 6, 30, tzinfo=UTC)

    items, err = parse_feed(
        (FIXTURES / "rss/cisa.xml").read_bytes(), "https://www.cisa.gov/cybersecurity-advisories/all.xml"
    )
    assert err is None and items[0].vuln_ids == ["CVE-2026-10001"]
    assert items[0].published == datetime(2026, 10, 20, 16, 0, tzinfo=UTC)

    items, err = parse_feed(
        (FIXTURES / "rss/thehackernews.atom").read_bytes(), "https://feeds.feedburner.com/TheHackersNews"
    )
    assert err is None and items[0].url == "https://thehackernews.com/2026/10/ai-agents-edge-devices.html"
    assert items[0].vuln_ids == ["CVE-2024-3400"] and "AI Security" in items[0].tags


async def test_rss_failing_feed_isolated(settings: Settings, feeds: Any) -> None:
    async with feeds.client() as c:
        res = await RssSource(settings).fetch(c, None)
    sources = {i.source for i in res.items}
    assert sources == {"rss:www.jpcert.or.jp", "rss:www.cisa.gov", "rss:feeds.feedburner.com"}
    assert len(res.errors) == 2  # IPA 404 + BleepingComputer non-feed
    assert any("www.ipa.go.jp" in e for e in res.errors)
    assert any("www.bleepingcomputer.com" in e for e in res.errors)
