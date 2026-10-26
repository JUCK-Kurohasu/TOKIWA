"""Sync job (state, error isolation, incremental since), intel API routes and the ``tokiwa intel`` CLI."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from tokiwa.config import Settings
from tokiwa.intel import sync as intel_sync
from tokiwa.intel.sources._common import parse_dt
from tokiwa.intel.sources.ghsa import GhsaSource
from tokiwa.runtime import jobs

NVD = ("services.nvd.nist.gov", "/rest/json/cves/2.0")


@pytest.mark.usefixtures("db")
async def test_sync_all_sources_state_and_epss_last(feeds: Any) -> None:
    out = await intel_sync.run_sync()
    assert set(out) == {"kev", "epss", "nvd", "osv", "jvn", "ghsa", "rss"}
    for sid in ("kev", "nvd", "ghsa", "jvn", "epss", "osv"):
        assert out[sid]["last_error"] is None, (sid, out[sid]["last_error"])
        assert out[sid]["last_sync"] is not None
    assert out["kev"]["records"] == 4
    assert out["osv"]["records"] == 0  # no assets -> skipped without error
    # RSS: two broken feeds are reported, the other three are stored; its window is not advanced.
    assert out["rss"]["items_created"] == 4
    assert out["rss"]["last_error"] and out["rss"].get("last_sync") is None
    # EPSS ran after the others and scored the CVEs they collected (KEV + NVD + GHSA + JVN).
    epss_cves = set(feeds.requests_to("api.first.org")[0].url.params["cve"].split(","))
    assert {"CVE-2024-3400", "CVE-2026-10001", "CVE-2024-6387", "CVE-2021-45046"} <= epss_cves
    state = await intel_sync.load_state()
    assert state["kev"]["last_sync"] == out["kev"]["last_sync"]


@pytest.mark.usefixtures("db")
async def test_sync_error_isolation_and_incremental_since(
    feeds: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    nvd_ok = feeds.routes[NVD]
    feeds.set(*NVD, lambda r: httpx.Response(500))

    async def boom(self: Any, client: Any, since: Any) -> Any:
        raise RuntimeError("ghsa exploded")

    monkeypatch.setattr(GhsaSource, "fetch", boom)
    out = await intel_sync.run_sync(["kev", "nvd", "ghsa"])
    assert set(out) == {"kev", "nvd", "ghsa"}
    assert out["kev"]["last_error"] is None and out["kev"]["vulns_created"] == 4
    assert "HTTP 500" in out["nvd"]["last_error"] and out["nvd"].get("last_sync") is None
    assert out["ghsa"]["last_error"] == "RuntimeError: ghsa exploded" and out["ghsa"].get("last_sync") is None

    # NVD recovers; the next run then uses the successful run's start time as ``since`` (minus overlap).
    feeds.set(*NVD, nvd_ok)
    first = await intel_sync.run_sync(["nvd"])
    assert first["nvd"]["last_error"] is None
    feeds.calls.clear()
    await intel_sync.run_sync(["nvd"])
    start = parse_dt(feeds.requests_to(NVD[0])[0].url.params["lastModStartDate"])
    expected = parse_dt(first["nvd"]["last_sync"])
    assert start is not None and expected is not None
    assert abs(start - (expected - timedelta(minutes=10))) < timedelta(milliseconds=1)  # NVD format has ms

    with pytest.raises(KeyError):
        await intel_sync.run_sync(["nope"])


def test_periodic_job_registered(settings: Settings) -> None:
    job = jobs()["intel.sync"]
    assert job.interval(settings) == settings.intel.sync_interval_minutes * 60
    assert job.is_enabled(settings)


async def test_api_sync_then_filter_kev(
    client: httpx.AsyncClient, admin_headers: dict[str, str], feeds: Any
) -> None:
    assert (await client.get("/api/v1/intel/vulns")).status_code == 401
    r = await client.post("/api/v1/intel/sync", json={"source": "nope"}, headers=admin_headers)
    assert r.status_code == 404
    r = await client.post("/api/v1/intel/sync", headers=admin_headers)
    assert r.status_code == 200 and r.json()["started"] is True
    assert set(r.json()["sources"]) == {"kev", "epss", "nvd", "osv", "jvn", "ghsa", "rss"}
    await intel_sync.wait_background()

    r = await client.get("/api/v1/intel/vulns", params={"kev": "true"}, headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    ids = [v["id"] for v in body["items"]]
    assert body["total"] == 4 and all(v["kev"] for v in body["items"])
    assert set(ids) == {"CVE-2024-3400", "CVE-2023-4966", "CVE-2021-44228", "CVE-2026-10001"}
    # default order inside KEV: EPSS desc (fixture: 44228 0.944 > 3400 0.9436 > 4966 0.942 > no score)
    assert ids == ["CVE-2021-44228", "CVE-2024-3400", "CVE-2023-4966", "CVE-2026-10001"]

    all_vulns = (await client.get("/api/v1/intel/vulns", params={"limit": 500}, headers=admin_headers)).json()
    assert all_vulns["total"] > 4 and any(not v["kev"] for v in all_vulns["items"])

    # merged record: KEV title, NVD CVSS/description, EPSS score, GHSA/OSV/JVN contributions
    r = await client.get("/api/v1/intel/vulns/cve-2024-3400", headers=admin_headers)
    assert r.status_code == 200
    detail = r.json()
    vuln = detail["vuln"]
    assert vuln["title"] == "Palo Alto Networks PAN-OS Command Injection Vulnerability"
    assert vuln["cvss_score"] == 9.8 and vuln["epss"] == pytest.approx(0.94358)
    assert {"kev", "nvd", "jvn", "epss"} <= set(vuln["sources"]) and "JVNDB-2024-003456" in vuln["aliases"]
    assert detail["matches"] == [] and detail["advisories"] == []
    by_alias = await client.get("/api/v1/intel/vulns/GHSA-jfh8-c2jp-5v3q", headers=admin_headers)
    assert by_alias.status_code == 200 and by_alias.json()["vuln"]["id"] == "CVE-2021-44228"
    assert (await client.get("/api/v1/intel/vulns/CVE-1999-0001", headers=admin_headers)).status_code == 404

    news = (await client.get("/api/v1/intel/news", params={"source": "rss"}, headers=admin_headers)).json()
    assert news["total"] == 4
    news = (await client.get("/api/v1/intel/news", params={"q": "AI Agents"}, headers=admin_headers)).json()
    assert [n["source"] for n in news["items"]] == ["rss:feeds.feedburner.com"]

    sources = {s["id"]: s for s in (await client.get("/api/v1/intel/sources", headers=admin_headers)).json()}
    assert set(sources) == {"kev", "epss", "nvd", "osv", "jvn", "ghsa", "rss"}
    assert sources["kev"]["enabled"] and sources["kev"]["last_sync"] and sources["kev"]["records"] == 4
    assert sources["rss"]["last_error"]
    assert sources["nvd"]["attribution"].startswith("This product uses the NVD API")


def test_cli_sync_status_show(settings: Settings, feeds: Any) -> None:
    from tokiwa.cli import app  # also checks that `intel` is registered as a sub-command

    runner = CliRunner()
    r = runner.invoke(app, ["intel", "sync", "--source", "kev"])
    assert r.exit_code == 0, r.output
    assert "kev" in r.output and "records=4" in r.output
    r = runner.invoke(app, ["intel", "status"])
    assert r.exit_code == 0 and "kev" in r.output
    r = runner.invoke(app, ["intel", "show", "CVE-2023-4966"])
    assert r.exit_code == 0 and "ransomware True" in r.output
    r = runner.invoke(app, ["intel", "show", "CVE-1999-0001"])
    assert r.exit_code == 1
    r = runner.invoke(app, ["intel", "sync", "--source", "nope"])
    assert r.exit_code == 2
