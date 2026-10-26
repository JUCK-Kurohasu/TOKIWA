"""Web research E2E with a recording mock provider: web_search reaches the provider, output is sanitized/stored."""

from __future__ import annotations

from typing import Any, ClassVar

import pytest
from sqlalchemy import select

from tokiwa.config import Settings
from tokiwa.db.models.intel import AdvisoryRow, ResearchReportRow
from tokiwa.db.session import session_scope
from tokiwa.intel import research
from tokiwa.intel.matcher import run_matching
from tokiwa.intel.research import DEFAULT_TRUSTED_DOMAINS, ResearchError, run_research, run_scheduled_research
from tokiwa.llm import gateway as gw
from tokiwa.llm.base import ProviderResponse
from tokiwa.llm.mock import MockProvider
from tokiwa.llm.prompting import UNTRUSTED_DATA_POLICY
from tokiwa.settings_store import set_setting

from ._helpers import APACHE_AFFECTED, APACHE_SW, add_asset, add_vuln, get_vuln

pytestmark = pytest.mark.usefixtures("db")


class RecordingProvider(MockProvider):
    """MockProvider that records every keyword argument (web_search, allowed_domains ...) and adds citations."""

    def __init__(self, responders: dict[str, Any] | None = None, *, refuse: bool = False) -> None:
        super().__init__(responders)
        self.kwargs: list[dict[str, Any]] = []
        self.refuse = refuse

    async def complete_structured(self, **kwargs: Any) -> ProviderResponse:  # type: ignore[override]
        self.kwargs.append(kwargs)
        if self.refuse:
            return ProviderResponse(model=kwargs["model"], refused=True, stop_reason="refusal")
        resp = await super().complete_structured(**kwargs)
        resp.citations = [
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2099-2000", "title": "NVD", "nested": {}}
        ]
        return resp


class RealishProvider(RecordingProvider):
    name: ClassVar[str] = "fake-real"


def _install(settings: Settings, provider: MockProvider) -> None:
    gw.set_gateway(gw.LLMGateway(provider=provider, settings=settings))


def _finding(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "title": "Finding",
        "summary": "s",
        "cve_ids": [],
        "affected_products": [],
        "exploitation": "unknown",
        "relevance_to_assets": "none",
        "recommended_actions": [],
        "source_urls": [],
    }
    return {**base, **kw}


def _output() -> dict[str, Any]:
    return {
        "overall_assessment": "Two relevant items.",
        "findings": [
            _finding(
                title="Apache HTTP Server traversal exploited",
                cve_ids=["cve-2099-2000", "CVE-2099-2001"],
                exploitation="in-the-wild",
                source_urls=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2099-2000",
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "https://evil.example/fake-advisory",
                    "javascript:alert(1)",
                ],
            ),
            _finding(
                title="New 0-day in Acme Gateway under attack",
                cve_ids=["CVE-2099-3000", "not-a-cve", "CVE-99-1"],
                affected_products=["Acme Gateway 5.x"],
                exploitation="in-the-wild",
                recommended_actions=["Apply the vendor hotfix"],
                source_urls=["https://www.bleepingcomputer.com/news/security/acme-0day/"],
            ),
            _finding(title="Unrelated", affected_products=["Something Else 1.0"]),
        ],
    }


async def test_research_e2e(settings: Settings) -> None:
    provider = RecordingProvider({"ResearchOutput": lambda system, user: _output()})
    _install(settings, provider)
    await add_vuln("CVE-2099-2000", kev=True, description="existing feed text", affected=APACHE_AFFECTED)
    apache_id = await add_asset("web-1", software=[APACHE_SW])
    acme_id = await add_asset(
        "gw-1", software=[{"vendor": "Acme", "product": "Acme Gateway", "version": "5.2"}]
    )
    await run_matching()

    report = await run_research("zero-days this week")

    # web search was requested through the gateway with the trusted allow-list, deep tier
    [call] = [k for k in provider.kwargs if k["schema"].__name__ == "ResearchOutput"]
    assert call["web_search"] is True
    assert call["allowed_domains"] == list(DEFAULT_TRUSTED_DOMAINS)
    assert {"nvd.nist.gov", "cisa.gov", "jpcert.or.jp", "ipa.go.jp"} <= set(call["allowed_domains"])
    assert call["web_search_max_uses"] == research.WEB_SEARCH_MAX_USES
    assert call["model"] == settings.llm.model_deep
    assert UNTRUSTED_DATA_POLICY in call["system"]
    assert '<untrusted_data name="asset_inventory">' in call["user"]
    assert "zero-days this week" in call["user"]

    # stored + sanitized
    assert report.topic == "zero-days this week"
    f1, f2, _ = report.output.findings
    assert f1.cve_ids == ["CVE-2099-2000", "CVE-2099-2001"]
    assert f1.source_urls == [
        "https://nvd.nist.gov/vuln/detail/CVE-2099-2000",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    ]
    assert f2.cve_ids == ["CVE-2099-3000"]
    assert report.citations == [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2099-2000", "title": "NVD"}]
    assert report.llm_call_id
    async with session_scope() as s:
        assert await s.get(ResearchReportRow, report.id) is not None

    # unknown CVEs registered minimally, existing feed records untouched
    existing = await get_vuln("CVE-2099-2000")
    assert (
        existing is not None and existing.description == "existing feed text" and existing.sources == ["nvd"]
    )
    for cve in ("CVE-2099-2001", "CVE-2099-3000"):
        row = await get_vuln(cve)
        assert row is not None and row.sources == ["research"] and row.affected == []
        assert row.data["research"]["report_id"] == report.id
    assert await get_vuln("not-a-cve") is None

    # advisory candidates: matched KEV CVE via the advisor, product-relevant 0-day as research advisory
    async with session_scope() as s:
        advisories = list((await s.execute(select(AdvisoryRow))).scalars())
    by_kind = {a.analysis["_meta"]["kind"]: a for a in advisories}
    assert set(by_kind) == {"vuln", "research"}
    assert by_kind["vuln"].vuln_ids == ["CVE-2099-2000"] and by_kind["vuln"].priority == "P1"
    assert by_kind["vuln"].analysis["affected_assets"] == [apache_id]
    research_adv = by_kind["research"]
    assert research_adv.vuln_ids == ["CVE-2099-3000"] and research_adv.priority == "P2"
    assert research_adv.analysis["affected_assets"] == [acme_id]
    assert research_adv.analysis["title"].startswith("[Research] ")
    assert research_adv.analysis["_meta"]["report_id"] == report.id

    # a second run does not duplicate advisories
    await run_research("zero-days this week")
    async with session_scope() as s:
        assert len(list((await s.execute(select(AdvisoryRow))).scalars())) == 2


async def test_all_topics_in_one_call_and_domain_override(settings: Settings) -> None:
    provider = RecordingProvider()
    _install(settings, provider)
    await set_setting(
        research.SETTINGS_KEY, {"allowed_domains": ["NVD.nist.gov", "bad domain", "jpcert.or.jp."]}
    )
    report = await run_research()
    assert report.topic == " / ".join(settings.intel.research_topics)
    assert report.output.findings == []  # registered mock responder
    assert provider.kwargs[0]["allowed_domains"] == ["nvd.nist.gov", "jpcert.or.jp"]
    for topic in settings.intel.research_topics:
        assert topic in provider.kwargs[0]["user"]


async def test_refusal_raises_and_stores_nothing(settings: Settings) -> None:
    _install(settings, RecordingProvider(refuse=True))
    with pytest.raises(ResearchError, match="refused"):
        await run_research("x")
    async with session_scope() as s:
        assert (await s.execute(select(ResearchReportRow))).first() is None


async def test_scheduled_research_requires_real_provider(settings: Settings) -> None:
    mock = RecordingProvider()
    _install(settings, mock)
    assert research.llm_available() is False
    assert await run_scheduled_research() == []
    assert mock.kwargs == []

    real = RealishProvider()
    _install(settings, real)
    assert research.llm_available() is True
    reports = await run_scheduled_research()
    assert [r.topic for r in reports] == list(settings.intel.research_topics)
    assert all(k["web_search"] is True for k in real.kwargs)


def test_research_job_registered() -> None:
    from tokiwa.runtime import jobs

    job = jobs()["intel.research"]
    s = Settings()
    assert job.interval(s) == s.intel.research_interval_hours * 3600
    assert job.is_enabled(s) is (s.intel.enabled and s.intel.research_enabled)
