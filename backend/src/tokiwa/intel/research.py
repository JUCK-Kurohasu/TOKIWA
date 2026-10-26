"""Periodic LLM web research: 0-day / exploitation / AI-attack-campaign watch ahead of structured feeds.

Each run asks the deep-tier model (via the gateway, ``web_search=True``) to research a topic, restricted to an
allow-list of trusted domains (NVD, CISA, JPCERT/CC, IPA, vendor PSIRTs, major security media). The output is the
fixed :class:`ResearchOutput` schema and is stored in ``research_reports``.

Post-processing (everything the model returns is derived from untrusted web pages):

- CVE ids are syntax-checked (``CVE-YYYY-NNNN+``); malformed ones are dropped;
- ``source_urls`` are kept only when they are http(s) URLs on an allow-listed domain;
- CVEs missing from ``vulns`` are registered as minimal records with ``sources=["research"]`` (structured feeds
  overwrite/merge them later); existing vulns are never modified here;
- highly relevant findings become advisory candidates: CVEs that already match an asset go through the normal
  advisor (dedup applies), findings naming products from the asset inventory become research advisories.

Scheduling: ``@periodic("intel.research")`` every ``intel.research_interval_hours`` when ``intel.research_enabled``
and a real LLM provider is configured (the mock provider cannot browse). ``POST /intel/research/run`` runs on
demand with any provider.

The allow-list can be overridden at runtime with ``settings_kv["intel.research"] = {"allowed_domains": [...]}``.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from tokiwa.config import get_settings
from tokiwa.db.models.intel import AssetRow, ResearchReportRow, VulnMatchRow, VulnRow
from tokiwa.db.session import session_scope
from tokiwa.intel import advisor
from tokiwa.intel.matcher import software_terms, text_mentions
from tokiwa.intel.prompts import RESEARCH_PROMPT, build_research_user, research_system
from tokiwa.llm.base import LLMPurpose, LLMTier, StructuredRequest
from tokiwa.llm.gateway import get_gateway
from tokiwa.llm.mock import register_mock_responder
from tokiwa.runtime import periodic
from tokiwa.schemas.intel import MatchStatus, ResearchFinding, ResearchOutput, ResearchReport
from tokiwa.settings_store import get_setting
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

SETTINGS_KEY = "intel.research"
LOOKBACK_DAYS = 14
WEB_SEARCH_MAX_USES = 8
MAX_INVENTORY_ITEMS = 100
MAX_VULN_ADVISORIES_PER_RUN = 3
MAX_RESEARCH_ADVISORIES_PER_RUN = 5
MAX_TOPIC_CHARS = 500

# Trusted sources for server-side web search. TODO(verify): the provider's handling of subdomains / max list size.
DEFAULT_TRUSTED_DOMAINS: tuple[str, ...] = (
    # vulnerability databases / government CERTs
    "nvd.nist.gov",
    "cve.org",
    "cisa.gov",
    "jpcert.or.jp",
    "jvn.jp",
    "ipa.go.jp",
    "kb.cert.org",
    "first.org",
    "ncsc.gov.uk",
    # vendor PSIRTs / official advisories
    "msrc.microsoft.com",
    "support.apple.com",
    "chromereleases.googleblog.com",
    "security.paloaltonetworks.com",
    "fortiguard.com",
    "sec.cloudapps.cisco.com",
    "access.redhat.com",
    "ubuntu.com",
    "security-tracker.debian.org",
    "github.com",
    "apache.org",
    "openssl-library.org",
    # threat research
    "googleprojectzero.blogspot.com",
    "unit42.paloaltonetworks.com",
    "cloud.google.com",
    "atlas.mitre.org",
    "genai.owasp.org",
    "anthropic.com",
    # major security media
    "bleepingcomputer.com",
    "thehackernews.com",
    "securityweek.com",
    "therecord.media",
    "darkreading.com",
)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class ResearchError(RuntimeError):
    """The LLM call did not produce a usable ResearchOutput (refusal, budget, error, invalid output)."""


@register_mock_responder(ResearchOutput)
def _mock_research(system: str, user: str) -> dict[str, Any]:
    return ResearchOutput(
        findings=[],
        overall_assessment="[mock] LLM is not configured (set ANTHROPIC_API_KEY); web research was not performed.",
    ).model_dump(mode="json")


def llm_available() -> bool:
    """True when a real provider is configured. The mock provider cannot browse the web."""
    gw = get_gateway()
    return gw.provider.name != "mock" and gw.provider.available()


async def trusted_domains() -> list[str]:
    try:
        override = (await get_setting(SETTINGS_KEY)).get("allowed_domains")
    except Exception:
        log.exception("failed to read %s from settings_kv", SETTINGS_KEY)
        override = None
    if isinstance(override, list):
        domains = [str(d).strip().lower().rstrip(".") for d in override]
        valid = [d for d in dict.fromkeys(domains) if _DOMAIN_RE.match(d)]
        if valid:
            return valid
    return list(DEFAULT_TRUSTED_DOMAINS)


async def _inventory() -> tuple[list[dict[str, Any]], list[tuple[str, set[str]]]]:
    """(prompt inventory, [(asset_id, product terms)])."""
    async with session_scope() as session:
        rows = (await session.execute(select(AssetRow.id, AssetRow.software))).all()
    items: dict[tuple[str, str, str], dict[str, Any]] = {}
    terms: list[tuple[str, set[str]]] = []
    for asset_id, software in rows:
        sw_list = [s for s in (software or []) if isinstance(s, dict)]
        terms.append((asset_id, software_terms(sw_list)))
        for sw in sw_list:
            product = str(sw.get("product") or "").strip()
            if not product:
                continue
            key = (str(sw.get("vendor") or "").lower(), product.lower(), str(sw.get("version") or ""))
            items.setdefault(key, {k: sw.get(k) for k in ("vendor", "product", "version") if sw.get(k)})
    return list(items.values())[:MAX_INVENTORY_ITEMS], terms


def clean_output(out: ResearchOutput, domains: list[str]) -> ResearchOutput:
    findings: list[ResearchFinding] = []
    for f in out.findings:
        cves = [c.strip().upper() for c in f.cve_ids if isinstance(c, str)]
        cves = [c for c in dict.fromkeys(cves) if _CVE_RE.match(c)]
        urls = [u.strip() for u in f.source_urls if isinstance(u, str)]
        urls = [
            u
            for u in dict.fromkeys(urls)
            if advisor.domain_allowed(u, domains) and u.startswith(("https://", "http://"))
        ]
        findings.append(f.model_copy(update={"cve_ids": cves, "source_urls": urls[:10]}))
    return out.model_copy(update={"findings": findings})


def _clean_citations(citations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in citations[:100]:
        if not isinstance(c, dict):
            continue
        out.append({k: v for k, v in c.items() if isinstance(v, str | int | float | bool) or v is None})
    return out


async def _register_unknown_cves(output: ResearchOutput, report_id: str) -> list[str]:
    by_cve: dict[str, ResearchFinding] = {}
    for f in output.findings:
        for cve in f.cve_ids:
            by_cve.setdefault(cve, f)
    if not by_cve:
        return []
    created: list[str] = []
    async with session_scope() as session:
        existing = set(
            (await session.execute(select(VulnRow.id).where(VulnRow.id.in_(list(by_cve))))).scalars()
        )
        for cve, f in by_cve.items():
            if cve in existing:
                continue
            session.add(
                VulnRow(
                    id=cve,
                    aliases=[],
                    sources=["research"],
                    title=f.title[:500],
                    description=f.summary[:4000],
                    references=f.source_urls[:10],
                    data={
                        "research": {
                            "report_id": report_id,
                            "exploitation": f.exploitation[:100],
                            "affected_products": f.affected_products[:20],
                            "first_seen": utcnow().isoformat(),
                        }
                    },
                    updated_at=utcnow(),
                )
            )
            created.append(cve)
    return created


async def _advisory_candidates(
    output: ResearchOutput, report_id: str, terms: list[tuple[str, set[str]]]
) -> list[str]:
    all_cves = list(dict.fromkeys(c for f in output.findings for c in f.cve_ids))
    matched_cves: set[str] = set()
    if all_cves:
        async with session_scope() as session:
            matched_cves = set(
                (
                    await session.execute(
                        select(VulnMatchRow.vuln_id).where(
                            VulnMatchRow.vuln_id.in_(all_cves), VulnMatchRow.status == MatchStatus.OPEN.value
                        )
                    )
                ).scalars()
            )
    advisory_ids: list[str] = []
    vuln_budget, research_budget = MAX_VULN_ADVISORIES_PER_RUN, MAX_RESEARCH_ADVISORIES_PER_RUN
    for f in output.findings:
        hit = [c for c in f.cve_ids if c in matched_cves]
        if hit:
            for cve in hit:
                if vuln_budget <= 0:
                    break
                vuln_budget -= 1
                try:
                    adv, created = await advisor.generate_advisory(cve)
                except Exception:
                    log.exception("advisory for research CVE %s failed", cve)
                    continue
                if created:
                    advisory_ids.append(adv.id)
            continue
        if research_budget <= 0:
            continue
        assets = [aid for aid, t in terms if t and any(text_mentions(p, t) for p in f.affected_products)]
        if not assets:
            continue
        research_budget -= 1
        adv2 = await advisor.create_research_advisory(
            title=f.title,
            summary=f.summary,
            exploitation=f.exploitation,
            relevance=f.relevance_to_assets,
            actions=f.recommended_actions,
            references=f.source_urls,
            cve_ids=f.cve_ids,
            asset_ids=sorted(set(assets)),
            report_id=report_id,
        )
        if adv2 is not None:
            advisory_ids.append(adv2.id)
    return advisory_ids


async def run_research(topic: str | None = None) -> ResearchReport:
    """Research one topic (or all configured topics in a single call when ``topic`` is None)."""
    settings = get_settings()
    topics = (
        [topic.strip()[:MAX_TOPIC_CHARS]] if topic and topic.strip() else list(settings.intel.research_topics)
    )
    if not topics:
        raise ResearchError("no research topics configured")
    label = topics[0] if len(topics) == 1 else " / ".join(topics)
    domains = await trusted_domains()
    inventory, terms = await _inventory()
    lang = settings.llm.output_language
    req = StructuredRequest(
        purpose=LLMPurpose.RESEARCH,
        tier=LLMTier.DEEP,
        system=research_system(lang),
        user=build_research_user(
            topics=topics,
            inventory=inventory,
            today=datetime.now(UTC).date().isoformat(),
            lookback_days=LOOKBACK_DAYS,
            trusted_domains=domains,
        ),
        prompt_version=RESEARCH_PROMPT.ref,
        related={"topic": label[:200]},
        web_search=True,
        web_search_max_uses=WEB_SEARCH_MAX_USES,
        allowed_domains=domains,
    )
    result = await get_gateway().structured(req, ResearchOutput)
    if not result.ok or result.output is None:
        raise ResearchError(f"research failed ({result.status}): {result.error or 'no output'}")
    output = clean_output(result.output, domains)
    report_id = new_id()
    async with session_scope() as session:
        row = ResearchReportRow(
            id=report_id,
            created_at=utcnow(),
            topic=label[:4000],
            output=output.model_dump(mode="json"),
            citations=_clean_citations(result.citations),
            llm_call_id=result.call_id,
        )
        session.add(row)
        await session.flush()
        report = ResearchReport.model_validate(row)
    try:
        registered = await _register_unknown_cves(output, report_id)
        if registered:
            log.info("research registered %d new CVE(s): %s", len(registered), ", ".join(registered))
        await _advisory_candidates(output, report_id, terms)
    except Exception:
        log.exception("research post-processing failed for report %s", report_id)
    return report


async def run_scheduled_research() -> list[ResearchReport]:
    if not llm_available():
        log.info("intel.research skipped: no real LLM provider configured")
        return []
    reports: list[ResearchReport] = []
    for topic in get_settings().intel.research_topics:
        try:
            reports.append(await run_research(topic))
        except ResearchError as exc:
            log.warning("intel.research topic %r: %s", topic[:80], exc)
    return reports


@periodic(
    "intel.research",
    every_seconds=lambda s: max(1, s.intel.research_interval_hours) * 3600,
    initial_delay=600,
    enabled=lambda s: s.intel.enabled and s.intel.research_enabled,
)
async def research_job() -> None:
    await run_scheduled_research()
