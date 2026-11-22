"""One UA catalog for AI attribution and ``web.scanner_ua`` (audit #124), plus the MCP fetch (#115) and ARTEX (#85) UAs.

The sample strings are test vectors that exercise each pattern; they are not a claim about a tool's current default
UA (UAs change between releases and are configurable).
"""

from __future__ import annotations

import pytest

from tokiwa.aidetect.fingerprints import ClientFamily, classify_user_agent, fingerprint_info
from tokiwa.aidetect.scoring import signals
from tokiwa.aidetect.sessions import SessionTracker
from tokiwa.aidetect.ua_catalog import UA_RULES, scanner_alert_rules
from tokiwa.detect.detectors.web_recon import match_scanner_ua

from . import synth

SCANNER_SAMPLES = {
    "sqlmap": "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "commix": "commix/3.9",
    "havij": "Havij",
    "xsstrike": "XSStrike/3.1.5",
    "hydra": "Mozilla/4.0 (Hydra)",
    "nikto": "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)",
    "nuclei": synth.NUCLEI_UA,
    "ffuf": "Fuzz Faster U Fool v2.1.0-dev",
    "gobuster": "gobuster/3.6",
    "feroxbuster": "feroxbuster/2.10.1",
    "dirbuster": "DirBuster-1.0-RC1",
    "dirsearch": "dirsearch/0.4.3",
    "wfuzz": "Wfuzz/3.1.0",
    "wpscan": "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)",
    "joomscan": "OWASP JoomScan (joomscan)",
    "masscan": "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
    "zgrab": "Mozilla/5.0 zgrab/0.x",
    "nmap": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "acunetix": "Acunetix-WVS",
    "invicti": "Netsparker",
    "zap": "OWASP ZAP/2.14",
    "arachni": "Arachni/v1.6.1",
    "w3af": "w3af.org",
    "skipfish": "skipfish/2.10b",
    "openvas": "OpenVAS-VT",
    "nessus": "Nessus SOAP",
    "qualys": "QualysGuard",
    "whatweb": "WhatWeb/0.5.5",
    "appscan": "AppScan",
    "webinspect": "WebInspect",
    "paros": "Paros/3.2.13",
    "jaeles": "Jaeles",
    "fimap": "fimap",
    "morfeus": "Morfeus Scanner",
    "zmeu": "ZmEu",
    "jorgee": "Mozilla/5.0 Jorgee",
    "censys": "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
}

MCP_AUTONOMOUS = "ModelContextProtocol/1.0 (Autonomous; +https://github.com/modelcontextprotocol/servers)"
MCP_USER = "ModelContextProtocol/1.0 (User-Specified; +https://github.com/modelcontextprotocol/servers)"
DECLARED = {
    MCP_AUTONOMOUS: "mcp-fetch-autonomous",
    MCP_USER: "mcp-fetch-user-specified",
    "ModelContextProtocol/2.0": "mcp-fetch",
    "artex-enrich/1.0": "artex-enrich",
    "Mozilla/5.0 (spa-api-recon spider)": "artex-api-recon",
    "Mozilla/5.0 (spa-api-recon)": "artex-api-recon",
}


def test_both_consumers_register_the_same_tools() -> None:
    scanners = {r.tool for r in UA_RULES if r.family == ClientFamily.SCANNER}
    alerting = {r.tool for r in scanner_alert_rules()}
    assert scanners == alerting == set(SCANNER_SAMPLES)  # a new scanner rule needs a sample here
    assert len({r.tool for r in UA_RULES}) == len(UA_RULES)  # tool ids are unique


@pytest.mark.parametrize("tool", sorted(SCANNER_SAMPLES))
def test_scanner_sample_is_seen_by_both(tool: str) -> None:
    ua = SCANNER_SAMPLES[tool]
    rule = next(r for r in UA_RULES if r.tool == tool)
    assert classify_user_agent(ua) == (ClientFamily.SCANNER, tool)
    hit = match_scanner_ua(ua)
    assert hit is not None and hit[0] == rule.alert_tool


def test_alert_names_kept_for_existing_alerts() -> None:
    """web.scanner_ua tags / dedup fingerprints keep their former names where aidetect used another id."""
    assert match_scanner_ua("Netsparker")[0] == "netsparker"  # type: ignore[index]
    assert match_scanner_ua("zaproxy")[0] == "owasp_zap"  # type: ignore[index]
    assert match_scanner_ua("sqlmap/1.8")[0] == "sqlmap"  # type: ignore[index]


@pytest.mark.parametrize("ua", sorted(DECLARED))
def test_declared_ai_tools(ua: str) -> None:
    assert classify_user_agent(ua) == (ClientFamily.AI_AGENT, DECLARED[ua])
    assert match_scanner_ua(ua) is None
    assert fingerprint_info(ua, {}).ai_declared


def test_scripted_mozilla_ua_keeps_its_automation_flag() -> None:
    """Reclassifying spa-api-recon must not drop the anomaly it had as an unknown client; real AI fetchers with a
    browser engine token are not flagged."""
    assert "nonstandard_mozilla_ua" in fingerprint_info("Mozilla/5.0 (spa-api-recon)", {}).anomalies
    chatgpt = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"
    assert classify_user_agent(chatgpt)[0] == ClientFamily.AI_AGENT
    assert fingerprint_info(chatgpt, {}).anomalies == ()


def _fetch_session_score(ua: str) -> float:
    """Six polite GETs (robots first, a few pages) — what a fetch tool / ARTEX enrichment looks like."""
    b = synth._Builder("198.51.100.90", synth.library_headers(ua), seed=1)
    events = []
    for p in ("/robots.txt", "/", "/about", "/login", "/api/v1/products", "/favicon.ico"):
        events.append(b.req(p))
        b.wait(2, 6)
    tr = SessionTracker()
    tr.observe_batch(events)
    s = tr.get(events[0].session_id)
    assert s is not None
    return s.ai_score


def test_declared_strength_is_moderate_and_ordered() -> None:
    """Measured on the fetch session above (2026-11-22): unknown UA 0.20, artex-enrich / user-specified MCP 0.37,
    spa-api-recon 0.54 (also an automation client), autonomous MCP 0.51. A UA alone never reaches the 0.7 verdict."""
    unknown = _fetch_session_score("someclient/1.0")
    scores = {ua: _fetch_session_score(ua) for ua in DECLARED}
    assert all(unknown < v < 0.7 for v in scores.values()), scores
    assert scores[MCP_AUTONOMOUS] > scores[MCP_USER]
    assert signals({"client_family": "ai_agent", "client_tool": "artex-enrich"})["ai_declared_client"] == 0.6
    assert signals({"client_family": "ai_agent", "client_tool": "chatgpt-user"})["ai_declared_client"] == 1.0
