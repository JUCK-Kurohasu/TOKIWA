"""Client fingerprinting: *what* is sending the requests.

Two outputs:

1. ``client_fingerprint`` — the second half of the actor-session key (``source_ip`` + fingerprint). It hashes the
   User-Agent and the set of *stable* header names. Request-shape dependent headers (content-type, origin, referer,
   cookie, sec-fetch-*, authorization, custom ``x-*`` ...) are deliberately excluded so that one client does not
   split into several sessions for GET vs POST, and — importantly — so that an agent that starts sending an
   AI-canary header (``X-Debug-Auth: <token>``) mid-session stays in the *same* session.
2. ``FingerprintInfo`` — a classification of the client (browser / HTTP library / headless browser / declared AI
   agent / AI crawler / scanner ...) plus header anomalies (e.g. a browser UA with a library's header set).

UA token lists are point-in-time knowledge (2026-10) and are hypotheses about the ecosystem, not ground truth:
UAs are trivially spoofed. They are therefore used as *weak* evidence in scoring. TODO(verify): review the AI
UA list periodically against vendors' published crawler/agent documentation.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache

from tokiwa.util import short_hash


class ClientFamily(StrEnum):
    BROWSER = "browser"
    HEADLESS_BROWSER = "headless_browser"
    HTTP_LIBRARY = "http_library"
    CLI_TOOL = "cli_tool"
    AI_AGENT = "ai_agent"  # user-triggered AI fetchers, agent frameworks, LLM SDK clients
    AI_CRAWLER = "ai_crawler"  # AI training / AI search crawlers
    SCANNER = "scanner"
    BOT = "bot"  # classic search/social crawlers
    EMPTY = "empty"
    UNKNOWN = "unknown"


# Families that indicate programmatic (non-human-browser) clients.
AUTOMATION_FAMILIES = frozenset(
    {ClientFamily.HTTP_LIBRARY, ClientFamily.CLI_TOOL, ClientFamily.HEADLESS_BROWSER, ClientFamily.EMPTY}
)

# Header names that are stable for a given client regardless of request type. Only these (plus the UA value)
# go into the fingerprint hash.
STABLE_FINGERPRINT_HEADERS = frozenset(
    {
        "accept",
        "accept-language",
        "accept-encoding",
        "connection",
        "dnt",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-gpc",
    }
)

# Default header sets of common HTTP libraries (names only). A browser UA with one of these sets is a spoof.
_LIBRARY_HEADER_SETS = (
    frozenset({"user-agent"}),
    frozenset({"user-agent", "accept"}),
    frozenset({"user-agent", "accept-encoding"}),
    frozenset({"user-agent", "accept", "accept-encoding"}),
    frozenset({"user-agent", "accept", "accept-encoding", "connection"}),
    frozenset({"user-agent", "accept-encoding", "connection"}),
)

# Headers that indicate an LLM SDK / agent protocol client. ``x-stainless-*`` are sent by the Stainless-generated
# OpenAI / Anthropic SDKs; ``mcp-session-id`` / ``mcp-protocol-version`` by MCP Streamable-HTTP clients.
_LLM_SDK_HEADER_PREFIXES = ("x-stainless-",)
_LLM_SDK_HEADERS = frozenset(
    {"mcp-session-id", "mcp-protocol-version", "anthropic-version", "openai-organization", "openai-project"}
)

# (pattern, family, tool) — first match wins, so order matters (specific before generic).
_UA_RULES: tuple[tuple[re.Pattern[str], ClientFamily, str], ...] = tuple(
    (re.compile(p, re.I), fam, tool)
    for p, fam, tool in (
        # --- self-declared, user-triggered AI agents / assistants and agent frameworks
        (r"ChatGPT-User", ClientFamily.AI_AGENT, "chatgpt-user"),
        (r"Claude-User", ClientFamily.AI_AGENT, "claude-user"),
        (r"Perplexity-User", ClientFamily.AI_AGENT, "perplexity-user"),
        (r"MistralAI-User", ClientFamily.AI_AGENT, "mistralai-user"),
        (r"\bOpenAI/(?:Python|JS|Node)\b", ClientFamily.AI_AGENT, "openai-sdk"),
        (r"\bAnthropic/(?:Python|JS|TypeScript)\b", ClientFamily.AI_AGENT, "anthropic-sdk"),
        (r"lang-?chain", ClientFamily.AI_AGENT, "langchain"),
        (r"llama[-_ ]?index", ClientFamily.AI_AGENT, "llamaindex"),
        (r"\bautogen\b", ClientFamily.AI_AGENT, "autogen"),
        (r"\bcrewai\b", ClientFamily.AI_AGENT, "crewai"),
        (r"browser[-_ ]use", ClientFamily.AI_AGENT, "browser-use"),
        (r"smolagents", ClientFamily.AI_AGENT, "smolagents"),
        (r"\bmcp[-_ ]?(?:client|remote|inspector)\b", ClientFamily.AI_AGENT, "mcp-client"),
        (r"\b(?:ai|llm)[-_ ]?agent\b", ClientFamily.AI_AGENT, "ai-agent"),
        # --- AI crawlers (training / AI search)
        (r"GPTBot", ClientFamily.AI_CRAWLER, "gptbot"),
        (r"OAI-SearchBot", ClientFamily.AI_CRAWLER, "oai-searchbot"),
        (r"ClaudeBot|Claude-SearchBot|Claude-Web|anthropic-ai", ClientFamily.AI_CRAWLER, "claudebot"),
        (r"PerplexityBot", ClientFamily.AI_CRAWLER, "perplexitybot"),
        (r"\bCCBot\b", ClientFamily.AI_CRAWLER, "ccbot"),
        (r"Bytespider", ClientFamily.AI_CRAWLER, "bytespider"),
        (r"meta-externalagent", ClientFamily.AI_CRAWLER, "meta-externalagent"),
        (r"cohere-ai", ClientFamily.AI_CRAWLER, "cohere-ai"),
        (r"\bYouBot\b", ClientFamily.AI_CRAWLER, "youbot"),
        # --- offensive scanners
        (r"sqlmap", ClientFamily.SCANNER, "sqlmap"),
        (r"nikto", ClientFamily.SCANNER, "nikto"),
        (r"nuclei", ClientFamily.SCANNER, "nuclei"),
        (r"Fuzz Faster U Fool|\bffuf\b", ClientFamily.SCANNER, "ffuf"),
        (r"gobuster", ClientFamily.SCANNER, "gobuster"),
        (r"feroxbuster", ClientFamily.SCANNER, "feroxbuster"),
        (r"dirbuster|\bdirb\b", ClientFamily.SCANNER, "dirbuster"),
        (r"wfuzz", ClientFamily.SCANNER, "wfuzz"),
        (r"wpscan", ClientFamily.SCANNER, "wpscan"),
        (r"masscan", ClientFamily.SCANNER, "masscan"),
        (r"zgrab", ClientFamily.SCANNER, "zgrab"),
        (r"Nmap Scripting Engine|\bnmap\b", ClientFamily.SCANNER, "nmap"),
        (r"acunetix", ClientFamily.SCANNER, "acunetix"),
        (r"netsparker|invicti", ClientFamily.SCANNER, "invicti"),
        (r"OWASP[ _-]?ZAP|\bZAP/", ClientFamily.SCANNER, "zap"),
        (r"arachni", ClientFamily.SCANNER, "arachni"),
        (r"\bw3af\b", ClientFamily.SCANNER, "w3af"),
        (r"openvas", ClientFamily.SCANNER, "openvas"),
        (r"nessus", ClientFamily.SCANNER, "nessus"),
        (r"whatweb", ClientFamily.SCANNER, "whatweb"),
        # --- headless / automated browsers
        (r"HeadlessChrome", ClientFamily.HEADLESS_BROWSER, "headless-chrome"),
        (r"PhantomJS", ClientFamily.HEADLESS_BROWSER, "phantomjs"),
        (r"Playwright", ClientFamily.HEADLESS_BROWSER, "playwright"),
        (r"Puppeteer", ClientFamily.HEADLESS_BROWSER, "puppeteer"),
        (r"Selenium|webdriver", ClientFamily.HEADLESS_BROWSER, "selenium"),
        # --- classic bots
        (
            r"Googlebot|bingbot|Slurp|DuckDuckBot|Baiduspider|YandexBot|facebookexternalhit|Twitterbot|AhrefsBot|SemrushBot",
            ClientFamily.BOT,
            "search-bot",
        ),
        # --- CLI tools
        (r"^curl/", ClientFamily.CLI_TOOL, "curl"),
        (r"^Wget/", ClientFamily.CLI_TOOL, "wget"),
        (r"HTTPie/", ClientFamily.CLI_TOOL, "httpie"),
        (r"PowerShell/", ClientFamily.CLI_TOOL, "powershell"),
        # --- HTTP libraries
        (r"python-httpx", ClientFamily.HTTP_LIBRARY, "python-httpx"),
        (r"python-requests", ClientFamily.HTTP_LIBRARY, "python-requests"),
        (r"aiohttp", ClientFamily.HTTP_LIBRARY, "aiohttp"),
        (r"Python-urllib", ClientFamily.HTTP_LIBRARY, "python-urllib"),
        (r"Go-http-client", ClientFamily.HTTP_LIBRARY, "go-http-client"),
        (r"node-fetch", ClientFamily.HTTP_LIBRARY, "node-fetch"),
        (r"\bundici\b", ClientFamily.HTTP_LIBRARY, "undici"),
        (r"\baxios\b", ClientFamily.HTTP_LIBRARY, "axios"),
        (r"\bgot\b \(https://github.com/sindresorhus/got\)", ClientFamily.HTTP_LIBRARY, "got"),
        (r"okhttp", ClientFamily.HTTP_LIBRARY, "okhttp"),
        (r"Apache-HttpClient", ClientFamily.HTTP_LIBRARY, "apache-httpclient"),
        (r"^Java/", ClientFamily.HTTP_LIBRARY, "java"),
        (r"libwww-perl", ClientFamily.HTTP_LIBRARY, "libwww-perl"),
        (r"^Ruby\b|Faraday", ClientFamily.HTTP_LIBRARY, "ruby"),
        (r"^Dart/", ClientFamily.HTTP_LIBRARY, "dart"),
        (r"reqwest", ClientFamily.HTTP_LIBRARY, "reqwest"),
        (r"Scrapy", ClientFamily.HTTP_LIBRARY, "scrapy"),
        (r"\bcolly\b", ClientFamily.HTTP_LIBRARY, "colly"),
        (r"^Deno/|^Bun/|^node$|^Node\.js", ClientFamily.HTTP_LIBRARY, "js-runtime"),
    )
)

_BROWSER_RE = re.compile(
    r"^Mozilla/5\.0 \(.+\) (?:AppleWebKit/[\d.]+|Gecko/\d+).*(?:Chrome|Firefox|Safari|Edg)/\d+"
)
_MOZILLA_PREFIX_RE = re.compile(r"^Mozilla/\d")
_CHROMIUM_RE = re.compile(r"(?:Chrome|Chromium|Edg)/(\d+)")


@dataclass(frozen=True, slots=True)
class FingerprintInfo:
    fingerprint: str
    family: ClientFamily
    tool: str | None
    ai_declared: bool
    anomalies: tuple[str, ...]
    header_names: tuple[str, ...]  # stable subset used in the hash
    llm_sdk_headers: tuple[str, ...]

    @property
    def is_automation(self) -> bool:
        return self.family in AUTOMATION_FAMILIES or "nonstandard_mozilla_ua" in self.anomalies

    @property
    def is_browser(self) -> bool:
        return self.family == ClientFamily.BROWSER


def _lower_names(headers: Mapping[str, str] | None, order: Iterable[str] | None = None) -> set[str]:
    names = {k.lower() for k in (headers or {})}
    names.update(k.lower() for k in (order or ()))
    names.discard("host")
    return names


def client_fingerprint(user_agent: str | None, headers: Mapping[str, str] | None) -> str:
    """16-hex hash of UA + stable header names. Same client => same value across GET/POST/canary headers."""
    names = sorted(_lower_names(headers) & STABLE_FINGERPRINT_HEADERS)
    return short_hash(f"{user_agent or ''}|{','.join(names) or '-'}")


@lru_cache(maxsize=4096)
def _classify_ua_cached(ua: str) -> tuple[ClientFamily, str | None]:
    for pattern, family, tool in _UA_RULES:
        if pattern.search(ua):
            return family, tool
    if _BROWSER_RE.search(ua):
        return ClientFamily.BROWSER, None
    return ClientFamily.UNKNOWN, None


def classify_user_agent(user_agent: str | None) -> tuple[ClientFamily, str | None]:
    ua = (user_agent or "").strip()
    if not ua:
        return ClientFamily.EMPTY, None
    return _classify_ua_cached(ua[:512])


def llm_sdk_headers(headers: Mapping[str, str] | None) -> tuple[str, ...]:
    found = sorted(
        {
            k.lower()
            for k in (headers or {})
            if k.lower() in _LLM_SDK_HEADERS or k.lower().startswith(_LLM_SDK_HEADER_PREFIXES)
        }
    )
    return tuple(found[:8])


def header_anomalies(
    user_agent: str | None,
    family: ClientFamily,
    headers: Mapping[str, str] | None,
    *,
    scheme: str | None = None,
    header_order: Iterable[str] | None = None,
) -> tuple[str, ...]:
    """Header-level inconsistencies. Conservative: only flags what is reliable for the given capture.

    Absence checks need a comprehensive header capture (Gate). nginx-style logs carry only the UA, so with fewer
    than 3 header names we do not judge absence. Client hints / Fetch Metadata are only sent by browsers to
    potentially trustworthy origins (HTTPS / localhost), so those checks only run for ``https``.
    """
    ua = (user_agent or "").strip()
    out: list[str] = []
    if not ua:
        out.append("empty_user_agent")
    elif _MOZILLA_PREFIX_RE.match(ua) and family == ClientFamily.UNKNOWN:
        # e.g. "Mozilla/5.0 (spa-api-recon)": a Mozilla prefix without a real browser engine token.
        out.append("nonstandard_mozilla_ua")
    names = _lower_names(headers, header_order)
    comprehensive = len(names) >= 3
    if family == ClientFamily.BROWSER:
        if names and frozenset(names) in _LIBRARY_HEADER_SETS:
            out.append("library_header_set_with_browser_ua")
        if comprehensive and "accept-language" not in names:
            out.append("browser_ua_without_accept_language")
        if comprehensive and (scheme or "").lower() == "https":
            m = _CHROMIUM_RE.search(ua)
            if m and int(m.group(1)) >= 90 and not any(n.startswith("sec-ch-ua") for n in names):
                out.append("chromium_ua_without_client_hints")
            if not any(n.startswith("sec-fetch-") for n in names):
                out.append("browser_ua_without_fetch_metadata")
    elif comprehensive and "accept-language" not in names and family != ClientFamily.EMPTY:
        out.append("no_accept_language")
    return tuple(out)


BROWSER_MISMATCH_ANOMALIES = frozenset(
    {
        "library_header_set_with_browser_ua",
        "browser_ua_without_accept_language",
        "chromium_ua_without_client_hints",
        "browser_ua_without_fetch_metadata",
    }
)


def fingerprint_info(
    user_agent: str | None,
    headers: Mapping[str, str] | None,
    *,
    scheme: str | None = None,
    header_order: Iterable[str] | None = None,
) -> FingerprintInfo:
    family, tool = classify_user_agent(user_agent)
    sdk = llm_sdk_headers(headers)
    anomalies = header_anomalies(user_agent, family, headers, scheme=scheme, header_order=header_order)
    stable = tuple(sorted(_lower_names(headers) & STABLE_FINGERPRINT_HEADERS))
    return FingerprintInfo(
        fingerprint=client_fingerprint(user_agent, headers),
        family=family,
        tool=tool,
        ai_declared=family in (ClientFamily.AI_AGENT, ClientFamily.AI_CRAWLER) or bool(sdk),
        anomalies=anomalies,
        header_names=stable,
        llm_sdk_headers=sdk,
    )


def actor_key(
    session_id: str | None, source_ip: str | None, user_agent: str | None, headers: Mapping[str, str] | None
) -> str:
    """Stable per-actor key for detector state: the session id when the sessionizer ran, else ip|fingerprint."""
    if session_id:
        return session_id
    return f"{source_ip or '-'}|{client_fingerprint(user_agent, headers)}"
