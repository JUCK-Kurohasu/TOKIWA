"""The single User-Agent catalog: client classification (aidetect) and offensive-tool alerts (``web.scanner_ua``).

Why one table: the two consumers used to keep separate hand-written lists that drifted apart — dirsearch, commix,
hydra ... raised ``web.scanner_ua`` but were ``unknown`` to the AI attribution, so its ``scanner_client``
counter-evidence never fired for them (audit #124). Both are now generated from :data:`UA_RULES`:

- :mod:`tokiwa.aidetect.fingerprints` compiles every rule in order (first match wins, so specific before generic);
- :mod:`tokiwa.detect.detectors.web_recon` alerts on every rule with ``alert`` set (exactly the SCANNER family;
  ``tests/aidetect/test_ua_catalog.py`` pins that both see the same tool set).

Patterns are case-insensitive regexes searched anywhere in the UA (no inline flags: the web detector combines them
into one alternation). UA strings are point-in-time knowledge and trivially spoofed — weak evidence, used mainly for
attribution. TODO(verify): review periodically against vendors' published crawler / agent documentation; only add
a tool whose UA is confirmed in a primary source (its README or source code).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from tokiwa.schemas.common import Severity


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


@dataclass(frozen=True, slots=True)
class UaRule:
    tool: str  # aidetect ``client_tool`` (persisted in session features — do not rename casually)
    family: ClientFamily
    pattern: str
    alert: Severity | None = None  # web.scanner_ua severity; set for (and only for) the SCANNER family
    alert_name: str | None = (
        None  # web.scanner_ua tool name (alert tags / dedup fingerprint) when != ``tool``
    )

    @property
    def alert_tool(self) -> str:
        return self.alert_name or self.tool


_A, _C, _S = ClientFamily.AI_AGENT, ClientFamily.AI_CRAWLER, ClientFamily.SCANNER
_H, _M, _L = Severity.HIGH, Severity.MEDIUM, Severity.LOW

UA_RULES: tuple[UaRule, ...] = (
    # --- self-declared, user-triggered AI agents / assistants and agent frameworks
    UaRule("chatgpt-user", _A, r"ChatGPT-User"),
    UaRule("claude-user", _A, r"Claude-User"),
    UaRule("perplexity-user", _A, r"Perplexity-User"),
    UaRule("mistralai-user", _A, r"MistralAI-User"),
    UaRule("openai-sdk", _A, r"\bOpenAI/(?:Python|JS|Node)\b"),
    UaRule("anthropic-sdk", _A, r"\bAnthropic/(?:Python|JS|TypeScript)\b"),
    UaRule("langchain", _A, r"lang-?chain"),
    UaRule("llamaindex", _A, r"llama[-_ ]?index"),
    UaRule("autogen", _A, r"\bautogen\b"),
    UaRule("crewai", _A, r"\bcrewai\b"),
    UaRule("browser-use", _A, r"browser[-_ ]use"),
    UaRule("smolagents", _A, r"smolagents"),
    # MCP reference "fetch" server (audit #115). Strings as quoted in finding L02-05 from mcp_server_fetch/server.py
    # (DEFAULT_USER_AGENT_AUTONOMOUS / _MANUAL): "ModelContextProtocol/1.0 (Autonomous; +https://github.com/
    # modelcontextprotocol/servers)" for model-initiated fetches, "(User-Specified; ...)" when the user named the
    # URL. Configurable with --user-agent, so absence proves nothing. TODO(verify): re-check on server releases.
    UaRule("mcp-fetch-autonomous", _A, r"ModelContextProtocol/[\w.]+ \(Autonomous\b"),
    UaRule("mcp-fetch-user-specified", _A, r"ModelContextProtocol/[\w.]+ \(User-Specified\b"),
    UaRule("mcp-fetch", _A, r"\bModelContextProtocol/"),
    UaRule("mcp-client", _A, r"\bmcp[-_ ]?(?:client|remote|inspector)\b"),
    # ARTEX (AI penetration-testing platform) self-declared UAs (audit #85, finding L01-08 from the ARTEX source):
    # the asset enrichment engine sends "artex-enrich/1.0", the bundled api-recon skill "Mozilla/5.0
    # (spa-api-recon spider)" / "Mozilla/5.0 (spa-api-recon)". Spoofable: attribution first, moderate AI weight
    # (scoring.DECLARED_CLIENT_STRENGTH).
    UaRule("artex-enrich", _A, r"\bartex-enrich/"),
    UaRule("artex-api-recon", _A, r"\bspa-api-recon\b"),
    UaRule("artex", _A, r"\bartex[-_]\w"),
    UaRule("ai-agent", _A, r"\b(?:ai|llm)[-_ ]?agent\b"),
    # --- AI crawlers (training / AI search)
    UaRule("gptbot", _C, r"GPTBot"),
    UaRule("oai-searchbot", _C, r"OAI-SearchBot"),
    UaRule("claudebot", _C, r"ClaudeBot|Claude-SearchBot|Claude-Web|anthropic-ai"),
    UaRule("perplexitybot", _C, r"PerplexityBot"),
    UaRule("ccbot", _C, r"\bCCBot\b"),
    UaRule("bytespider", _C, r"Bytespider"),
    UaRule("meta-externalagent", _C, r"meta-externalagent"),
    UaRule("cohere-ai", _C, r"cohere-ai"),
    UaRule("youbot", _C, r"\bYouBot\b"),
    # --- offensive tools / scanners (also raise web.scanner_ua). Exploitation tools HIGH, scanners MEDIUM,
    # research crawlers LOW. Each pattern is the union of the two former lists, so nothing that matched stops matching.
    UaRule("sqlmap", _S, r"sqlmap", _H),
    UaRule("commix", _S, r"\bcommix\b", _H),
    UaRule("havij", _S, r"\bhavij\b", _H),
    UaRule("xsstrike", _S, r"\bxsstrike\b", _H),
    UaRule("hydra", _S, r"\bhydra\b", _H),
    UaRule("nikto", _S, r"nikto", _M),
    UaRule("nuclei", _S, r"nuclei|projectdiscovery", _M),
    UaRule("ffuf", _S, r"Fuzz Faster U Fool|\bffuf\b", _M),
    UaRule("gobuster", _S, r"gobuster", _M),
    UaRule("feroxbuster", _S, r"feroxbuster", _M),
    UaRule("dirbuster", _S, r"dirbuster|\bdirb\b", _M),
    UaRule("dirsearch", _S, r"\bdirsearch\b", _M),
    UaRule("wfuzz", _S, r"wfuzz", _M),
    UaRule("wpscan", _S, r"wpscan", _M),
    UaRule("joomscan", _S, r"\bjoomscan\b", _M),
    UaRule("masscan", _S, r"masscan", _M),
    UaRule("zgrab", _S, r"zgrab", _M),
    UaRule("nmap", _S, r"Nmap Scripting Engine|\bnmap\b", _M),
    UaRule("acunetix", _S, r"acunetix", _M),
    UaRule("invicti", _S, r"netsparker|invicti", _M, "netsparker"),
    UaRule("zap", _S, r"OWASP[ _-]?ZAP|\bZAP/|\bzaproxy\b", _M, "owasp_zap"),
    UaRule("arachni", _S, r"arachni", _M),
    UaRule("w3af", _S, r"\bw3af\b", _M),
    UaRule("skipfish", _S, r"\bskipfish\b", _M),
    UaRule("openvas", _S, r"openvas", _M),
    UaRule("nessus", _S, r"nessus", _M),
    UaRule("qualys", _S, r"\bqualys", _M),
    UaRule("whatweb", _S, r"whatweb", _M),
    UaRule("appscan", _S, r"\bappscan\b", _M),
    UaRule("webinspect", _S, r"\bwebinspect\b", _M),
    UaRule("paros", _S, r"\bparos\b", _M),
    UaRule("jaeles", _S, r"\bjaeles\b", _M),
    UaRule("fimap", _S, r"\bfimap\b", _M),
    UaRule("morfeus", _S, r"\bmorfeus\b", _M),
    UaRule("zmeu", _S, r"\bzmeu\b", _M),
    UaRule("jorgee", _S, r"\bjorgee\b", _M),
    UaRule("censys", _S, r"\bcensysinspect\b", _L),
    # --- headless / automated browsers
    UaRule("headless-chrome", ClientFamily.HEADLESS_BROWSER, r"HeadlessChrome"),
    UaRule("phantomjs", ClientFamily.HEADLESS_BROWSER, r"PhantomJS"),
    UaRule("playwright", ClientFamily.HEADLESS_BROWSER, r"Playwright"),
    UaRule("puppeteer", ClientFamily.HEADLESS_BROWSER, r"Puppeteer"),
    UaRule("selenium", ClientFamily.HEADLESS_BROWSER, r"Selenium|webdriver"),
    # --- classic bots
    UaRule(
        "search-bot",
        ClientFamily.BOT,
        r"Googlebot|bingbot|Slurp|DuckDuckBot|Baiduspider|YandexBot|facebookexternalhit|Twitterbot|AhrefsBot"
        r"|SemrushBot",
    ),
    # --- CLI tools
    UaRule("curl", ClientFamily.CLI_TOOL, r"^curl/"),
    UaRule("wget", ClientFamily.CLI_TOOL, r"^Wget/"),
    UaRule("httpie", ClientFamily.CLI_TOOL, r"HTTPie/"),
    UaRule("powershell", ClientFamily.CLI_TOOL, r"PowerShell/"),
    # --- HTTP libraries
    UaRule("python-httpx", ClientFamily.HTTP_LIBRARY, r"python-httpx"),
    UaRule("python-requests", ClientFamily.HTTP_LIBRARY, r"python-requests"),
    UaRule("aiohttp", ClientFamily.HTTP_LIBRARY, r"aiohttp"),
    UaRule("python-urllib", ClientFamily.HTTP_LIBRARY, r"Python-urllib"),
    UaRule("go-http-client", ClientFamily.HTTP_LIBRARY, r"Go-http-client"),
    UaRule("node-fetch", ClientFamily.HTTP_LIBRARY, r"node-fetch"),
    UaRule("undici", ClientFamily.HTTP_LIBRARY, r"\bundici\b"),
    UaRule("axios", ClientFamily.HTTP_LIBRARY, r"\baxios\b"),
    UaRule("got", ClientFamily.HTTP_LIBRARY, r"\bgot\b \(https://github.com/sindresorhus/got\)"),
    UaRule("okhttp", ClientFamily.HTTP_LIBRARY, r"okhttp"),
    UaRule("apache-httpclient", ClientFamily.HTTP_LIBRARY, r"Apache-HttpClient"),
    UaRule("java", ClientFamily.HTTP_LIBRARY, r"^Java/"),
    UaRule("libwww-perl", ClientFamily.HTTP_LIBRARY, r"libwww-perl"),
    UaRule("ruby", ClientFamily.HTTP_LIBRARY, r"^Ruby\b|Faraday"),
    UaRule("dart", ClientFamily.HTTP_LIBRARY, r"^Dart/"),
    UaRule("reqwest", ClientFamily.HTTP_LIBRARY, r"reqwest"),
    UaRule("scrapy", ClientFamily.HTTP_LIBRARY, r"Scrapy"),
    UaRule("colly", ClientFamily.HTTP_LIBRARY, r"\bcolly\b"),
    UaRule("js-runtime", ClientFamily.HTTP_LIBRARY, r"^Deno/|^Bun/|^node$|^Node\.js"),
)


def scanner_alert_rules() -> tuple[UaRule, ...]:
    """Rules that ``web.scanner_ua`` alerts on (the offensive tools), in catalog order."""
    return tuple(r for r in UA_RULES if r.alert is not None)
