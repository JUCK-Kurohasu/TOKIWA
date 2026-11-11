# L02 pass2 NOTES
Done: findings L02-04..L02-10 filed. Network: only github/raw reachable; cylab.be, anthropic assets, cybersecuritynews blocked.
ARES: ambiguous. Candidates found via search: peruz-a/ares (Go, autonomous recon/exploit; page 404 on fetch, unread), mafifrizi/ares (Python/FastAPI red-team platform, MCP gateway for Cursor/Claude Desktop, AD/cloud/lateral modules; README read), munalabs/ares (Hermes agent profile). Could not determine which the owner means. No UA/transport documented for any.

| tool | transport/UA/pacing/rotation/reads-HTML | source |
|---|---|---|
| HexStrike AI | MCP server wrapping 100+ CLI tools run as subprocesses (nmap, nuclei, sqlmap, ffuf -t40, gobuster -t20/50, masscan rate 1000, katana depth3, httpx); no custom UA seen in first 100KB of server.py (727KB, rest unread); selenium+mitmproxy imported (browser agent); no rotation seen | https://github.com/0x4m4/hexstrike-ai (raw hexstrike_server.py) |
| PentAGI | Go backend, 20+ tools in Kali docker sandbox; web via 'scraper' browser service (MAX_CONCURRENT_SESSIONS 10); PROXY_URL covers only LLM/search, not sandbox; no evasion features documented; UA not documented | https://github.com/vxcontrol/pentagi README |
| Strix | agent loop, Kali sandbox, Caido proxy, automated browser (engine unnamed), terminal, python; multi-agent parallel; UA not documented | https://github.com/usestrix/strix README |
| MCP fetch server | httpx; UA ModelContextProtocol/1.0 (Autonomous|User-Specified; ...); robots.txt first | modelcontextprotocol/servers src/fetch |
| GTG-1002 (Anthropic) | multiple MCP servers, multiple ops/sec peaks (secondary sources only; PDF unreachable) | anthropic assets PDF via secondary: venturebeat, scworld |
| XBOW | no wire details publicly found | xbow.com blog |
| ARES (mafifrizi) | HTTP client/UA not documented; MCP gateway; headless browser only for reports | https://github.com/mafifrizi/ares |
Not researched (budget/network): PentestGPT, Villager, CAI (README 404), Nebula, RamiGPT, AutoPentest, Playwright-MCP UA.
