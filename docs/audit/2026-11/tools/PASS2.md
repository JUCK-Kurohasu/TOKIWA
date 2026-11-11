# TOKIWA audit — second pass (read after RULES.md)

AUDIT_DIR = $AUDIT_DIR

## Common instructions (all lanes)
1. Read `$AUDIT_DIR/RULES.md` first and obey it (repo read-only, localhost only, mock LLM, no GitHub writes,
   never `pkill -f`, kill by PID, no secrets in findings, ARTEX = cite file:line only).
2. Dedupe: run `python3 $AUDIT_DIR/consolidate.py summary | cut -c1-150` — these ~100 findings are ALREADY FILED as
   GitHub issues. Do not re-report them. `python3 $AUDIT_DIR/consolidate.py show <id>` prints one in full.
   Report something related only if it is a different root cause or changes the severity.
3. Read your lane's existing notes/scripts under `$AUDIT_DIR/agents/<lane>/` (NOTES.md if present) before starting.
4. MYDIR = `$AUDIT_DIR/agents/<lane>/pass2/` (create it). Use only your port range.
5. **You can be cut off by rate limits at any moment.** Therefore:
   - APPEND each finding to your lane's JSONL the moment it is solid (python `json.dumps(obj, ensure_ascii=False)`),
     continuing the numbering given below. Never hold findings until the end.
   - Keep `MYDIR/NOTES.md` current (done / in progress / next) every few steps.
6. Budget: about 60 tool calls. Prefer 3–8 solid, non-duplicate findings over many weak ones. Reproduce when it is
   cheap (confidence `confirmed` with command + observed output); otherwise `likely` with file:line.
7. A bare `sleep` Bash command is blocked in this sandbox: wait inside Python (`time.sleep`) or use `curl --retry`.
   Background processes: `nohup ... & echo $! > pidfile`; stop them by PID before finishing.
8. Prose fields in Japanese; code/paths/commands as-is. Final message: RULES.md §5 (< 400 words).

## Lane L03 — canary / deception, pass 2   (file: findings/L03-canary.jsonl, next id L03-06, ports 21300-21349)
The owner's explicit question: 「カナリアが十分じゃない？」. Existing: L03-01..05, L01-05, L01-06, L06-03, L07-01, L11-03, L09-06.
Open items:
- (a) API-only agents: an agent that drives only JSON/OpenAPI endpoints never fetches HTML. Is there any canary/honeytoken
  surface in JSON responses, error pages, headers, robots.txt/sitemap, the OpenAPI spec, JS bundles? Verify against the lab victim via Gate.
- (b) Trip evasion: ways to USE a decoy/honeytoken/canary value that the trip detector does not see (encodings, body
  formats, header vs cookie vs path, split values, using the credential against a host/path not behind Gate, methods).
- (c) Injection side effects on the protected app: Content-Length/ETag/caching (a cache or CDN in front stores the page with
  the canary — per-visitor? cache poisoning?), compressed (gzip/br) or chunked/streamed upstream bodies, non-UTF-8 charsets,
  HTML fragments (htmx), CSP/SRI interaction, accessibility tools, search-engine indexing of hidden text and decoy links
  (benign crawlers and user-initiated AI assistants then trip the canary = false AI-attacker attribution).
- (d) Follow rate (web research): how often do current agent stacks obey hidden-instruction text in fetched pages?
  (prompt-injection benchmarks and vendor defenses for browsing/computer-use agents; pentest agents; check ARTEX prompts in
  /home/user/artex-jp for instructions about untrusted tool output). The canary depends on the attacker's agent being
  obedient; if modern agents are trained to ignore injected instructions, quantify/argue what remains, and propose lures
  that a rational agent WANTS to use (credentials, endpoints, IDs) rather than instructions it must obey.
- (e) Coverage across the kill chain: what deception exists after initial recon (host files, DB rows, cloud keys, internal
  docs)? Compare with canarytokens-style approaches and published "LLM agent honeypot" research.

## Lane L06 — Gate protocol, pass 2   (file: findings/L06-gate.jsonl, next id L06-06, ports 21600-21649)
Existing: L06-01..05, L05-01..03, L02-03. Open items:
- Request smuggling / desync between Gate's HTTP parser and the upstream client: CL.TE, TE.CL, duplicate Content-Length,
  obs-fold, bare LF, chunk extensions, `Expect: 100-continue`. Which parser/server and which client does Gate use?
- Inspection/forwarding mismatch: what Gate records and inspects vs what upstream receives (path normalisation `//`, `/./`,
  `%2e`, `;`, NUL; duplicate headers; `X-HTTP-Method-Override`; Host vs absolute-form; body re-encoding).
- Hop-by-hop abuse: `Connection: X-Forwarded-For`-style header stripping; `Forwarded:` vs XFF; multiple XFF values.
- absolute-form / CONNECT / Host-header routing: open proxy or SSRF via Gate? WebSocket / Upgrade / h2c: forwarded
  uninspected or broken?
- Gate-generated responses (block page, decoys): reflection/XSS, header injection, cache headers.
- Gate <-> server link: TLS verification, plain-http allowed silently?, policy integrity (a MITM or spoofed server can push
  an empty/hostile policy?), token handling (argv, logs, env).
- Blocklist matching edge cases: IPv4-mapped IPv6, IPv6 /64 rotation, zone IDs, XFF with port, TTL expiry and clock.

## Lane L09 — respond / notify, pass 2   (file: findings/L09-respond.jsonl, next id L09-07, ports 21900-21949)
Existing: L09-01..06, L07-05, L06-01, L08-05, L08-08. Open items:
- Approval workflow integrity: races (double approve, approve vs expire, approve vs revert), self-approval of own
  proposal, role checks on every transition, audit trail completeness/tamper, proposals created via API with arbitrary params.
- Auto-approval (if any): conditions an attacker can satisfy.
- Parameter validation: CIDR width (/0, /8), IPv6, TTL bounds (permanent blocks), default `protected_cidrs` completeness
  (loopback, link-local, RFC1918, the server/Gate/upstream/DNS/monitoring addresses).
- Executor truth: Gate offline or policy not fetched → action shown "active" but not enforced? revert reliability.
- Notification channels: SSRF via webhook URL (internal metadata, redirects, DNS rebinding), secrets inside webhook URLs
  exposed by API/UI/logs, content injection into Slack/Discord/email built from attacker-controlled fields (mentions,
  link spoofing, markdown, email header injection, HTML), notification flood / no rate limit / dedupe, failure handling
  (retry, backoff, does a slow channel block the pipeline?), SMTP TLS verification, sensitive data sent to third-party SaaS.

## Lane L12 — sensors + intel parsing, pass 2   (file: findings/L12-sensors-intel.jsonl, next id L12-04, ports 22200-22249)
Existing: L12-01..03, L04-01, L08-06. Open items:
- Agent log parsers (nginx/apache/JSON...): log injection through attacker-controlled fields (quotes, escapes, newlines in
  UA/referer/path) to forge lines or spoof the source IP; malformed/huge lines; encodings; timezone/timestamp parsing
  (future timestamps feed L04-01); offset persistence, inode reuse, symlinks; spool/retry limits (disk fill); TLS
  verification and token file permissions; privileges the agent needs.
- Host sensors: port/process collection correctness, baseline poisoning during learning, agent silence/tamper detection.
- Intel feeds (NVD/KEV/EPSS/JVN/OSV/GHSA/RSS): XML safety (XXE, entity expansion), size limits, user-added feed URL
  validation (SSRF, schemes, redirects), third-party-controlled text (RSS/advisories) reaching the UI (stored XSS) or the
  advisor LLM (prompt injection → rule proposals), CPE/version matching false negatives/positives, staleness handling,
  date parsing, web-research output handling.

## Lane L02 — field research: real AI attack tools vs TOKIWA, pass 2   (file: findings/L02-field.jsonl, next id L02-04, ports 21200-21249)
Existing: L02-01, L02-03 (+ all L01 ARTEX findings, L04 evasion findings). The owner named "ARTEX や ARES のような攻撃ツール".
- Web research (WebSearch/WebFetch; read-only) on currently public AI/LLM-driven offensive tools and what their traffic
  looks like on the wire: identify what "ARES" refers to in this space (state uncertainty if ambiguous), plus e.g. PentAGI,
  Strix, PentestGPT, XBOW, HexStrike AI, Villager, CAI (Cybersecurity AI), Nebula, RamiGPT, AutoPentest/DRL tools, MCP-based
  kali toolchains, browser-use/Playwright-MCP based agents, and reported in-the-wild LLM-orchestrated campaigns.
  For each: transport (curl/python-requests/Go/headless browser), tool wrappers (nmap/nuclei/sqlmap/ffuf), concurrency,
  pacing, UA/TLS fingerprint, proxy/IP rotation features, whether it reads HTML (canary reachability), post-exploitation.
- Map each behaviour onto TOKIWA's detectors (backend/src/tokiwa/detect, aidetect, deception) and report GAPS that are not
  already filed: tool classes TOKIWA has no signal for, wrong assumptions in its AI-attribution features, missing
  signatures/fingerprints (e.g. tool-specific default UAs, MCP tool chains), missing eval scenarios in `tokiwa.eval.sim`.
- Where cheap, confirm with a local replay of the documented traffic shape through the lab (sim or a short script).
- Cite sources (URLs) in `references`; separate documented facts from your inference.

## Lane L10 — frontend, pass 2   (file: findings/L10-frontend.jsonl, next id L10-04, ports 22000-22049)
Existing: L10-01..03, L07-02. Open items (attacker-controlled telemetry rendered in an analyst's browser is the theme):
- Stored XSS / HTML injection / link injection: every place the UI renders event fields (path, UA, headers, body),
  LLM output (markdown rendering? links? images → data exfiltration by image URL), intel/RSS text, notification previews,
  decoy previews. `dangerouslySetInnerHTML`, markdown libs, `href={untrusted}` (javascript: URLs), CSV/JSON export (formula injection).
- Token storage and session handling in the SPA, SSE auth (token in URL?), CORS config, CSRF, clickjacking, open redirects,
  role checks done only client-side, error messages leaking internals, dependency audit (`npm audit` on a COPY of
  frontend/package*.json in MYDIR — never in the repo), source maps in dist.
- UX problems that matter in an incident: unbounded lists, missing pagination, misleading states (mock LLM shown as real,
  "active" block that is not enforced), bilingual gaps, timezone display.
  Use the pre-installed Playwright (`require('playwright')`, chromium.launch() with no options) against a local server if useful.

## Lane L14 — Docker lab e2e, remainder   (file: findings/L14-lab.jsonl, next id L14-11, ports 22400-22449)
Read `$AUDIT_DIR/agents/L14/NOTES.md`. Finish only what is listed there as pending (lab ingest/agent profiles), write any
evidence you already have as findings, then clean up containers/daemons you start. If Docker cannot be started within
~10 tool calls, write that down in NOTES.md and stop — do not burn budget on it.
