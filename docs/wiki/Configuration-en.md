> 🌐 [日本語](Configuration) · **English** · [中文](Configuration-zh) · [Español](Configuration-es)

# Configuration reference

## How to pass settings, and precedence

Items higher in the list take precedence.

1. **Environment variables** `TOKIWA_*` (nesting levels are joined with `__`; for example, `TOKIWA_LLM__DAILY_BUDGET_USD=10` → `llm.daily_budget_usd`)
2. **YAML file**: the path given in `TOKIWA_CONFIG` (default: `tokiwa.yaml` in the current directory, optional. A file named in `TOKIWA_CONFIG` that is missing or a directory is logged as a WARNING at startup. `TOKIWA_CONFIG=` (empty) reads no YAML file)
3. **Defaults** (`backend/src/tokiwa/config.py`)

In addition, the following two can be **overridden at runtime from the Web UI**, and those values are stored in the DB.

- LLM settings (**LLM → Settings**): provider, models, budget, output language, API key, and so on
- Enabling / disabling detectors (**Rules → Detectors**)

**A value saved in the UI takes precedence over the environment and YAML for that field** (the DB value wins). It survives restarts
and database restores. At startup the names of LLM fields that differ from the static configuration are logged as a WARNING
(values are not logged). Under LLM → Settings, "Overrides saved here" shows which fields come from the DB, and
**Reset all overrides** (`DELETE /api/v1/llm/config`, admin only, audited) goes back to the static configuration. To pin the LLM
settings from the environment / YAML (e.g. to force `TOKIWA_LLM__PROVIDER=mock` so that nothing is ever sent to an external LLM), set
`TOKIWA_LLM__ALLOW_UI_OVERRIDE=false` (`llm.allow_ui_override`, default true). DB overrides are then ignored and changes from the UI
(`PUT /api/v1/llm/config`) return 409. This setting itself cannot be changed from the UI.

With Docker Compose, `.env` is passed to the container as environment variables. When you run `tokiwa serve` directly on your machine,
`.env` is not loaded automatically.

### Things to watch when writing settings

- **Write lists and dictionaries as JSON**: `TOKIWA_DETECTION__DISABLED_DETECTORS='["web.scanner_ua"]'`
- **Do not set a value to empty** (what an empty string means differs per setting). An empty `TOKIWA_SERVER__SECRET_KEY=` is treated as unset, so the generated key in `data_dir/secret.key` is used. A key you set must have at least 32 characters; a shorter one stops the server from starting.
- We recommend passing secrets (API keys, passwords) in environment variables rather than in YAML.

### Checking the configuration (typos, effective values)

A misspelt setting is ignored and that setting keeps its default. So that you notice, the following are logged as a **WARNING** at
startup (names and paths only, never values):

- Unknown keys in the YAML file (`llm.providr` → `did you mean llm.provider?`; keys are case-sensitive)
- `TOKIWA_*` environment variables that name no setting (`TOKIWA_LLM__PROVIDR`, or `TOKIWA_LLM_PROVIDER` with one underscore instead of two)
- A file named in `TOKIWA_CONFIG` that does not exist or is a directory (a Docker bind mount creates a directory when the source file is missing)

With `TOKIWA_STRICT_CONFIG=1` the server refuses to start when any of these is found (the default only warns). Variables used by
Compose, the healthcheck and the lab scripts rather than by the settings (`TOKIWA_BIND`, `TOKIWA_HEALTHCHECK_URL`, ...) and e-mail
password variables are not reported. The `tokiwa serve` startup log also has one INFO line with the config file that was read,
`data_dir`, the database (password masked) and the LLM provider.

`tokiwa config show` prints the effective values and where each came from (`env` / `file` / `default`, and `ui` for values saved in
the UI with `--db`). Secrets are shown as `<set>`; passwords and queries in URLs and the path of webhook URLs are hidden.

```bash
tokiwa config show                       # every setting and its source
tokiwa config show --changed -s llm      # only llm.* values changed from the default
tokiwa config show --db                  # include LLM overrides saved in the UI (ui)
tokiwa config show --check               # exit code 1 if problems are found (pre-deploy check)
docker compose -f deploy/compose.yaml exec tokiwa tokiwa config show
```

### YAML example

```yaml
# tokiwa.yaml
server:
  base_url: https://tokiwa.example.internal
llm:
  daily_budget_usd: 10
  output_language: ja
triage:
  min_severity_for_llm: high
response:
  protected_cidrs: ["127.0.0.0/8", "::1/128", "10.0.0.0/24"]
  default_ttl_minutes: 30
deception:
  labyrinth_enabled: true
```

## Main settings

### General, server, DB

| Key | Default | Description |
|---|---|---|
| `env` | `dev` | `dev` / `prod` / `test` |
| `log_level` | `INFO` | Log level |
| `server.host` / `server.port` | `0.0.0.0` / `8788` | Listen address |
| `server.base_url` | `http://localhost:8788` | URL that users open (used for links in notifications and so on) |
| `server.cors_origins` | `["http://localhost:5173"]` | Only when the UI is served from a different origin |
| `server.static_dir` | None | Built UI (`frontend/dist`). When set, it is served at `/` |
| `server.data_dir` | `./data` | Where data is stored (signing key, and so on) |
| `server.secret_key` | Auto-generated | Signing key for logins (JWT), at least 32 characters. If unset or empty, it is generated and saved to `data_dir/secret.key` (mode 0600) |
| `server.token_ttl_minutes` | 720 | Login lifetime |
| `auth.setup_code_required` | `true` | First-run setup (creating the first admin) requires the single-use code printed in the startup log and saved to `data_dir/setup-code` |
| `server.max_body_bytes` | 1048576 (1 MiB) | Request body limit; larger bodies get 413. Applies to every API except ingest |
| `server.security_headers` | `true` | Add CSP, `X-Frame-Options: DENY`, `nosniff` and `Referrer-Policy: no-referrer` to every response. Set `false` only if a proxy sets its own policy or a customised UI does not fit the CSP |
| `server.expose_docs` | `true` | Serve the API docs (`/api/docs`, `/api/openapi.json`) without authentication. `false` is recommended in production |
| `server.max_ingest_body_bytes` | 33554432 (32 MiB) | Body limit for `/api/v1/ingest/`. A batch above it gets 413 and the Gate / agent **drops** that batch; raise it together with a larger `batch_size` |
| `auth.login_max_failures` | 5 | After this many failed logins for the same user name + source IP, further attempts are refused for a while (429). 0 disables |
| `auth.login_max_failures_per_ip` | 30 | Limit on failures from one source IP across all user names (password spraying). 0 disables |
| `auth.login_lockout_minutes` | 15 | Window (minutes) for both limits above; the lock lifts when old failures leave the window |
| `auth.password_hash_concurrency` | 4 | Password hashes (scrypt) computed at the same time |
| `database.url` | `sqlite+aiosqlite:///./data/tokiwa.db` | For PostgreSQL: `postgresql+asyncpg://user:pass@host/db` |

### LLM (`llm.*`)

See [LLM setup & cost](LLM-en). Main items: `provider`, `anthropic_api_key` (or the environment variable `ANTHROPIC_API_KEY`),
`openai_base_url` / `openai_api_key`, `model_fast` / `model_deep`, `daily_budget_usd`, `output_language`, `redaction.*`.

### Detection (`detection.*`)

| Key | Default | Description |
|---|---|---|
| `disabled_detectors` | `[]` | IDs of detectors to disable |
| `sigma_rule_dirs` | resolved from the package location (`<repo>/rules/sigma` in a source checkout, `/app/rules/sigma` in the Docker image) | Where Sigma rules are stored. Does not depend on the working directory. A directory that does not exist is logged as an ERROR at startup. Relative paths are looked up in the working directory, then in `backend/` |
| `dedup_window_seconds` | 300 | Time window for merging identical alerts |
| `llm_app_paths` | `/api/chat`, `/v1/chat/completions`, `/chat` | HTTP paths monitored for prompt injection |
| `session_idle_timeout_seconds` | 1800 | After this long without access, activity is treated as a new session |
| `ai_agent_threshold` | 0.7 | AI score threshold for classifying a session as an AI agent |
| `max_future_skew_seconds` | 120 | How far a sensor clock may run ahead. Events dated further in the future get the receive time instead, the tag `clock_skew` and the label `ingest.original_timestamp` (the original time); the audit entry `ingest.clock_skew` is written at most once per token every 10 minutes. Past timestamps (late or re-sent events) are kept |
| `max_live_sessions` | 4096 | Maximum number of sessions kept in memory. When full, one-request low-score sessions are evicted first and sessions with AI, canary or decoy evidence last. Heavy eviction logs a WARNING (a flood of one-request clients can reset session features); raise the limit if it appears under normal load |
| `fp_suppress_hours` | 168 | When an alert is marked as a false positive, recurrences of the same finding (same rule, matched content, path and source IP) are suppressed for this long: they are added to the original alert's count, with no new alert, LLM triage or notification. A new signature or a higher severity still alerts as usual. 0 disables the automatic suppression. List and lift suppressions with the API `GET/POST /api/v1/alert-suppressions` |
| `allowlist_max_hours` | 720 | Longest allowlist declaring the source CIDR of an authorised vulnerability scan or load test (created by an admin through the API; a duration is required). Alerts under an allowlist are only recorded at info severity and are not triaged, notified, turned into incidents or response proposals |
| `web.*` | — | Thresholds for web rate-based detections (bursts of errors, login failures, floods, and so on) |
| `web.max_inspect_chars` / `web.max_params` / `web.max_headers` / `web.max_json_leaves` / `web.max_json_depth` / `web.max_multipart_parts` | 8192 / 64 / 64 / 128 / 16 / 32 | Inspection limits of the web signature detections. Parameters, headers, JSON values and multipart parts past a count limit are not dropped but inspected together; text past the character limit is not inspected. Reaching a limit is recorded in the alert's `details.inspection_truncated` and the tag `inspection-truncated`; if what comes before the limit looks like padding (one repeated character, empty dummy items), `web.inspection_evasion` (low) fires |
| `web.inspect_custom_headers` / `web.extra_framing_headers` | true / `[]` | Application-specific headers (X-Tenant-Id and the like) are also checked for SQLi, XSS, path traversal and command injection. Framing headers (Accept, Sec-*, If-*, trace context and so on) are skipped; add names to `extra_framing_headers` (a trailing `*` matches a prefix) to skip more. false restores the previous behaviour (only User-Agent, Referer, X-Forwarded-* and similar) |
| `web.max_decode_rounds` | 8 | Maximum number of URL / HTML / JS decoding passes per value (against nested encodings; decoding stops as soon as the value no longer changes) |
| `web.header_count_low` / `web.header_count_medium` | 40 / 64 | A request with more header lines than this raises `web.header_anomaly` at low / medium (padding a request with headers to push the ones detection needs out of the capture). Browsers send about 10 to 25 lines and each CDN or load balancer adds a few. Raise it if legitimate requests trigger it; 0 turns that level off |

### Triage and correlation (`triage.*`)

| Key | Default | Description |
|---|---|---|
| `auto_triage` | true | Triage alerts with the LLM automatically |
| `min_severity_for_llm` | `medium` | Minimum severity sent to the LLM |
| `escalate_confidence_below` | 0.6 | If the fast model's confidence is below this, escalate to the deep model |
| `escalate_severity` | `high` | At or above this severity, escalate to the deep model |
| `max_concurrent` | 4 | Number of concurrent triage runs |
| `incident_window_minutes` | 60 | Time window for grouping alerts into the same incident |
| `max_evidence_events` | 25 | Maximum number of evidence events passed to the LLM |

### Response (`response.*`)

| Key | Default | Description |
|---|---|---|
| `auto_approve_enabled` / `auto_approve_actions` | false / `[]` | Auto-approval (both settings are required) |
| `auto_approve_cooldown_minutes` | 1440 | After a human rejects or reverts an action, the same type + target is not auto-approved for this many minutes (0 disables) |
| `default_ttl_minutes` / `max_ttl_minutes` | 60 / 10080 | Default and maximum TTL |
| `protected_cidrs` | `127.0.0.0/8`, `::1/128` | Ranges that are never targeted |
| `protect_server_addresses` | true | Protect the server's own IPs |
| `block_private_targets` | false | Forbid targeting private addresses (protects management networks) |
| `default_rate_limit_rpm` / `default_tarpit_delay_ms` | 60 / 2000 | Defaults for rate limiting and tarpit |
| `nftables_enabled` | false | Blocking with nftables |
| `webhook_urls` / `webhook_allowed_hosts` / `webhook_block_private` | `{}` / `[]` / true | Destinations for webhooks sent as a response action, and SSRF protection |

### Deception (`deception.*`) and intelligence (`intel.*`)

See [Deception (Mirage)](Deception-en) and [Vulnerability intelligence](Threat-Intel-en).

### Gate (`gate.*`) and Agent (`agent.*`)

| Key | Default | Description |
|---|---|---|
| `gate.upstream` | `http://127.0.0.1:3000` | Where to forward requests |
| `gate.listen_host` / `gate.listen_port` | `0.0.0.0` / 8080 | Listen address |
| `gate.server_url` | `http://127.0.0.1:8788` | TOKIWA server |
| `gate.ingest_token` | None | API token (scope: ingest + gate) |
| `gate.token_file` | None | File holding the API token. Re-read when it changes and after a 401 (no restart on rotation). Takes precedence over `ingest_token` when readable |
| `gate.capture_body_bytes` | 4096 | Number of leading body bytes to capture |
| `gate.trust_forwarded_for` | false | Trust `X-Forwarded-For` |
| `gate.max_request_headers` | 100 | Requests with more header lines than this get 431 instead of being forwarded (0 disables) |
| `gate.forward_client_headers` | `[]` | Headers normally removed (`X-Real-IP`, `Forwarded`, `CF-Connecting-IP`, `X-Original-URL`, ...) to pass to the upstream unchanged (only ones a trusted proxy in front sets) |
| `gate.tarpit_max_concurrent` / `gate.tarpit_max_per_client` | 256 / 8 | Max requests held by the tarpit at once (in total / per IP). Requests beyond get 429. 0 = no cap |
| `agent.server_url` | `http://127.0.0.1:8788` | TOKIWA server |
| `agent.ingest_token` | None | API token (scope: ingest) |
| `agent.interval_seconds` | 10 | Host sensor collection interval |
| `agent.nginx_json_logs` / `caddy_json_logs` / `suricata_eve_logs` / `zeek_log_dirs` | `[]` | Logs to ingest |
| `agent.verify_tls` | true | Verify the server's TLS certificate |
| `agent.send_cmdline` | true | Send process command lines (secrets masked before sending). false: only name, executable and user |
| `agent.max_connections_per_cycle` | 1000 | New connections sent per cycle (the overflow goes to the next cycle) |
| `agent.log_timezone` | none | Time zone of log timestamps without an offset (`Asia/Tokyo`, `+09:00`, `UTC`). Unset: read as UTC with a warning |
| `agent.health_report_seconds` | 300 | Minimum interval for reporting unreadable lines / timestamps (`agent.health` event) |

### Notifications (`notify.*`) and Copilot (`copilot.*`)

| Key | Default | Description |
|---|---|---|
| `notify.default_webhook_url` | None | Default webhook that works without registering it in the UI |
| `notify.default_min_severity` | `high` | Minimum severity for the default webhook |
| `notify.public_ui_url` | None | UI link target included in notifications |
| `notify.language` | `both` | Notification language |
| `notify.dedup_minutes` | 10 | Period during which identical notifications are suppressed |
| `notify.include_summary` | false | Include text written by the LLM (incident summaries, action reasons) in notifications |
| `notify.include_source_ip` | true | Include source IPs and IP / CIDR action targets in notifications (false shows `(hidden)`) |
| `notify.allowed_hosts` / `notify.block_private_destinations` | `[]` / true | Destination restrictions (SSRF protection) |
| `notify.smtp_password_envs` | `[]` | Extra environment variable names allowed as an email `password_env` (`TOKIWA_NOTIFY_SMTP_*` / `TOKIWA_SMTP_PASSWORD*` are allowed by default) |
| `notify.smtp_allowed_hosts` / `notify.smtp_block_private` | `[]` / false | SMTP destination restrictions (refusing private addresses is off by default because internal relays are common) |
| `notify.smtp_allow_plaintext_auth` | false | Allow SMTP authentication without TLS |
| `copilot.enabled` | true | Copilot |
| `copilot.tier` | `deep` | Model tier to use |
| `copilot.max_tool_iterations` | 8 | Maximum number of tool uses per question |
| `copilot.min_role` | `analyst` | Minimum role to create conversations and send messages (`viewer` / `analyst` / `admin`). One question can make up to 8 deep-tier calls against the shared daily budget, so viewers are excluded by default |
| `copilot.messages_per_minute` | 6 | Per-user cap on messages per minute (0 = unlimited). Above it the API answers 429 |

Every setting is defined in `backend/src/tokiwa/config.py`. For a Docker example, see `.env.example` in the repository root.
