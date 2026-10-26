> 🌐 [日本語](Configuration) · **English** · [中文](Configuration-zh) · [Español](Configuration-es)

# Configuration reference

## How to pass settings, and precedence

Items higher in the list take precedence.

1. **Environment variables** `TOKIWA_*` (nesting levels are joined with `__`; for example, `TOKIWA_LLM__DAILY_BUDGET_USD=10` → `llm.daily_budget_usd`)
2. **YAML file**: the path given in `TOKIWA_CONFIG` (default: `tokiwa.yaml` in the current directory; ignored if it doesn't exist)
3. **Defaults** (`backend/src/tokiwa/config.py`)

In addition, the following two can be **overridden at runtime from the Web UI**, and those values are stored in the DB.

- LLM settings (**LLM → Settings**): provider, models, budget, output language, API key, and so on
- Enabling / disabling detectors (**Rules → Detectors**)

With Docker Compose, `.env` is passed to the container as environment variables. When you run `tokiwa serve` directly on your machine,
`.env` is not loaded automatically.

### Things to watch when writing settings

- **Write lists and dictionaries as JSON**: `TOKIWA_DETECTION__DISABLED_DETECTORS='["web.scanner_ua"]'`
- **Do not set a value to empty**. `TOKIWA_SERVER__SECRET_KEY=` is treated as "a signing key that is an empty string" (which is not the same as leaving it unset).
- We recommend passing secrets (API keys, passwords) in environment variables rather than in YAML.

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
| `server.secret_key` | Auto-generated | Signing key for logins (JWT). If unset, it is generated and saved to `data_dir/secret.key` |
| `server.token_ttl_minutes` | 720 | Login lifetime |
| `database.url` | `sqlite+aiosqlite:///./data/tokiwa.db` | For PostgreSQL: `postgresql+asyncpg://user:pass@host/db` |

### LLM (`llm.*`)

See [LLM setup & cost](LLM-en). Main items: `provider`, `anthropic_api_key` (or the environment variable `ANTHROPIC_API_KEY`),
`openai_base_url` / `openai_api_key`, `model_fast` / `model_deep`, `daily_budget_usd`, `output_language`, `redaction.*`.

### Detection (`detection.*`)

| Key | Default | Description |
|---|---|---|
| `disabled_detectors` | `[]` | IDs of detectors to disable |
| `sigma_rule_dirs` | `["../rules/sigma"]` | Where Sigma rules are stored |
| `dedup_window_seconds` | 300 | Time window for merging identical alerts |
| `llm_app_paths` | `/api/chat`, `/v1/chat/completions`, `/chat` | HTTP paths monitored for prompt injection |
| `session_idle_timeout_seconds` | 1800 | After this long without access, activity is treated as a new session |
| `ai_agent_threshold` | 0.7 | AI score threshold for classifying a session as an AI agent |
| `web.*` | — | Thresholds for web rate-based detections (bursts of errors, login failures, floods, and so on) |

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
| `gate.capture_body_bytes` | 4096 | Number of leading body bytes to capture |
| `gate.trust_forwarded_for` | false | Trust `X-Forwarded-For` |
| `agent.server_url` | `http://127.0.0.1:8788` | TOKIWA server |
| `agent.ingest_token` | None | API token (scope: ingest) |
| `agent.interval_seconds` | 10 | Host sensor collection interval |
| `agent.nginx_json_logs` / `caddy_json_logs` / `suricata_eve_logs` / `zeek_log_dirs` | `[]` | Logs to ingest |
| `agent.verify_tls` | true | Verify the server's TLS certificate |

### Notifications (`notify.*`) and Copilot (`copilot.*`)

| Key | Default | Description |
|---|---|---|
| `notify.default_webhook_url` | None | Default webhook that works without registering it in the UI |
| `notify.default_min_severity` | `high` | Minimum severity for the default webhook |
| `notify.public_ui_url` | None | UI link target included in notifications |
| `notify.language` | `both` | Notification language |
| `notify.dedup_minutes` | 10 | Period during which identical notifications are suppressed |
| `notify.allowed_hosts` / `notify.block_private_destinations` | `[]` / true | Destination restrictions (SSRF protection) |
| `copilot.enabled` | true | Copilot |
| `copilot.tier` | `deep` | Model tier to use |
| `copilot.max_tool_iterations` | 8 | Maximum number of tool uses per question |

Every setting is defined in `backend/src/tokiwa/config.py`. For a Docker example, see `.env.example` in the repository root.
