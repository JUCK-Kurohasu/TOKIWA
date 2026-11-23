> 🌐 [日本語](CLI) · **English** · [中文](CLI-zh) · [Español](CLI-es)

# CLI reference

Everything is done with the `tokiwa` command. When running from source, use `uv run tokiwa ...` in the `backend/` directory;
in the Docker image, use `tokiwa ...` (or pass the subcommand name as the container argument).
Use `--help` to see the latest options for each command.

| Command | Description |
|---|---|
| `tokiwa version` | Show the version |
| `tokiwa serve` | Server (API, UI, ingest, background jobs) |
| `tokiwa user` | User management |
| `tokiwa token` | API tokens for sensors |
| `tokiwa gate` | Reverse-proxy sensor |
| `tokiwa agent` | Host sensor and log forwarding |
| `tokiwa intel` | Vulnerability feeds |
| `tokiwa sim` | Lab traffic simulator |
| `tokiwa eval` | Evaluation harness |
| `tokiwa data` | Delete / export the data of a given IP or session |

> ⚠️ Run commands that access the DB directly (`user`, `token`, `intel`, and so on) with the **same configuration** as the server (the same current directory,
> or the same `TOKIWA_DATABASE__URL`). The default DB path `./data/tokiwa.db` is a relative path.

## tokiwa serve

```bash
tokiwa serve [--host HOST] [--port 8788] [--reload] [--no-jobs]
```

| Option | Description |
|---|---|
| `--host` / `--port` | Listen address (defaults to the configured values; port 8788) |
| `--reload` | Restart automatically when the code changes (for development) |
| `--no-jobs` | Do not start periodic jobs (intel sync, expiry processing, and so on) |

The API docs are at `http://<server>:8788/api/docs`, and the health check is at `/api/v1/health`.
The API docs (`/api/docs`, `/api/openapi.json`) are public without authentication, so in production we recommend turning them
off with `server.expose_docs: false` (environment variable `TOKIWA_SERVER__EXPOSE_DOCS=false`). The health check needs no
authentication, but it returns the version only to a signed-in user.

## tokiwa user create

```bash
tokiwa user create <username> [--role admin|analyst|viewer]
```

You are prompted for the password interactively (twice, with input hidden). The default role is `analyst`.
If a user with that name already exists, the command prints an error and exits with code 1. The creation is recorded in the audit log as `user.create` (actor `cli`).
It is also the recovery path when no admin is left (`--role admin`).

## tokiwa user reset-password

```bash
tokiwa user reset-password <username>
```

Prompts for a new password (twice, with input hidden) and sets it. All existing logins of that user end, and the audit log records `user.password_reset` (actor `cli`; the password is never recorded). Use it when the admin password is lost.

## tokiwa token create

```bash
tokiwa token create <name> [--scope ingest] [--scope gate] [--sensor-id ID ...] [--dataset PATTERN ...]
```

The default scope is `ingest` **only**. For a Gate token pass `--scope ingest --scope gate` explicitly (the `gate` scope can read the Gate policy, including decoy paths, canary values and the block list, so give it to Gates only). The token (`tkw_...`) is shown **only once**.
`--sensor-id` / `--dataset` (repeatable) bind the token to sensor ids and datasets ([Connecting sensors](Sensors-en)).
`--expires-in-days N` sets an expiry (default: never). An expired token gets 401.

## tokiwa token list / revoke / rotate

```bash
tokiwa token list [--all]                                  # list (never shows secrets; --all includes revoked)
tokiwa token revoke <id|name>                              # revoke now
tokiwa token rotate <id|name> [--grace-hours 24] [--expires-in-days N]   # issue a new token (printed once on stdout)
```

These work on the server host without an admin login (lost password, incident in progress). Each operation is recorded
in the audit log with actor `cli`. `rotate` issues a new token with the same name, scopes and binding and keeps the old
one valid for `--grace-hours` (default 24 hours; 0 revokes it now). The Gate re-reads its token file when it changes, so
writing the new token to the file switches over without a restart. If a name matches several active tokens, pass the id.

## tokiwa data purge / export

```bash
tokiwa data purge  [--ip IP] [--session ID] [--before 2026-11-01] [--yes]   # default: counts only (dry run)
tokiwa data export [--ip IP] [--session ID] [--before ...] [--out subject.jsonl]
```

Deletes or exports everything stored about a source IP, an actor session or a time range (data-subject access or deletion
requests, customer data ingested by mistake). Selectors combine with AND. Covered: `events`, `actor_sessions` and
`deception_trips` rows are deleted; `alerts` get their `details` cleared (the row stays, incidents refer to it); `llm_calls`
lose only the prompt and response text (cost records stay). LLM records are matched on the IP / session id with word
boundaries (`10.0.0.1` does not match `10.0.0.15`). `export` writes JSONL (one `{"table": ..., "row": {...}}` per line); an
`--out` file gets mode 600. Both are recorded in the audit log with actor `cli`. Incident summaries, Copilot conversations
and backups are not covered.

## tokiwa gate run

```bash
tokiwa gate run --upstream http://127.0.0.1:3000 [--listen 0.0.0.0:8080] [--server http://127.0.0.1:8788] \
  [--token-file PATH] [--trust-forwarded-for] ...
```

| Option | Default | Description |
|---|---|---|
| `--upstream` | Configured value | URL to forward requests to |
| `--listen` | `0.0.0.0:8080` | Listen `host:port` |
| `--server` | Configured value | TOKIWA server URL |
| `--token` / `--token-file` | — | API token (the environment variable `TOKIWA_GATE__INGEST_TOKEN` or a file is recommended; the file is re-read when it changes and after a 401) |
| `--sensor-id` | `gate-1` | Sensor ID recorded in events |
| `--capture-body-bytes` | 4096 | Number of leading body bytes to capture |
| `--trust-forwarded-for` | off | Use the rightmost `X-Forwarded-For` entry as the source (only behind a trusted LB) |
| `--policy-refresh` | 5 | Policy pull interval (seconds) |
| `--batch-size` / `--flush-interval` | 100 / 1.0 | Batching for sending |
| `--upstream-timeout` | 30 | Upstream read/write timeout (seconds) |
| `--max-queue` | 10000 | Cap on events waiting to be sent (when exceeded, the oldest are dropped first) |
| `--preserve-host` / `--rewrite-host` | preserve | Send the Host header as is, or rewrite it to the upstream's host |
| `--access-log` | off | uvicorn access log |
| `--log-level` | Configured value | Log level |

## tokiwa agent

```bash
tokiwa agent run  [--server-url URL] [--nginx PATH ...] [--caddy PATH ...] [--suricata PATH ...] [--zeek-dir PATH ...]
tokiwa agent once [--print] [--max-events 1000] ...
```

| Option | Description |
|---|---|
| `--server-url` | TOKIWA server URL |
| `--token` | API token (the environment variable `TOKIWA_AGENT__INGEST_TOKEN` is recommended) |
| `--sensor-id` | Sensor ID (defaults to the hostname) |
| `--interval` | Host sensor interval (seconds) |
| `--host-sensor / --no-host-sensor` | Collect listening ports and connections |
| `--connections / --no-connections` | Report new TCP connections |
| `--nginx` / `--caddy` / `--suricata` / `--zeek-dir` | Logs to ingest (can be specified multiple times) |
| `--from-beginning / --from-end` | Where to start reading logs (default: end) |
| `once --print` | Collect once and print the JSON without sending it (for checking that it works) |

## tokiwa intel

```bash
tokiwa intel sync [-s kev] [-s nvd]   # Run one sync (default: all enabled sources)
tokiwa intel status                   # Sync status per source
tokiwa intel show CVE-2021-44228 [--json]   # Show one merged entry (CVE / GHSA / JVNDB ID)
```

## tokiwa sim

```bash
tokiwa sim profiles
tokiwa sim run      [--profile mixed] [--target http://localhost:8080] [--sessions N] [--seed 1] \
                    [--time-scale 1.0] [--spread 60] [--max-requests 2000] [--max-rps 50] \
                    [--spoof-xff] [--record FILE.jsonl] [--loop] [--i-own-this-target]
tokiwa sim generate --out FILE.jsonl [--profile mixed] [--sessions N] [--seed 1] [--start ISO8601] [--spread 1800] [--no-canary]
tokiwa sim ingest   [--server http://localhost:8788] [--token-file PATH] [--profile mixed] [--batch-size 200]
```

| Subcommand | Description |
|---|---|
| `profiles` | List the profiles |
| `run` | Actually send traffic to a lab target (the Gate) |
| `generate` | Generate a labeled dataset without using the network (the same seed gives an identical file) |
| `ingest` | Send synthetic events directly to the ingest API (no Gate needed) |

Specify `--profile` like `ai_agent`, `ai_agent,scanner`, `ai_agent=2,benign_browser=5`, or `mixed`.
Setting `--time-scale` below 1 makes the run finish faster, but it changes the request rhythm and also affects the features used for the AI verdict.

## tokiwa eval

```bash
tokiwa eval run --dataset FILE.jsonl [--llm mock|live] [--budget-usd N] [--out DIR] \
                [--compare PREV] [--fail-on-regression] [--allow-mismatch] [--speed 0] [--json]
tokiwa eval compare <current> <previous> [--fail-on-regression] [--allow-mismatch]
tokiwa eval import-artex <source> --out FILE.jsonl [--host HOST] [--session LABEL] [--source-ip IP] \
                         [--since T] [--until T] [--split-gap-minutes N]
tokiwa eval info FILE.jsonl
```

| Option | Description |
|---|---|
| `--llm` | `mock` (free, offline, default) or `live` (the configured provider; **incurs cost**) |
| `--budget-usd` | **Required** with `--llm live`. Cost cap for this run |
| `--out` | Output directory (default `eval/runs/<UTC time>`) |
| `--compare` / `--fail-on-regression` | Compare with a previous run / exit with code 1 if results got worse. If the two runs differ in their conditions (dataset sha256, LLM provider, enabled detectors, number of Sigma rules loaded, thresholds, batching), they are "not comparable" and the exit code is 3 |
| `--allow-mismatch` | Compare and judge regressions even when the conditions differ (the differences are shown as a warning) |
| `--speed` | 0 = as fast as possible, 1 = real time, 10 = 10× speed |
| `--enable-detector` / `--disable-detector` | Force a detector on / off |
| `--keep-work` | Keep the temporary DB used for the evaluation |
| `import-artex --since` / `--until` | Import only ARTEX records in this time window (unix seconds or ISO 8601; UTC if no offset) |
| `import-artex --split-gap-minutes` | Per host, start a new session (with its own source IP) wherever the recording pauses for N minutes or more. No splitting by default |
