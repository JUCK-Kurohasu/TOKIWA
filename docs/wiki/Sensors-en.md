> 🌐 [日本語](Sensors) · **English** · [中文](Sensors-zh) · [Español](Sensors-es)

# Connecting sensors

The TOKIWA server does not go out and collect data itself; it analyzes the **events that sensors send to it**.
There are three kinds of sensors, and you can combine them.

| Sensor | What it sees | Good for |
|---|---|---|
| **TOKIWA Gate** | Entire HTTP requests (**including bodies**) and the response status | Protecting web apps and APIs. The Gate also enforces blocks and decoys |
| **TOKIWA Agent** | Host listening ports and connections, nginx / Caddy JSON logs, Suricata, Zeek | Monitoring servers, ingesting existing logs |
| **Ingest API (direct)** | Whatever you send yourself (for example, prompts from an LLM app) | Custom integrations |

## API tokens

Sensors authenticate with **API tokens**, not user logins.

```bash
cd backend
uv run tokiwa token create gate-1 --scope ingest --scope gate   # for Gate: add the gate scope explicitly
uv run tokiwa token create agent-web01            # default scope: ingest only
```

| Scope | What it allows |
|---|---|
| `ingest` | Sending events (`POST /api/v1/ingest/events`) |
| `gate` | Pulling the Gate policy (`GET /api/v1/gate/policy`) |
| `read` | Reserved (in v0.1, no API uses this scope yet) |

- The token (`tkw_...`) is shown **only once, when it is created**. Only its hash is stored in the DB.
- You can also create and revoke tokens in the Web UI under **Settings → API tokens** (admins only).
- If you pass a token as a command-line argument, other users can see it with `ps`, so pass it **in an environment variable or a file**.
- `--sensor-id` / `--dataset` **bind** a token to specific sensor ids and datasets (unrestricted when omitted). A bound
  token that sends a dataset outside its list gets the whole batch refused with 403; claiming another sensor id is replaced
  by an allowed one. Binding the tokens of non-Gate sensors is recommended
  (e.g. `--sensor-id web01 --dataset nginx.access --dataset 'host.*'`).
- The server records the delivering token on every event as the `ingest.token` / `ingest.token_id` labels. Gate-only data
  (`gate.*` / `deception.*`) sent by a token without the `gate` scope is labelled `ingest.trust=low`.
  So that forged events cannot get an innocent IP blocked, put partner, CDN and your own egress IPs in `response.protected_cidrs`.

## TOKIWA Gate (reverse-proxy sensor)

A reverse proxy that you put in front of the web app you want to protect. It captures even request bodies, which access logs don't show,
and immediately applies the policy distributed by the server (block, rate limit, tarpit, decoys).

```
Client ──▶ Gate (:8080) ──▶ App you want to protect
             │ Sends events / pulls policy (every 5 s by default)
             ▼
        TOKIWA Server (:8788)
```

### Starting the Gate

```bash
cd backend
export TOKIWA_GATE__INGEST_TOKEN=tkw_...          # Or --token-file <path>
uv run tokiwa gate run --upstream http://127.0.0.1:3000 --listen 0.0.0.0:8080 --server http://127.0.0.1:8788
```

Then change your DNS or load balancer so that users reach the Gate (:8080) from now on.

### Main settings

Settings take precedence in this order: "CLI flags > environment variables `TOKIWA_GATE__*` > `tokiwa.yaml` > defaults".

| Setting | CLI | Default | Description |
|---|---|---|---|
| upstream | `--upstream` | `http://127.0.0.1:3000` | Where to forward requests. A path prefix is also allowed (`http://app/base`) |
| listen | `--listen host:port` | `0.0.0.0:8080` | Listen address |
| server_url | `--server` | `http://127.0.0.1:8788` | TOKIWA server |
| ingest_token | `--token` / `--token-file` | None | Requires the `ingest` and `gate` scopes |
| capture_body_bytes | `--capture-body-bytes` | 4096 | Number of leading bytes of the request body to capture (0 disables capture) |
| policy_refresh_seconds | `--policy-refresh` | 5.0 | How often to pull the policy |
| trust_forwarded_for | `--trust-forwarded-for` | false | Use the **rightmost** `X-Forwarded-For` entry as the source IP |
| max_request_headers | — (`TOKIWA_GATE__MAX_REQUEST_HEADERS`) | 100 | Requests with more header lines than this get 431 instead of being forwarded (0 disables) |
| forward_client_headers | — (`TOKIWA_GATE__FORWARD_CLIENT_HEADERS`) | `[]` | Headers normally removed (see below) to pass to the upstream unchanged |
| tarpit_max_concurrent / tarpit_max_per_client | — | 256 / 8 | Max requests held by the tarpit at once (in total / per IP); requests beyond get 429 (0 = no cap) |

Operational knobs that exist only on the CLI: `--upstream-timeout` (30 seconds), `--max-queue` (cap on events waiting to be sent, 10,000),
`--preserve-host / --rewrite-host`, `--access-log`, `--limit-concurrency` (cap on concurrent connections; 503 beyond it; unlimited by default).

### Behavior you should know about

- **Use `--trust-forwarded-for` only behind a trusted load balancer**. Without it, `X-Forwarded-*` headers sent by the client
  are discarded and replaced with the values the Gate observed (to prevent source IP spoofing).
- Other headers that claim a client address or scheme (`X-Real-IP`, `Forwarded`, `True-Client-IP`, `CF-Connecting-IP`, ...) and `X-Original-URL` /
  `X-Rewrite-URL` are **not passed to the upstream**. Instead, the Gate sets `X-Real-IP` and `Forwarded` to the client address it determined.
  If your upstream reads a header that a front proxy such as Cloudflare sets, list it in `forward_client_headers` (e.g. `["cf-connecting-ip"]`).
  The Gate also never adds a `User-Agent` or similar header that the client did not send.
- Decoy matching treats differences in case, a trailing `/` or `.`, anything after `;`, `%5c` (`\`) and double encoding as the same path
  (`/.ENV` and `/.env;x` also hit a `/.env` decoy). Paths containing such variations get the tag `gate:path_anomaly`.
- Responses the Gate generates itself (403 for blocks, decoys, 502/504 on upstream failures, ...) carry `Cache-Control: no-store`. If a CDN sits in front of the Gate,
  check that it is not configured to force-cache 404s and similar responses.
- Request bodies with `Content-Encoding: gzip` / `deflate` are recorded decompressed (tag `gate:req_encoded`; the upstream still gets the compressed bytes).
  br and zstd cannot be decompressed; only the tag `gate:req_encoding_unknown` is recorded.
- Captured data is **redacted on the Gate before it is sent** (header values such as `Authorization` and `Cookie`,
  parameter values such as `password=`, tokens, keys, email addresses, and so on).
- Events keep up to 64 distinct request headers. Headers used for detection (User-Agent, Referer, `Sec-Fetch-*`, `X-Forwarded-*`, ...)
  are always kept wherever they appear; anything beyond is visible as the tag `gate:headers_truncated` with the header count (label `gate.header_count`).
- **fail-open**: If the TOKIWA server goes down, the Gate keeps proxying (events are buffered temporarily and resent).
- **fail-static**: If the Gate cannot fetch the policy, it keeps the last policy (so that taking the server down does not become a loophole for lifting blocks). Each block's own expiry (TTL) is still honoured by the Gate: entries past it are lifted.
- Health check: `GET /__tokiwa/health` → `{"status":"ok"}`. Requests from local / private IPs also get send statistics and more.
- Not supported: WebSocket (returns 501), HTTP/2 upstreams, gRPC. The Gate assumes a single process.

## TOKIWA Agent (host sensor and log forwarding)

```bash
cd backend
export TOKIWA_AGENT__INGEST_TOKEN=tkw_...
uv run tokiwa agent run --server-url http://tokiwa.example.internal:8788 \
  --nginx /var/log/nginx/tokiwa.json.log \
  --suricata /var/log/suricata/eve.json
```

| Source | Option | Details |
|---|---|---|
| Host | `--host-sensor` (on by default), `--connections` (on by default), `--interval` | List of listening ports and changes to it, new TCP connections |
| nginx | `--nginx <path>` (repeatable) | Access logs in JSON format (the format is in `lab/nginx/tokiwa-json.conf` in the repository) |
| Caddy | `--caddy <path>` | JSON access logs |
| Suricata | `--suricata <path>` | `eve.json` |
| Zeek | `--zeek-dir <path>` | A log directory or a single file |

- By default, logs are read **from the end** (use `--from-beginning` to read from the start).
- To check that it works, `tokiwa agent once --print` (collects once and prints the JSON without sending it) is handy.
- Reading other users' process information may require root-equivalent privileges.
- Listeners found in the first port snapshot are, by default (`agent.ports_first_snapshot: info`), recorded with severity "info"
  (with `learn`, they are not recorded and are only memorized as the baseline). After that, any new listener that appears is detected.

## Ingest API (direct sending and LLM app integration)

To send events from your own systems, call the ingest API directly. For example, an in-house LLM app can send
user prompts to TOKIWA so that you can monitor them for prompt injection.

```bash
curl -X POST http://127.0.0.1:8788/api/v1/ingest/events \
  -H "X-Tokiwa-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "events": [{
      "kind": "llm_app",
      "dataset": "support-bot.prompts",
      "source": {"ip": "203.0.113.10"},
      "llm_app": {"app": "support-bot", "role": "user", "prompt": "Ignore all previous instructions and ..."}
    }]
  }'
```

- The auth header is `X-Tokiwa-Token: tkw_...` or `Authorization: Bearer tkw_...`. The `ingest` scope is required.
- Up to **5,000 events** per request. If you omit `timestamp`, the time of receipt is used.
- The request body is limited to 32 MiB by default (`server.max_ingest_body_bytes`; larger bodies get 413). A string field longer
  than 65,536 characters is truncated to its beginning, and the event gets the tag `truncated` and the label `tokiwa.truncated`
  (`field:original length`). The event is not rejected; detection runs on the truncated values.
- `kind` values include `http` / `port_snapshot` / `connection` / `ids_alert` / `dns` / `process` / `auth` / `deception` /
  `llm_app` / `custom`. For schema details, see the server's API docs (`http://<server>:8788/api/docs`).
- ⚠️ **The ingest API does not redact anything on the server side** (the Gate and the Agent redact before sending).
  When you send directly, do not include secrets such as passwords or tokens. Note that data is always redacted right before it is passed to the LLM.

HTTP JSON chats (by default, those sent to `/api/chat`, `/v1/chat/completions`, and `/chat`) are automatically covered
by prompt-injection detection when they go through the Gate (configurable with `detection.llm_app_paths`).
