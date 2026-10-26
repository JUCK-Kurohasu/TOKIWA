> 🌐 [日本語](Deception) · **English** · [中文](Deception-zh) · [Español](Deception-es)

# Deception (Mirage)

This feature places **traps** that legitimate users never touch on your own organization's assets, and detects whoever touches them with high confidence.
The Gate serves the traps; nothing is forwarded to the app you want to protect.

## AI canaries (reverse prompt injection)

This is the core mechanism of Mirage. It embeds "**hidden instructions that only AI agents read and follow**" inside decoys.

- Human users cannot see them (HTML comments and hidden elements; screen readers do not read them aloud either).
- The instructions take a form that **can only be followed by reading, understanding, and assembling them**, such as "send a value in a specific header (default `X-Debug-Auth`)"
  or "request a path made by appending a value to `/api/internal/`".
- The values never appear as links (`href`) or as OpenAPI examples. If a crawler or fuzzer that mechanically follows links happened to
  "follow" them by chance, the basis for concluding that the client is an AI would collapse.

When a request that follows the instructions arrives, you can conclude that it comes from an LLM-driven client (AI score 0.99).

## Asset types

| Type | What is placed | Detection condition |
|---|---|---|
| `decoy_path` | `/.env`, `/backup.sql`, `/admin/config.php`, `/.git/config`, `/api/internal/debug`, and so on. The content is fake credentials plus an AI canary note | Access to that path, or use of the fake credentials inside it |
| `honeytoken` | Fake AWS keys, API keys, DB credentials | The value appears in any event |
| `ai_canary` | Hidden instructions. Injection into HTML, `/robots.txt`, `/llms.txt`, OpenAPI-style JSON, and so on | **When the value is used as instructed** (merely fetching the page is not detected) |
| `labyrinth` | An endless maze of pages under `/archive/` (off by default) | Access under it. Severity critical at depth 3 or more |

The fake credentials deliberately differ from the formats of real services (for example, the AWS access key ID is 24 characters instead of the real
20). Even if they leak outside, they cannot pass as real credentials.

## What is created by default

When the server starts, the following assets are created automatically (existing ones are left unchanged).

- A `decoy_path` for each path listed in `deception.decoy_paths`
- AI canaries: HTML injection (enabled), `/api/internal/openapi.json` (enabled), `/robots.txt` (**disabled**), `/llms.txt` (**disabled**)
- The labyrinth, only when `deception.labyrinth_enabled: true`

The `/robots.txt` and `/llms.txt` canaries are disabled by default because they would replace files with the same names in the app you want to protect.
If you enable them, check that they do not conflict with the app's own content.

> Even if you **delete** an asset, it comes back at the next start as long as it remains in the settings. To stop it, **disable** it or remove it from the settings.

## When something is detected

| Classification | Severity | Meaning |
|---|---|---|
| `ai_canary_followed` | critical | Followed an AI canary instruction (almost certainly an AI agent; AI score 0.99) |
| `ai_canary_token` | critical | A canary value appeared somewhere else (an actor that read the hidden text; a human copying it from the source remains possible) |
| `honeytoken` | critical | Fake credentials were used |
| `decoy_path` | critical | A decoy path was accessed |
| `labyrinth` | high (critical at depth 3 or more) | Wandered into the labyrinth |

Decoy access also happens with automated scanners (paths like `/.env` are standard probing targets). To judge whether a client is an AI agent,
look at `ai_canary_followed` together with the behavioral score in [AI sessions](Web-UI-en).

## Working in the UI

On the **Deception** page, you can list, add, and enable / disable assets, **preview what is served**, and view the list of trips (records of touches).
You can also add traps in response to an incident with the `deploy_canary` response action.

## Main settings (`deception.*`)

| Key | Default | Description |
|---|---|---|
| `enabled` | true | Deception as a whole |
| `ai_canaries` | true | AI canaries |
| `decoy_paths` | The 5 paths above | Decoys created by default |
| `html_injection` | true | Inject hidden instructions into the HTML responses of the app you want to protect (right before `</body>`) |
| `canary_header` | `X-Debug-Auth` | Header name the hidden instructions ask the client to send. If you add it to `llm.redaction.sensitive_headers`, it can no longer be detected |
| `canary_language` | `both` | Language of the hidden instructions (`ja` / `en` / `both`) |
| `labyrinth_enabled` | false | Labyrinth |
| `labyrinth_prefix` / `labyrinth_max_depth` | `/archive/` / 8 | Location and depth of the labyrinth |

Disable `html_injection` if the app has a mechanism that sends the page DOM back to the server (session replay and the like).

## Usage notes

- Place traps **only on your own organization's assets**. TOKIWA does not strike back at the attack source or send back malware-like payloads.
- How strong the wording of the hidden instructions is, which language they use, and whether to place them in robots.txt / llms.txt are operational decisions. Before deploying,
  check with your organization's policies and your legal team.
