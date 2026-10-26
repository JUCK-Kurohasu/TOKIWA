> 🌐 [日本語](Quick-Start) · **English** · [中文](Quick-Start-zh) · [Español](Quick-Start-es)

# Quick start

These steps start TOKIWA on your own machine and use the bundled attack simulator to walk you through "detect an AI agent's attack → a human approves → block".
Docker is not used. It takes about 10 to 15 minutes.

> For a production-style, day-to-day setup (Docker Compose), see [Installation & operations](Installation-en).

## Requirements

| Software | Version | Purpose |
|---|---|---|
| Python | 3.12 or later | Backend |
| [uv](https://docs.astral.sh/uv/) | Latest | Python dependency management |
| Node.js / npm | 22.x | Building the Web UI |
| git | — | Getting the source |

It has been tested on Linux. macOS is expected to work with the same steps, but this is not yet verified. Windows is not yet verified.
TOKIWA **works without an LLM API key** (in that case it runs with the mock LLM and rule-based verdicts).

## 1. Get the source and install

```bash
git clone https://github.com/JUCK-Kurohasu/TOKIWA.git
cd TOKIWA

cd frontend && npm install && npm run build && cd ..   # Build the Web UI (frontend/dist)
cd backend && uv sync                                   # Install the backend dependencies
```

## 2. Start the server

```bash
# Run in backend/
TOKIWA_SERVER__STATIC_DIR=../frontend/dist uv run tokiwa serve
```

Open <http://localhost:8788> in your browser. The first time, you see the **setup page (/setup)**, where you create the first administrator.

- Username: 3–64 characters (letters, digits, `_` `.` `-`)
- Password: at least 10 characters

Data (the SQLite DB and the signing key) is stored in `backend/data/`.

> 💡 If you want to modify the UI while using it, run `make dev` in the repository root. It starts the API (:8788, auto-reload) and
> the UI dev server (:5173) together.

### Using an LLM (optional)

Pass the API key in an environment variable before you start the server.

```bash
export ANTHROPIC_API_KEY=sk-ant-...      # Setting this switches the provider to Anthropic automatically
```

The default daily budget is **$5**. Beyond that, TOKIWA switches to rule-based verdicts. For details, see [LLM setup & cost](LLM-en).

## 3. Build a mini lab and send attacks

Put TOKIWA Gate in front of the bundled "victim" demo app, and send attack traffic with the simulator.
You use **three terminals** (four in total, including the one for the server).

```
 Simulator ──▶ Gate :8080 ──▶ Victim app :3000 (demo shop with no vulnerabilities)
                 │
                 ▼
         TOKIWA Server :8788
```

**Terminal A — victim app** (all responses are fixed; it is not actually vulnerable)

```bash
cd lab/victim
../../backend/.venv/bin/uvicorn app:app --host 127.0.0.1 --port 3000
```

**Terminal B — create an API token for the Gate and start the Gate**

```bash
cd backend
uv run tokiwa token create gate-1        # tkw_... is shown only once; note it down
export TOKIWA_GATE__INGEST_TOKEN=tkw_...  # Safer than a command-line argument (does not show up in ps)
uv run tokiwa gate run --upstream http://127.0.0.1:3000 --listen 127.0.0.1:8080 \
  --server http://127.0.0.1:8788 --trust-forwarded-for
```

> ⚠️ Run `tokiwa token create` in the **same directory (`backend/`) and with the same environment variables** as the server.
> The DB location (default `./data/tokiwa.db`) is a path relative to the current directory at run time.

`--trust-forwarded-for` is a lab-only setting that lets the simulator claim a source IP through `X-Forwarded-For`.
In production, do not use it except "when the Gate is behind a trusted load balancer".

**Terminal C — send attacks with the simulator**

```bash
cd backend
uv run tokiwa sim run --target http://127.0.0.1:8080 --time-scale 0.1 --spread 10 --spoof-xff
```

The traffic mixes five types: benign users, scanners, human attackers, AI agents, and attackers targeting LLM apps
(it finishes in a few minutes). Destinations are restricted to local / private addresses, and the payloads are only harmless strings for detection testing.

> `--time-scale 0.1` cuts wait times to 1/10 so the run finishes faster. Because this changes the "rhythm" of the requests,
> omit it when you want to examine the verdicts closely (default 1.0).

## 4. Look at the results

Open the following pages in the Web UI.

| Page | What to look at |
|---|---|
| Dashboard | Alert count, open incidents, number of AI sessions, response actions awaiting approval |
| AI sessions | AI score per source. AI-agent sessions rank at the top, labeled in purple as "AI agent" |
| Incidents | Alerts from the same source are grouped, with the attack stage (reconnaissance → initial access, and so on) and the LLM triage result attached |
| Alerts | Individual detections (SQL injection, scanners, decoy access, following an AI canary, and so on) |

## 5. Approve and block

1. Open the "Awaiting approval" tab on the **Response** page. It lists actions such as `block_ip` proposed by the LLM (or by rules).
2. **Approve** the `block_ip` for the AI agent's source IP.
3. Within a few seconds (the Gate's policy pull interval is 5 seconds by default), the Gate starts returning **403** to requests from that IP.

```bash
# Check after approval (<IP> is the source you approved)
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: <IP>" http://127.0.0.1:8080/   # → 403
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: 192.0.2.1" http://127.0.0.1:8080/  # → 200 (other IPs get through)
```

4. Click **Revert** on the "Active" tab to lift the block (even if you do nothing, it expires automatically after the TTL, 60 minutes by default).

Unless you approve them, proposed response actions are **never executed**.

## 6. Clean up

Press Ctrl-C in each terminal to stop everything. To delete the data and start over, delete `backend/data/`.

## What to read next

- Protect your own app: [Connecting sensors](Sensors-en)
- How to read the screens in detail: [Web UI guide](Web-UI-en)
- Day-to-day setup: [Installation & operations](Installation-en)
