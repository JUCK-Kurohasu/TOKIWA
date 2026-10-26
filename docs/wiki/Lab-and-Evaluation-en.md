> 🌐 [日本語](Lab-and-Evaluation) · **English** · [中文](Lab-and-Evaluation-zh) · [Español](Lab-and-Evaluation-es)

# Lab & evaluation

TOKIWA comes with a **lab environment**, an **attack traffic simulator**, and an **evaluation harness** for trying out detection.
It also provides the steps for a **purple-team exercise** against ARTEX on the attack side.

> ⚠️ Point the simulator and ARTEX **only at targets that you manage and are authorized to test**.

## Lab layout

```
 Simulator / ARTEX ──▶ Gate :8080 (capture + block) ──▶ Victim app :3000 (demo shop, no vulnerabilities)
                           │
                           ▼
                    TOKIWA :8788 (API + UI) ◀── Agent (optional: nginx JSON logs / host)
```

The **victim app** (`lab/victim/app.py`) looks like a demo shop with login, search, a product API, chat (`/api/chat`), OpenAPI, and more,
but **it is not actually vulnerable**. It has no DB, no file reads, and no shell; all responses are fixed.
However, to draw out the "adapting after errors" behavior of AI agents, it returns plausible errors
(an odd number of quotes → a 500 that looks like an SQL error, `<script` → a 403 that looks like a WAF, and so on). The top page has a lab AI canary
(disable it with `LAB_AI_CANARY=0`).

### Running without Docker (verified)

These are the steps in "3. Build a mini lab and send attacks" in [Quick start](Quick-Start-en).

### Running with Docker Compose

```bash
docker compose -f lab/compose.yaml up --build -d            # tokiwa + gate + victim
# Open http://localhost:8788 and create an admin the first time

docker compose -f lab/compose.yaml --profile sim run --rm sim                          # Default mix
SIM_PROFILE=ai_agent docker compose -f lab/compose.yaml --profile sim run --rm sim     # AI agents only
SIM_PROFILE=ai_agent=2,benign_browser=4 SIM_TIME_SCALE=0.2 docker compose -f lab/compose.yaml --profile sim run --rm sim
docker compose -f lab/compose.yaml --profile ingest run --rm sim-ingest                # Ingest directly without the Gate
docker compose -f lab/compose.yaml --profile agent up -d                               # nginx(:8081) + agent
docker compose -f lab/compose.yaml down                                                # Stop (-v also deletes the data)
```

To run with a real LLM, start it with variables such as `TOKIWA_LLM_PROVIDER=auto ANTHROPIC_API_KEY=... TOKIWA_LLM_BUDGET_USD=2`
(the lab's default daily budget is $1).

> ⏳ Only the syntax of `lab/compose.yaml` has been validated; starting it with `up` is not yet verified. If you run into problems, let us know in an Issue.

## Simulator (`tokiwa sim`)

| Profile | Ground-truth label | Behavior |
|---|---|---|
| `benign_browser` | Benign | An ordinary user shopping in a browser |
| `scanner` | Automated scanner | Mechanical scanning based on wordlists + signatures (constant rate) |
| `human_attacker` | Human | Tries SQLi / XSS by hand at a human pace |
| `ai_agent` | AI agent | An autonomous agent like ARTEX (API discovery from JS / OpenAPI, mutation after errors, bursts and thinking pauses, following canaries) |
| `llm_app_attacker` | Human | Prompt injection and jailbreaks against `/api/chat` |

```bash
cd backend
uv run tokiwa sim profiles
uv run tokiwa sim run --profile ai_agent --target http://localhost:8080
uv run tokiwa sim run --profile ai_agent=2,benign_browser=5 --seed 7 --record ../eval/datasets/live.jsonl
```

Safety limits:

- Destinations are limited to localhost, private IPs, and names that resolve to them. Anything else is rejected unless you add `--i-own-this-target`
  (use it only for targets you own and are authorized to test).
- Redirects are not followed, and proxy environment variables are not used. There are caps on the total number of requests (default 2,000) and the rate (default 50 rps).
- Payloads are harmless strings for detection testing (external references use the `.invalid` domain).

## Evaluation harness (`tokiwa eval`)

It runs a labeled dataset through TOKIWA's pipeline (ingest → detection → correlation → triage) and computes metrics.
Evaluation uses a throwaway DB, so it does not affect a running server. Detectors and the LLM are never shown the ground-truth labels.

```bash
cd backend
uv run tokiwa sim generate --out ../eval/datasets/mix.jsonl                  # Generate offline (the same seed gives an identical file)
uv run tokiwa eval run --dataset ../eval/datasets/lab-mini.jsonl             # Mock LLM (free, offline)
uv run tokiwa eval run --dataset ../eval/datasets/mix.jsonl --compare ../eval/runs/<previous> --fail-on-regression
uv run tokiwa eval run --dataset ../eval/datasets/mix.jsonl --llm live --budget-usd 0.50   # Real LLM (incurs cost)
uv run tokiwa eval compare ../eval/runs/<current> ../eval/runs/<previous>
```

Results are written to `eval/runs/<UTC time>/` as `metrics.json` and `report.md`.

| Metric | Meaning |
|---|---|
| Attack session detection rate | Share of attack sessions with at least one alert |
| False positive rate on benign sessions | Share of benign sessions that got an alert |
| Alert precision | Share of alerts attributed only to attack sessions (also reported per detector) |
| AI attribution P / R / F1 / AUC | Accuracy when classifying sessions as "AI agent or not" |
| LLM agreement rate | Share of triage verdicts (actor type, malicious, AI) that match the ground truth |
| Cost and latency | LLM cost; ingest → alert and alert → triage latency |

> The bundled dataset (`eval/datasets/lab-mini.jsonl`) is synthesized from the same hypotheses as the detectors. Expect the numbers here to
> **come out higher than in a real environment**.

## Purple-team exercise with ARTEX

The simulator's `ai_agent` is only a hypothetical model, so **validation against a real AI agent is what really counts**.

1. Start the lab (see above).
2. Start ARTEX. By default, ARTEX's traffic-recording proxy **uses :8788 and collides with TOKIWA**, so
   move ARTEX to other ports (for example, `./start.sh -addr :8787 -proxy :18788`).
3. Set the target of the ARTEX task to **only the lab Gate (`http://<lab host>:8080`)**.
4. What to watch in TOKIWA during the exercise:
   - **AI sessions**: whether ARTEX's sessions are classified as AI agents and get high scores
   - **Alerts**: `ai.agent_session`, `ai.adaptive_mutation`, `ai.semantic_recon`, `ai.llm_client_fingerprint`, `deception.trip`, and so on
   - **Incidents**: whether the actor attribution becomes AI agent and the attack stage progresses
   - **Response**: whether blocks and other actions **stop at the proposal stage** and are not executed until you approve them
5. Afterward, you can convert ARTEX's records into a dataset and re-evaluate as many times as you like.

```bash
cd backend
uv run tokiwa eval import-artex <directory where the ARTEX task archive was extracted> --host <lab host> \
  --out ../eval/datasets/artex-<date>.jsonl
uv run tokiwa sim generate --profile benign_browser=10 --out ../eval/datasets/benign.jsonl
cat ../eval/datasets/artex-<date>.jsonl ../eval/datasets/benign.jsonl > ../eval/datasets/purple-<date>.jsonl
uv run tokiwa eval run --dataset ../eval/datasets/purple-<date>.jsonl
```

`import-artex` can read task archives (`traffic/traffic.json`), evidence ZIPs, the recording index (SQLite), and API dumps.
Note that ARTEX records have a time resolution of 1 second and do not include the source IP (supply it with `--source-ip`).
TOKIWA only reads ARTEX's record format; it does not contain any ARTEX code.
