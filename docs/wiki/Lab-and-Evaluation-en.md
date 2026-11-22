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
# Open http://localhost:8788 and create an admin the first time (setup code: docker compose -f lab/compose.yaml logs tokiwa)

docker compose -f lab/compose.yaml --profile sim run --rm sim                          # Default mix
SIM_PROFILE=ai_agent docker compose -f lab/compose.yaml --profile sim run --rm sim     # AI agents only
SIM_PROFILE=ai_agent=2,benign_browser=4 SIM_TIME_SCALE=0.2 docker compose -f lab/compose.yaml --profile sim run --rm sim
docker compose -f lab/compose.yaml --profile ingest run --rm sim-ingest                # Ingest directly without the Gate
docker compose -f lab/compose.yaml --profile agent up -d                               # nginx(:8081) + agent
docker compose -f lab/compose.yaml down                                                # Stop (-v also deletes the data)
```

To run with a real LLM, start it with variables such as `TOKIWA_LLM_PROVIDER=auto ANTHROPIC_API_KEY=... TOKIWA_LLM_BUDGET_USD=2`
(the lab's default daily budget is $1).

> ✅ **Verified (2026-11-10, audit L14, in a sandbox; Docker / Compose versions were not recorded)**: with `up -d`,
> `tokiwa-init` exits normally and `tokiwa` / `gate` / `victim` become healthy; initial setup in the UI; and from the `sim` of
> `--profile sim`: alerts → incident → response proposal → approval → block at the Gate (403). The block took about 4–8 seconds
> to take effect after approval.
>
> ⚠️ In that environment a plain `up --build` failed because of Docker Hub rate limiting (429), a 403 from ghcr.io, and a
> TLS-intercepting proxy. The lab was started after replacing the base images through build arguments (`NODE_IMAGE` /
> `PYTHON_IMAGE` / `UV_IMAGE`) and re-tagging the victim's base image by hand (details under "検証状況" in `lab/README.md`).
> **Not verified**: `--profile ingest` and `--profile agent`, and running with a real LLM.

## Simulator (`tokiwa sim`)

| Profile | Ground-truth label | Behavior |
|---|---|---|
| `benign_browser` | Benign | An ordinary user shopping in a browser |
| `scanner` | Automated scanner | Mechanical scanning based on wordlists + signatures (constant rate) |
| `human_attacker` | Human | Tries SQLi / XSS by hand at a human pace |
| `ai_agent` | AI agent | An autonomous agent like ARTEX (API discovery from JS / OpenAPI, mutation after errors, bursts and thinking pauses, following canaries) |
| `llm_app_attacker` | Human | Prompt injection and jailbreaks against `/api/chat` |
| `api_only_agent` | AI agent (holdout) | An LLM tool loop that only calls the API (starts from OpenAPI, never touches HTML, robots or canaries, one request per turn, generic HTTP-client UA) |
| `slow_rotating_agent` | AI agent (holdout) | A browser-driven agent (full Chrome headers), reasoning pauses with a median of about 20 seconds, source IP changing every few requests |

**Holdout profiles** have shapes that were not used to design or tune the detectors, and they are not in the default mix. Name them explicitly (`--profile api_only_agent=2,...`) or include them with `--profile all --sessions N`. Evaluation results report them separately from the scripted profiles. IP rotation is visible to the Gate only with `--spoof-xff`.

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
| Attack session detection rate (medium or higher) | **Primary metric**. Share of attack sessions with at least one alert of medium severity or higher |
| Attack session detection rate (any severity) | Secondary metric. Counts a session as detected even with a single info / low alert |
| False positive rate on benign sessions | Share of benign sessions that got an alert |
| Alert precision | Share of alerts attributed only to attack sessions (also reported per detector) |
| AI attribution P / R / F1 / AUC | Accuracy when classifying sessions as "AI agent or not" |
| LLM agreement rate | Share of triage verdicts (actor type, malicious, AI) that match the ground truth |
| Cost and latency | LLM cost; ingest → alert and alert → triage latency |

Every rate is reported with its numerator / denominator and a 95% interval (Clopper–Pearson); values from fewer than 30 trials
are shown as **reference values** (参考値) in `report.md` (the bundled lab-mini has 3 benign and 2 AI sessions, so "0/3 false
positives" has an interval of 0–70.8%). With `--llm mock`, the "LLM agreement rate" is the rule-based fallback agreeing with
itself and **is not LLM quality**; cost is shown as the actual $0 plus a separate estimate (estimated tokens × price table).
`--compare` warns that two runs are "not comparable" when their conditions differ (dataset sha256, LLM provider, enabled
detectors, number of Sigma rules loaded, thresholds), and `--fail-on-regression` then exits with code 3 (use `--allow-mismatch`
for an intended comparison). The total alert count and the count per detector are compared as well.

> The bundled dataset (`eval/datasets/lab-mini.jsonl`) is synthesized from the same hypotheses as the detectors. Expect the numbers here to
> **come out higher than in a real environment**.

## Purple-team exercise with ARTEX

The simulator's `ai_agent` is only a hypothetical model, so **validation against a real AI agent is what really counts**.

1. Start the lab (see above).
2. Start ARTEX. By default, ARTEX's traffic-recording proxy **uses :8788 and collides with TOKIWA**, so
   move ARTEX to other ports (for example, `./start.sh -addr :8787 -proxy :18788`).
3. **Before creating the task**, turn on traffic recording (setting key `traffic_capture`) and LLM recording (`llm_record`) in
   ARTEX's system settings, and clear earlier records for the target host. Both recordings are OFF by default, and with them OFF no
   data is left for the post-exercise evaluation. ARTEX keeps records per host, not per task (details in `docs/purple-team.md` §2).
4. Set the target of the ARTEX task to **only the lab Gate (`http://<lab host>:8080`)**.
5. What to watch in TOKIWA during the exercise:
   - **AI sessions**: whether ARTEX's sessions are classified as AI agents and get high scores
   - **Alerts**: `ai.agent_session`, `ai.adaptive_mutation`, `ai.semantic_recon`, `ai.llm_client_fingerprint`, `deception.trip`, and so on
   - **Incidents**: whether the actor attribution becomes AI agent and the attack stage progresses
   - **Response**: whether blocks and other actions **stop at the proposal stage** and are not executed until you approve them
6. Afterward, you can convert ARTEX's records into a dataset and re-evaluate as many times as you like.

```bash
cd backend
uv run tokiwa eval import-artex <directory where the ARTEX task archive was extracted> --host <lab host> \
  --since <exercise start UTC> --until <exercise end UTC> --split-gap-minutes 30 --out ../eval/datasets/artex-<date>.jsonl
uv run tokiwa sim generate --profile benign_browser=10 --out ../eval/datasets/benign.jsonl
cat ../eval/datasets/artex-<date>.jsonl ../eval/datasets/benign.jsonl > ../eval/datasets/purple-<date>.jsonl
uv run tokiwa eval run --dataset ../eval/datasets/purple-<date>.jsonl
```

`import-artex` can read task archives (`traffic/traffic.json`), evidence ZIPs, the recording index (SQLite), and API dumps.
ARTEX record times are **response-completion times with 1-second resolution**, and the records do not include the source IP
(supply it with `--source-ip`). Gaps and bursts of imported events are approximations, so judge request rhythm on the Gate's live
capture from the exercise. Header order is not meaningful either. Narrow the time window with `--since` / `--until`, and split
sessions at silent gaps with `--split-gap-minutes`. When nothing is imported, the command tells you whether recording was probably
OFF, which hosts were present, and which time range the records cover.
TOKIWA only reads ARTEX's record format; it does not contain any ARTEX code.
