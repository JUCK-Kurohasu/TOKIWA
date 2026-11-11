# TOKIWA security & operational-readiness audit — rules for every agent

You are one lane of a parallel audit of TOKIWA (LLM-driven SIEM/XDR that detects/defends against generative-AI-driven
attacks; counterpart of the AI pentest tool ARTEX). The owner wants every realistic problem that would appear when
TOKIWA faces real AI attack tools (ARTEX, ARES, PentAGI, Strix, ...) — detection gaps, operational problems, and
security vulnerabilities in TOKIWA itself. Findings will become GitHub issues after central review.

AUDIT_DIR = /tmp/claude-0/-home-user/75e76892-3678-5d8e-a1e7-d43782811556/scratchpad/audit
Repo (main @ 19f0252): /home/user/TOKIWA   ARTEX source (AGPL, read-only): /home/user/artex-jp

## 1. Hard rules
1. **The repo checkout is shared and read-only for you.** Never edit files in /home/user/TOKIWA, never run
   `git checkout/stash/commit/branch/reset` there, never `uv sync` / `npm install` / `npm run build` there.
   Run backend code with `cd /home/user/TOKIWA/backend && uv run --no-sync <cmd>` or `/home/user/TOKIWA/backend/.venv/bin/python`.
   For PoC patches, copy what you need into your own dir (e.g. `cp -r /home/user/TOKIWA/backend/src $MYDIR/src` and run
   with `PYTHONPATH=$MYDIR/src /home/user/TOKIWA/backend/.venv/bin/python ...`). The built UI is at /home/user/TOKIWA/frontend/dist.
2. **Your own directory and ports only.** MYDIR = $AUDIT_DIR/agents/<lane>/ (create it). Use only the port range assigned
   in your prompt. Data dirs, logs, venvs, scratch files go under MYDIR.
3. **Process hygiene.** Record the PID of every process you start and kill only those PIDs (`kill <pid>`).
   NEVER use `pkill -f` / `killall` / `pgrep -f ... | xargs kill`: the pattern matches your own shell and kills it.
   Stop everything you started before you finish.
4. **Targets are localhost only.** Never send attack traffic to any external host. External network = reading only
   (WebSearch / WebFetch tools, `pip install`/`npm` from public registries). api.github.com and git clones of other
   repos are blocked by the proxy; use WebFetch on github.com pages or raw.githubusercontent.com instead.
5. **No GitHub writes, no pushes, no issue creation.** Only the orchestrator files issues.
6. **No live LLM calls.** Always `TOKIWA_LLM__PROVIDER=mock`. If a finding can only be confirmed with a real model,
   say so (confidence `hypothesis`, add `"needs-live-llm"` to `related`).
7. **ARTEX is AGPL-3.0:** cite files/lines (`/home/user/artex-jp/agent/x.go:120`), describe behaviour; never paste its code.
8. **No secrets in findings** (don't print secret.key, tokens you generate, passwords).
9. **CPU is shared** (4 cores, ~14 agents). Keep load tests short and only when your lane is about load.

## 2. How to run TOKIWA locally (pattern)
```bash
B=/home/user/TOKIWA/backend; D=$MYDIR/run1; mkdir -p $D/data
export TOKIWA_SERVER__DATA_DIR=$D/data TOKIWA_DATABASE__URL=sqlite+aiosqlite:///$D/data/tokiwa.db \
       TOKIWA_SERVER__STATIC_DIR=/home/user/TOKIWA/frontend/dist TOKIWA_LLM__PROVIDER=mock
cd $B && nohup uv run --no-sync tokiwa serve --port <P1> > $D/server.log 2>&1 & echo $! > $D/server.pid
# admin: POST http://127.0.0.1:<P1>/api/v1/auth/setup {"username":"admin","password":"<random>=10+ chars"} -> access_token
# token (same env!): uv run --no-sync tokiwa token create gate-1   (prints tkw_... once; keep it in a 600 file)
# victim: cd /home/user/TOKIWA/lab/victim && $B/.venv/bin/uvicorn app:app --host 127.0.0.1 --port <P2>
# gate: uv run --no-sync tokiwa gate run --upstream http://127.0.0.1:<P2> --listen 127.0.0.1:<P3> \
#       --server http://127.0.0.1:<P1> --token-file <file> [--trust-forwarded-for]
# traffic: uv run --no-sync tokiwa sim run --target http://127.0.0.1:<P3> --time-scale 0.1 --spoof-xff ...
# offline: uv run --no-sync tokiwa sim generate --out f.jsonl ...; uv run --no-sync tokiwa eval run --dataset f.jsonl --llm mock --out <dir>
```
API docs: http://127.0.0.1:<P1>/api/docs. Key docs: HANDOFF.md, AGENTS.md, docs/architecture.md, docs/api-contract.md,
docs/gate.md, docs/deception.md, docs/response.md, docs/detection/*.md, docs/security/llm-safety.md, docs/tasks/wave2-*.md.

## 3. Before reporting something as new
Read HANDOFF.md and docs/tasks/wave2-*.md (planned work) and grep `TODO(verify)`. If a finding is already planned or
known, still report it if you have new evidence, but set `"known"` to e.g. `"wave2-feature-gaps"` / `"HANDOFF"` /
`"TODO(verify)"`.

## 4. Output: append findings to $AUDIT_DIR/findings/<lane>.jsonl AS YOU GO
One JSON object per line, UTF-8, written with Python `json.dumps(obj, ensure_ascii=False)` (never hand-quote JSON).
Write each finding as soon as it is solid — do not hold them until the end (rate limits may stop you mid-way).
Fields (Japanese for prose fields; code/paths/commands as-is):
```json
{"id":"<lane>-01","title":"短い日本語タイトル（何が・どうなる）","area":"gate|aidetect|deception|detect-web|sigma|api|auth|llm|triage|correlate|respond|notify|intel|sensors|frontend|ops|deploy|ci|eval|docs|other",
 "category":"security|detection-gap|robustness|reliability|performance|ops|ux|docs|testing",
 "severity":"critical|high|medium|low|info","confidence":"confirmed|likely|hypothesis",
 "summary":"何が問題か（2-5文）",
 "evidence":"根拠: file:line、再現コマンドと観測結果（要点のみ。長いログは MYDIR に置きパスを書く）",
 "attack_scenario":"現実の攻撃者/AIエージェント（ARTEX, ARES 等）がどう突くか、または運用で何が起きるか",
 "recommendation":"推奨対応（具体的に）","effort":"S|M|L","known":"none|wave2-xxx|HANDOFF|TODO(verify)",
 "references":["https://..."],"related":["他の論点やID"]}
```
Confidence: `confirmed` = you reproduced it (command + observed output in evidence); `likely` = code path traced
(file:line) but not executed; `hypothesis` = plausible, needs verification. Severity guide:
- critical: unauthenticated compromise of TOKIWA / the protected app, or TOKIWA's core purpose defeated by default with
  trivial effort, and reproduced.
- high: privilege escalation, attacker-controlled defender actions (e.g. framing an innocent IP into a block), reliable
  evasion of a major detection class, secret exposure, easy DoS of gate/server.
- medium: partial evasion, needs specific config, plausible defense-in-depth gap.  low: hardening/edge cases.  info: notes.
Do not inflate. One root cause = one finding (list variants inside it). Repro steps: minimal, no turnkey weaponized payloads.

## 5. Final message (< 400 words)
Number of findings by severity, the 3-5 most important ones (id + one line), what you could not test and why,
and the path of your JSONL file.
