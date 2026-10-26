> 🌐 [日本語](Troubleshooting) · **English** · [中文](Troubleshooting-zh) · [Español](Troubleshooting-es)

# Troubleshooting

## Startup and login

**Opening it in a browser gives a 404 / only the API is visible**
The UI has not been built, or where to serve it from is not configured. After `cd frontend && npm run build`,
start the server with `TOKIWA_SERVER__STATIC_DIR=../frontend/dist`. During development, `make dev` (UI on :5173) also works.
In the Docker image, check that you haven't overridden `TOKIWA_SERVER__STATIC_DIR` (default `/app/frontend/dist`).

**I forgot the admin password**
With the same configuration as the server, run `uv run tokiwa user create <new name> --role admin` to create another admin,
then change the original account's password with "Reset password" under **Settings → Users**.

**I was logged out after a restart**
The signing key (`data/secret.key`) may have been lost. Check that the data directory is persisted.

## Sensors and ingest

**Events don't arrive even though traffic goes through the Gate**
1. Check the Gate's logs for 401 / 403 errors on ingest (wrong token, missing scope, revoked token).
   The token needs both the `ingest` and `gate` scopes.
2. Check that `--server` is a URL that reaches the TOKIWA server.
3. Run `curl http://127.0.0.1:8080/__tokiwa/health` on the host running the Gate to see send statistics
   (sent, dropped, and so on).

**A token created with `tokiwa token create` is rejected as "invalid token"**
The command and the server may be looking at different DBs. The default DB path (`./data/tokiwa.db`) is relative, so
run the command in the same directory as the server (`backend/`) with the same environment variables. With Docker, use
`docker compose ... exec tokiwa tokiwa token create ...`.

**All traffic appears to come from the same IP (the load balancer's IP)**
If the Gate is behind a load balancer, set `--trust-forwarded-for` (`TOKIWA_GATE__TRUST_FORWARDED_FOR=true`).
Use it **only behind a trusted load balancer**. In any other environment, the source IP can be spoofed.

**WebSocket stopped working**
Gate v0.1 does not support WebSocket (it returns 501). Route WebSocket paths so that they bypass the Gate.

## Response

**I approved an action, but nothing is blocked**
- By default, the Gate pulls its policy every 5 seconds. Wait a moment, then check again.
- Check whether the response action's status is `failed`. If it overlaps a protected range (`response.protected_cidrs`) or the server's own IP,
  it fails during the re-validation right before execution.
- Check that the blocked IP matches the source IP the Gate sees (if the Gate is behind a load balancer, see the item above).

**There are too many response actions awaiting approval**
Proposals of the same type for the same target are merged into one, but they are still created per source. Raise the minimum severity sent to the LLM
(`triage.min_severity_for_llm`), or reject proposals that are clearly unnecessary. You can disable detectors that produce many false positives
under **Rules → Detectors**.

## LLM

**The LLM isn't being used (you get mock responses)**
Check the provider and whether it is available in "Current status" under **LLM → Settings**. With `auto`, the provider becomes `mock` if there is no Anthropic API key.
Check that you set `ANTHROPIC_API_KEY` before starting the server, or that you entered a key in the UI, and run the **Connection test**.

**LLM triage stopped partway through**
You may have used up the daily budget (`llm.daily_budget_usd`, default $5). For the rest of that day, TOKIWA switches to rule-based verdicts.
Check **LLM → Usage**.

**The LLM refused to respond (refusal)**
Refusals by the model's safety features are treated as normal behavior. That alert falls back to rule-based verdicts.
You can check the status in **LLM → Call log**.

## Vulnerability intelligence

**Syncing fails**
The environment running TOKIWA needs outbound connections to each service (NVD, CISA, FIRST, OSV, JVN, GitHub, and so on).
Without an API key, NVD's rate limits are stricter, and GitHub is also more reliable with a token.
JVN may not be retrievable because of a revamp on the provider side (not yet verified).

## Docker

**`PermissionError: /data/...` or "/data is not writable"**
The container runs as uid 10001. If you use a bind mount, change the ownership of the host directory with
`sudo chown -R 10001:10001 <dir>` (named volumes get the correct ownership automatically).

**The container becomes `unhealthy`**
Check the cause with `docker inspect --format '{{json .State.Health}}' <container>`. For roles without HTTP (agent / sim), set
`TOKIWA_HEALTHCHECK_URL=none`; for the Gate, set it to `http://127.0.0.1:8080/__tokiwa/health`.

**Real-time updates stop behind a reverse proxy**
Turn off buffering for SSE (`/api/v1/stream`) and set a long read timeout (see the nginx example in [Installation & operations](Installation-en)).

## Data

**I want to start over**
Stop the server and delete the data directory (`backend/data/` when running from source; the volume when using Docker).

**I get errors after upgrading**
v0.1 has no automatic schema migration. Check the release notes and `HANDOFF.md` for schema changes and,
if necessary, restore from a backup.

---

If this doesn't solve your problem, let us know in an [Issue](https://github.com/JUCK-Kurohasu/TOKIWA/issues), including the commands you ran, logs (**with secrets redacted**), and your environment.
