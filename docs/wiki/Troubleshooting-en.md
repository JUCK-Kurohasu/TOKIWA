> 🌐 [日本語](Troubleshooting) · **English** · [中文](Troubleshooting-zh) · [Español](Troubleshooting-es)

# Troubleshooting

## Startup and login

**Opening it in a browser gives a 404 / only the API is visible**
The UI has not been built, or where to serve it from is not configured. After `cd frontend && npm run build`,
start the server with `TOKIWA_SERVER__STATIC_DIR=../frontend/dist`. During development, `make dev` (UI on :5173) also works.
In the Docker image, check that you haven't overridden `TOKIWA_SERVER__STATIC_DIR` (default `/app/frontend/dist`).

**The login screen appears instead of the admin setup screen on first start**
The first-time admin setup screen (/setup) is shown only while the server's database has no users at all. Check the state first.

```bash
curl -s http://localhost:8788/api/v1/auth/status
```

- `{"setup_required":false,...}` → the database already has a user (data from an earlier setup is still there).
  Log in with that account, wipe it with "I want to reset everything" below, or create another admin as described above.
- `{"setup_required":true,...}` → reopen `http://localhost:8788/` in the browser. Older versions of the UI stayed on the login screen
  when `/login` was opened directly, even when setup was needed (it now redirects to /setup).
- No connection → the server is not running (`cd backend && uv run tokiwa serve`). Older versions of the UI also showed the login screen
  when the API was unreachable (it now shows "Cannot reach the server").

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

**I want to reset everything (start over)**
⚠️ This deletes all events, alerts, users, API tokens and the signing key. Sensors need new tokens afterwards.

```bash
# Running from source: stop the server first
rm -rf backend/data            # or wherever TOKIWA_SERVER__DATA_DIR / TOKIWA_DATABASE__URL point

# Docker Compose (deploy/compose.yaml): -v also deletes the volumes (tokiwa-data, postgres-data)
docker compose -f deploy/compose.yaml down -v && make up

# Lab (lab/compose.yaml): the lab tokens are recreated too
docker compose -f lab/compose.yaml down -v && docker compose -f lab/compose.yaml up --build -d
```

With an external PostgreSQL, drop and recreate the database. After the restart the UI opens on the setup screen.
Old login data left in the browser becomes invalid because the signing key changes (clear the site data if you like).

**I get errors after upgrading**
v0.1 has no automatic schema migration. Check the release notes and `HANDOFF.md` for schema changes and,
if necessary, restore from a backup.

---

If this doesn't solve your problem, let us know in an [Issue](https://github.com/JUCK-Kurohasu/TOKIWA/issues), including the commands you ran, logs (**with secrets redacted**), and your environment.
