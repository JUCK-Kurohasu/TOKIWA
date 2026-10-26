> 🌐 [日本語](Installation) · **English** · [中文](Installation-zh) · [Español](Installation-es)

# Installation & operations (Docker Compose)

This is the setup for day-to-day, production-style use. A single Docker image contains the server (API + Web UI + background jobs)
and every other role: Gate, Agent, and simulator. If you only want to try TOKIWA on your machine, [Quick start](Quick-Start-en) is easier.

## Requirements

- Docker Engine **25 or later**, Docker Compose **v2.24 or later**
- x86_64 or arm64 (building on arm64 is not yet verified)
- Memory: from about 512 MB at lab scale

## Installation

```bash
git clone https://github.com/JUCK-Kurohasu/TOKIWA.git tokiwa && cd tokiwa
cp .env.example .env     # Uncomment only the lines you need
make up                  # = docker compose -f deploy/compose.yaml --env-file .env up -d --build --wait
```

1. Create the first administrator at <http://localhost:8788/setup> (with the CLI:
   `docker compose -f deploy/compose.yaml exec tokiwa tokiwa user create admin --role admin`; you enter the password interactively).
2. To use an LLM, add `ANTHROPIC_API_KEY=...` to `.env` (if it is not set, TOKIWA runs with the mock LLM).
3. By default, TOKIWA is exposed only on `127.0.0.1:8788`. To expose it on your LAN, set `TOKIWA_BIND=0.0.0.0` in `.env`, but
   **do not expose it without TLS**; put a reverse proxy (described below) in front of it.

> ⚠️ **Do not enable a setting with an empty value**. For example, `TOKIWA_SERVER__SECRET_KEY=` (empty) ends up being used as
> "a signing key that is an empty string". Leave settings you don't use commented out. If it is not set, the signing key is generated automatically on first start.

### Running with plain docker

```bash
make docker              # docker build -f deploy/Dockerfile -t tokiwa:local .
docker run -d --name tokiwa --init -p 127.0.0.1:8788:8788 -v tokiwa-data:/data tokiwa:local
```

### Default hardening (compose)

Read-only root filesystem (writes go only to `/data` and `/tmp`), all capabilities dropped,
`no-new-privileges`, a non-root user (uid/gid 10001), and log rotation (10 MB × 5).

## Running other roles with the same image

If the first argument to the container is one of `serve gate agent sim eval intel user token version`, it runs as the `tokiwa` command.

```bash
# API token for a sensor (shown only once)
docker compose -f deploy/compose.yaml exec tokiwa tokiwa token create gate-1

# Gate (the gate profile in compose; set TOKIWA_GATE__INGEST_TOKEN and TOKIWA_GATE__UPSTREAM in .env)
docker compose -f deploy/compose.yaml --env-file .env --profile gate up -d

# Host sensor (uses the host's PID / network namespaces so it can see the host's ports and processes)
docker run -d --name tokiwa-agent --pid host --network host -e TOKIWA_HEALTHCHECK_URL=none \
  -e TOKIWA_AGENT__INGEST_TOKEN=tkw_... -v /var/log/nginx:/var/log/nginx:ro tokiwa:local agent run
```

- Roles without HTTP (agent / sim) need `TOKIWA_HEALTHCHECK_URL=none`. The Gate's health check is
  `http://127.0.0.1:8080/__tokiwa/health`.
- The Agent may need root-equivalent privileges to read other users' process information (the image runs as non-root).
  If your goal is host monitoring, installing it directly on the host is the more straightforward option. For details, see [Connecting sensors](Sensors-en).

## Switching to PostgreSQL

SQLite is meant for labs and small deployments. If your event volume is large, use PostgreSQL. Set the following in `.env` and run `make up`.

```bash
COMPOSE_PROFILES=postgres
POSTGRES_USER=tokiwa
POSTGRES_PASSWORD=<output of openssl rand -hex 24>
TOKIWA_DATABASE__URL=postgresql+asyncpg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/tokiwa
```

- Tables are created automatically at startup. PostgreSQL is not exposed to the host (only inside the compose network).
- **There is no data migration tool from SQLite to PostgreSQL yet** (you start with a new DB).

## Placing it behind a reverse proxy

- **Serve it at the root of a domain (or subdomain)**. Serving it under a subpath such as `/tokiwa/` is not supported.
- Set `TOKIWA_SERVER__BASE_URL=https://tokiwa.example.internal` (it is used for links in notifications, among other things).
- For real-time updates (SSE: `/api/v1/stream`), **turn off buffering and set a long timeout**.
- If the proxy runs on a different host / container, set `FORWARDED_ALLOW_IPS=<proxy IP/CIDR>`.

nginx example:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name tokiwa.example.internal;
    client_max_body_size 20m;                  # For ingest batches from sensors

    location /api/v1/stream {
        proxy_pass http://127.0.0.1:8788;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_read_timeout 1h;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location / {
        proxy_pass http://127.0.0.1:8788;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Caddy example:

```caddyfile
tokiwa.example.internal {
    reverse_proxy 127.0.0.1:8788 {
        flush_interval -1
    }
}
```

If you add authentication such as SSO at the proxy, note that `/api/v1/ingest/events` and `/api/v1/gate/policy`, which the sensors use,
are authenticated with API tokens. Either exclude these paths, or point the sensors directly at :8788 over the internal network.

## Backup and restore

There are two things to keep: the **DB** and the **signing key `secret.key`** (both in `/data`). If you lose `secret.key`,
logged-in sessions become invalid (API tokens are not affected, because they are stored as hashes in the DB).

SQLite runs in WAL mode, so do not copy the files directly while it is running; use the online backup API instead.

```bash
C="docker compose -f deploy/compose.yaml"
$C exec -T tokiwa python -c "import sqlite3; s=sqlite3.connect('/data/tokiwa.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d); d.close(); s.close()"
mkdir -p backups
$C cp tokiwa:/data/backup.db  "backups/tokiwa-$(date +%F).db"
$C cp tokiwa:/data/secret.key "backups/secret-$(date +%F).key"
$C exec -T tokiwa rm /data/backup.db
```

To restore, replace the files while the container is stopped.

```bash
$C stop tokiwa
$C cp backups/tokiwa-YYYY-MM-DD.db  tokiwa:/data/tokiwa.db
$C cp backups/secret-YYYY-MM-DD.key tokiwa:/data/secret.key
$C run --rm --entrypoint sh tokiwa -c 'rm -f /data/tokiwa.db-wal /data/tokiwa.db-shm'
$C start tokiwa
```

For PostgreSQL, use `pg_dump -Fc` / `pg_restore`, and save `secret.key` separately.

## Upgrading

```bash
git pull
make up                  # Rebuild and replace (the /data volume is kept)
```

> ⚠️ **There is no automatic schema migration yet**. At startup, TOKIWA only "creates tables that don't exist";
> it does not add or change columns in existing tables. Always take a backup before upgrading.
> A migration tool (Alembic) is planned for the next development phase.

## Helper commands for development and operations (make)

| Command | Description |
|---|---|
| `make dev` | Start the API (:8788, auto-reload) and the UI (:5173) together |
| `make test` / `make lint` / `make build` | Tests / lint / UI build |
| `make up` / `make down` / `make logs` | Start / stop / logs for `deploy/compose.yaml` |
| `make lab` | Start the lab (`lab/compose.yaml`) |
| `make seed` | Load synthetic demo events into the local server (sends to localhost only) |
| `make docker` / `make docker-smoke` | Build the image / smoke test |
