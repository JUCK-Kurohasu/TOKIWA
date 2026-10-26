> 🌐 [日本語](Installation) · [English](Installation-en) · **中文** · [Español](Installation-es)

# 安装与运维（Docker Compose）

这是用于长期运行、接近生产环境的配置。一个 Docker 镜像中包含了服务器（API + Web UI + 后台作业）以及
Gate、Agent、模拟器的全部角色。如果只是在本机试用，[快速开始](Quick-Start-zh) 更简单。

## 要求

- Docker Engine **25 及以上**、Docker Compose **v2.24 及以上**
- x86_64 或 arm64（arm64 上的构建尚未验证）
- 内存：实验环境规模下约 512 MB 起

## 安装

```bash
git clone https://github.com/JUCK-Kurohasu/TOKIWA.git tokiwa && cd tokiwa
cp .env.example .env     # 只取消注释需要的行
make up                  # = docker compose -f deploy/compose.yaml --env-file .env up -d --build --wait
```

1. 在 <http://localhost:8788/setup> 创建第一个管理员（使用 CLI 时：
   `docker compose -f deploy/compose.yaml exec tokiwa tokiwa user create admin --role admin`。密码以交互方式输入）。
2. 如需使用 LLM，在 `.env` 中写入 `ANTHROPIC_API_KEY=...`（未设置时以模拟 LLM 运行）。
3. 默认只在 `127.0.0.1:8788` 上公开。若要对局域网公开，可在 `.env` 中设置 `TOKIWA_BIND=0.0.0.0`，但
   **不要在没有 TLS 的情况下公开**，请在前面放置后文所述的反向代理。

> ⚠️ **不要用空值启用设置**。例如 `TOKIWA_SERVER__SECRET_KEY=`（空）会被当作“空字符串签名密钥”使用。
> 不使用的项目请保持注释状态。未设置时，签名密钥会在首次启动时自动生成。

### 单独用 docker 运行

```bash
make docker              # docker build -f deploy/Dockerfile -t tokiwa:local .
docker run -d --name tokiwa --init -p 127.0.0.1:8788:8788 -v tokiwa-data:/data tokiwa:local
```

### 默认加固措施（compose）

只读根文件系统（仅 `/data` 和 `/tmp` 可写）、删除全部 capabilities、
`no-new-privileges`、非 root 用户（uid/gid 10001）、日志轮转（10 MB × 5）。

## 用同一镜像运行其他角色

如果容器的第 1 个参数是 `serve gate agent sim eval intel user token version` 之一，就会作为 `tokiwa` 命令执行。

```bash
# 传感器用 API 令牌（仅显示一次）
docker compose -f deploy/compose.yaml exec tokiwa tokiwa token create gate-1

# Gate（compose 的 gate profile。在 .env 中设置 TOKIWA_GATE__INGEST_TOKEN 和 TOKIWA_GATE__UPSTREAM）
docker compose -f deploy/compose.yaml --env-file .env --profile gate up -d

# 主机传感器（为了查看主机的端口和进程，使用 host 的 PID / 网络命名空间）
docker run -d --name tokiwa-agent --pid host --network host -e TOKIWA_HEALTHCHECK_URL=none \
  -e TOKIWA_AGENT__INGEST_TOKEN=tkw_... -v /var/log/nginx:/var/log/nginx:ro tokiwa:local agent run
```

- 没有 HTTP 的角色（agent / sim）需要加上 `TOKIWA_HEALTHCHECK_URL=none`。Gate 的健康检查地址是
  `http://127.0.0.1:8080/__tokiwa/health`。
- Agent 读取其他用户的进程信息时，可能需要相当于 root 的权限（镜像以非 root 运行）。
  如果目的是监控主机，直接安装在主机上会更简单。详情请参阅 [接入传感器](Sensors-zh)。

## 切换到 PostgreSQL

SQLite 适用于实验环境到小规模场景。事件量较大时请使用 PostgreSQL。在 `.env` 中设置以下内容后执行 `make up`。

```bash
COMPOSE_PROFILES=postgres
POSTGRES_USER=tokiwa
POSTGRES_PASSWORD=<openssl rand -hex 24 的输出>
TOKIWA_DATABASE__URL=postgresql+asyncpg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/tokiwa
```

- 表会在启动时自动创建。PostgreSQL 不会暴露到主机（仅在 compose 网络内可访问）。
- 从 SQLite 到 PostgreSQL 的 **数据迁移工具目前还没有**（需要从新的数据库开始）。

## 部署在反向代理之后

- 请 **在域名（或子域名）的根路径下公开**。尚不支持在 `/tokiwa/` 这类子路径下提供服务。
- 设置 `TOKIWA_SERVER__BASE_URL=https://tokiwa.example.internal`（用于通知中的链接等）。
- 实时更新（SSE：`/api/v1/stream`）需要 **关闭缓冲并延长超时**。
- 如果代理位于其他主机 / 其他容器，请设置 `FORWARDED_ALLOW_IPS=<代理的 IP/CIDR>`。

nginx 示例：

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name tokiwa.example.internal;
    client_max_body_size 20m;                  # 用于传感器发来的摄取批次

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

Caddy 示例：

```caddyfile
tokiwa.example.internal {
    reverse_proxy 127.0.0.1:8788 {
        flush_interval -1
    }
}
```

如果在代理上叠加 SSO 等认证：传感器使用的 `/api/v1/ingest/events` 和 `/api/v1/gate/policy`
通过 API 令牌认证，因此请将这些路径排除在外，或者让传感器经由内部网络直接访问 :8788。

## 备份与恢复

需要保存的是 **数据库** 和 **签名密钥 `secret.key`** 这两样（都位于 `/data`）。丢失 `secret.key` 会导致
已登录的会话失效（API 令牌是数据库中的哈希值，因此不受影响）。

SQLite 使用 WAL 模式，因此不要在运行中直接复制文件，而应使用在线备份 API。

```bash
C="docker compose -f deploy/compose.yaml"
$C exec -T tokiwa python -c "import sqlite3; s=sqlite3.connect('/data/tokiwa.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d); d.close(); s.close()"
mkdir -p backups
$C cp tokiwa:/data/backup.db  "backups/tokiwa-$(date +%F).db"
$C cp tokiwa:/data/secret.key "backups/secret-$(date +%F).key"
$C exec -T tokiwa rm /data/backup.db
```

恢复时在停止状态下替换文件。

```bash
$C stop tokiwa
$C cp backups/tokiwa-YYYY-MM-DD.db  tokiwa:/data/tokiwa.db
$C cp backups/secret-YYYY-MM-DD.key tokiwa:/data/secret.key
$C run --rm --entrypoint sh tokiwa -c 'rm -f /data/tokiwa.db-wal /data/tokiwa.db-shm'
$C start tokiwa
```

使用 PostgreSQL 时，请使用 `pg_dump -Fc` / `pg_restore`，并另行保存 `secret.key`。

## 升级

```bash
git pull
make up                  # 重新构建并替换（保留 /data 卷）
```

> ⚠️ **目前还没有 Schema 的自动迁移（migration）**。启动时只会“创建不存在的表”，
> 不会对已有表的列进行添加或修改。升级前请务必备份。
> 迁移工具（Alembic）计划在下一个开发阶段引入。

## 开发与运维辅助命令（make）

| 命令 | 内容 |
|---|---|
| `make dev` | 同时启动 API（:8788，自动重载）和 UI（:5173） |
| `make test` / `make lint` / `make build` | 测试 / Lint / UI 构建 |
| `make up` / `make down` / `make logs` | `deploy/compose.yaml` 的启动、停止、日志 |
| `make lab` | 启动实验环境（`lab/compose.yaml`） |
| `make seed` | 向本地服务器投放演示用的合成事件（发送目标仅限 localhost） |
| `make docker` / `make docker-smoke` | 镜像构建 / 冒烟测试 |
