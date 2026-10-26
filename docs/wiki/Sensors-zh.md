> 🌐 [日本語](Sensors) · [English](Sensors-en) · **中文** · [Español](Sensors-es)

# 接入传感器

TOKIWA 服务器不会自己去收集数据，而是分析 **传感器发送过来的事件**。
传感器有 3 种，可以组合使用。

| 传感器 | 可见内容 | 适用场景 |
|---|---|---|
| **TOKIWA Gate** | HTTP 请求的全部内容（**包括请求体**）及响应状态 | 保护 Web 应用和 API。封禁和诱饵也由 Gate 执行 |
| **TOKIWA Agent** | 主机的监听端口与连接、nginx / Caddy 的 JSON 日志、Suricata、Zeek | 监控服务器、接入现有日志 |
| **摄取 API（直接）** | 您自己发送的内容（LLM 应用的提示词等） | 自定义集成 |

## API 令牌

传感器不使用用户登录，而是通过 **API 令牌** 认证。

```bash
cd backend
uv run tokiwa token create gate-1                    # 默认作用域：ingest + gate
uv run tokiwa token create agent-web01 --scope ingest
```

| 作用域（scope） | 允许的操作 |
|---|---|
| `ingest` | 发送事件（`POST /api/v1/ingest/events`） |
| `gate` | 获取 Gate 策略（`GET /api/v1/gate/policy`） |
| `read` | 预留（v0.1 中尚无可使用此作用域的 API） |

- 令牌（`tkw_...`）**仅在创建时显示一次**。数据库中只保存其哈希值。
- 也可以在 Web UI 的 **Settings → API tokens**（设置 → API 令牌，仅限管理员）中创建和吊销。
- 通过命令行参数传递时，其他用户可以通过 `ps` 看到，因此请 **通过环境变量或文件** 传递。

## TOKIWA Gate（反向代理型传感器）

这是放在要保护的 Web 应用前面的反向代理。它能捕获访问日志中看不到的请求体，
并立即应用服务器下发的策略（封禁、速率限制、tarpit、诱饵）。

```
客户端       ──▶ Gate (:8080) ──▶ 要保护的应用
                   │ 发送事件 / 获取策略（默认每 5 秒）
                   ▼
              TOKIWA Server (:8788)
```

### 启动

```bash
cd backend
export TOKIWA_GATE__INGEST_TOKEN=tkw_...          # 或使用 --token-file <path>
uv run tokiwa gate run --upstream http://127.0.0.1:3000 --listen 0.0.0.0:8080 --server http://127.0.0.1:8788
```

然后修改 DNS 或负载均衡器的指向，让用户今后访问 Gate（:8080）。

### 主要设置

设置的优先级为“CLI 参数 > 环境变量 `TOKIWA_GATE__*` > `tokiwa.yaml` > 默认值”。

| 设置 | CLI | 默认 | 说明 |
|---|---|---|---|
| upstream | `--upstream` | `http://127.0.0.1:3000` | 转发目标。也可以带路径前缀（`http://app/base`） |
| listen | `--listen host:port` | `0.0.0.0:8080` | 监听地址 |
| server_url | `--server` | `http://127.0.0.1:8788` | TOKIWA 服务器 |
| ingest_token | `--token` / `--token-file` | 无 | 需要 `ingest` 和 `gate` 作用域 |
| capture_body_bytes | `--capture-body-bytes` | 4096 | 捕获请求体的前多少字节（0 表示不捕获） |
| policy_refresh_seconds | `--policy-refresh` | 5.0 | 拉取策略的间隔 |
| trust_forwarded_for | `--trust-forwarded-for` | false | 将 `X-Forwarded-For` 的 **最右端** 作为来源 IP |

仅 CLI 提供的运维参数：`--upstream-timeout`（30 秒）、`--max-queue`（待发送事件上限 10,000 条）、
`--preserve-host / --rewrite-host`、`--access-log`。

### 需要了解的行为

- **`--trust-forwarded-for` 只能在可信的负载均衡器之后** 使用。不加此选项时，客户端发送的
  `X-Forwarded-*` 会被丢弃，并替换为 Gate 观测到的值（以防止伪造来源 IP）。
- 捕获的数据会 **在发送前由 Gate 端脱敏**（`Authorization`、`Cookie` 等请求头的值，
  `password=` 等参数的值，以及令牌、密钥、电子邮件地址等）。
- **fail-open**：即使 TOKIWA 服务器停止，Gate 的代理功能也不会停止（事件会暂时缓存并重新发送）。
- **fail-static**：无法获取策略时，保持最后一次的策略（以免出现“让服务器宕机就能解除封禁”这样的漏洞）。
- 健康检查：`GET /__tokiwa/health` → `{"status":"ok"}`。对来自本地 / 私有 IP 的请求，还会返回发送统计等信息。
- 不支持：WebSocket（返回 501）、HTTP/2 上游、gRPC。Gate 以单进程运行为前提。

## TOKIWA Agent（主机传感器、日志转发）

```bash
cd backend
export TOKIWA_AGENT__INGEST_TOKEN=tkw_...
uv run tokiwa agent run --server-url http://tokiwa.example.internal:8788 \
  --nginx /var/log/nginx/tokiwa.json.log \
  --suricata /var/log/suricata/eve.json
```

| 采集对象 | 选项 | 内容 |
|---|---|---|
| 主机 | `--host-sensor`（默认 ON）、`--connections`（默认 ON）、`--interval` | 监听端口列表及其变化、新的 TCP 连接 |
| nginx | `--nginx <path>`（可多次指定） | JSON 格式的访问日志（格式见仓库中的 `lab/nginx/tokiwa-json.conf`） |
| Caddy | `--caddy <path>` | JSON 访问日志 |
| Suricata | `--suricata <path>` | `eve.json` |
| Zeek | `--zeek-dir <path>` | 日志目录或单个文件 |

- 日志默认 **从末尾** 开始读取（使用 `--from-beginning` 则从开头读取）。
- 检查运行情况时，`tokiwa agent once --print`（只采集一次，不发送，而是显示 JSON）很方便。
- 读取其他用户的进程信息时，可能需要相当于 root 的权限。
- 端口首次快照中发现的监听，在默认设置（`agent.ports_first_snapshot: info`）下会以严重级别“信息”记录
  （设为 `learn` 则不记录，只作为基准学习）。此后出现新的监听时就会被检测到。

## 摄取 API（直接发送、LLM 应用集成）

从自己的系统发送事件时，可以直接调用摄取 API。例如，可以在公司内部的 LLM 应用中，
把用户的提示词发送到 TOKIWA，以监控提示注入。

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

- 认证请求头为 `X-Tokiwa-Token: tkw_...` 或 `Authorization: Bearer tkw_...`。需要 `ingest` 作用域。
- 每个请求最多 **5,000 个事件**。省略 `timestamp` 时使用接收时间。
- `kind` 包括 `http` / `port_snapshot` / `connection` / `ids_alert` / `dns` / `process` / `auth` / `deception` /
  `llm_app` / `custom` 等。Schema 详情请参阅服务器的 API 文档（`http://<server>:8788/api/docs`）。
- ⚠️ **摄取 API 不会在服务器端进行脱敏**（Gate 和 Agent 会在发送前脱敏）。
  直接发送时，请不要包含密码、令牌等机密信息。另外，在传给 LLM 之前一定会进行脱敏。

HTTP 的 JSON 聊天请求（默认发往 `/api/chat`、`/v1/chat/completions`、`/chat`）只要经过 Gate，
就会自动成为提示注入检测的对象（可通过 `detection.llm_app_paths` 更改）。
