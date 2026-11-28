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
uv run tokiwa token create gate-1 --scope ingest --scope gate   # Gate 用：需显式指定 gate 作用域
uv run tokiwa token create agent-web01            # 默认作用域：仅 ingest
```

| 作用域（scope） | 允许的操作 |
|---|---|
| `ingest` | 发送事件（`POST /api/v1/ingest/events`） |
| `gate` | 获取 Gate 策略（`GET /api/v1/gate/policy`） |
| `read` | 预留（v0.1 中尚无可使用此作用域的 API） |

- 令牌（`tkw_...`）**仅在创建时显示一次**。数据库中只保存其哈希值。
- 也可以在 Web UI 的 **Settings → API tokens**（设置 → API 令牌，仅限管理员）中创建和吊销。
- 通过命令行参数传递时，其他用户可以通过 `ps` 看到，因此请 **通过环境变量或文件** 传递。
- 可以用 `--sensor-id` / `--dataset` 把令牌 **绑定** 到特定的传感器 ID 和 dataset（省略时不限制）。已绑定的令牌发送
  范围外的 dataset 时整批返回 403；冒充其他传感器 ID 时会被替换为允许的 ID。建议为 Gate 以外的传感器令牌设置绑定
  （例：`--sensor-id web01 --dataset nginx.access --dataset 'host.*'`）。
- 服务器会在每个事件上以 `ingest.token` / `ingest.token_id` 标签记录发送它的令牌。没有 `gate` 作用域的令牌发送的
  Gate 专属数据（`gate.*` / `deception.*`）会带上 `ingest.trust=low`。
  为避免伪造事件导致无辜 IP 被封禁，请把合作方、CDN 和自身出口 IP 加入 `response.protected_cidrs`。

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
| ingest_token | `--token-file`（不要用 `--token`：会在 `ps` 中可见） | 无 | 需要 `ingest` 和 `gate` 作用域。也可以用环境变量 `TOKIWA_GATE__INGEST_TOKEN` |
| capture_body_bytes | `--capture-body-bytes` | 4096 | 捕获请求体的前多少字节（0 表示不捕获） |
| policy_refresh_seconds | `--policy-refresh` | 5.0 | 拉取策略的间隔 |
| trust_forwarded_for | `--trust-forwarded-for` | false | 从 `X-Forwarded-For` 确定来源 IP（仅限 `trusted_proxies` 中的对端；从右向左读取并跳过可信代理） |
| max_request_headers | —（`TOKIWA_GATE__MAX_REQUEST_HEADERS`） | 100 | 请求头行数超过此值的请求不转发给上游，返回 431（0 表示不限制） |
| forward_client_headers | —（`TOKIWA_GATE__FORWARD_CLIENT_HEADERS`） | `[]` | 默认会移除的请求头（见下文）中，要原样转发给上游的那些 |
| tarpit_max_concurrent / tarpit_max_per_client | — | 256 / 8 | tarpit 同时挂起的请求上限（总计 / 同一 IP）；超出的请求返回 429（0 表示不限制） |
| trusted_proxies | —（`TOKIWA_GATE__TRUSTED_PROXIES`） | `[]` | 启用 `trust_forwarded_for` 时，仅当 TCP 对端在此列表中（IP / CIDR，例如 `["10.0.0.0/8"]`）才读取 `X-Forwarded-For`。为空时保持旧行为（信任任何对端）并在启动时警告；设置 `TOKIWA_STRICT_CONFIG=1` 时拒绝启动 |
| body_idle_timeout_seconds / body_total_timeout_seconds | — | 15 / 120 | 请求体中断的最长时间 / 整个请求体的上限。超出时返回 408 并释放上游连接（标签 `gate:slow_body`；0 表示不限制） |
| max_requests_per_client | — | 64 | 同一来源 IP 正在处理的请求数上限。超出时立即返回 429（标签 `gate:conn_limit`；0 表示不限制）。**在 LB 之后未启用 `trust_forwarded_for` 时，所有用户都显示为 LB 的地址，整个站点只能同时处理 64 个** |
| persist_policy / policy_cache_file / policy_cache_max_age_hours | — | true / `<server.data_dir>/gate-policy-<sensor_id>.json` / 168 | 保存获取到的策略，启动时即使无法连接服务器也强制执行（过旧的副本不使用；0 表示不限制） |

仅 CLI 提供的运维参数：`--upstream-timeout`（30 秒）、`--max-queue`（待发送事件上限 10,000 条）、
`--preserve-host / --rewrite-host`、`--access-log`、`--limit-concurrency`（并发连接上限，超出返回 503，默认不限制）。

### 需要了解的行为

- **`--trust-forwarded-for` 只能在可信的负载均衡器之后** 使用。不加此选项时，客户端发送的
  `X-Forwarded-*` 会被丢弃，并替换为 Gate 观测到的值（以防止伪造来源 IP）。
- `X-Real-IP`、`Forwarded`、`True-Client-IP`、`CF-Connecting-IP` 等其他声明来源 IP 或协议的请求头，以及 `X-Original-URL` /
  `X-Rewrite-URL`，**不会转发给上游**。Gate 会改为在 `X-Real-IP` 和 `Forwarded` 中填入自己判定的来源 IP。
  如果上游读取 Cloudflare 等前置代理添加的请求头，请将其列入 `forward_client_headers`（例如 `["cf-connecting-ip"]`）。
  Gate 也不会补充客户端没有发送的 `User-Agent` 等请求头。
- 诱饵路径匹配时，大小写、末尾的 `/` 或 `.`、`;` 之后的部分、`%5c`（`\`）以及双重编码的差异都视为同一路径
  （`/.ENV`、`/.env;x` 也会命中 `/.env` 诱饵）。包含这类变形的路径会带上标签 `gate:path_anomaly`。
- Gate 自己返回的响应（封禁的 403、诱饵、上游故障时的 502/504 等）都带有 `Cache-Control: no-store`。如果在 Gate 前面放置 CDN，
  请确认 CDN 没有被设置为强制缓存 404 等响应。
- `Content-Encoding: gzip` / `deflate` 的请求体会先解压再记录（标签 `gate:req_encoded`；发给上游的仍是压缩后的字节）。
  br、zstd 无法解压，只记录标签 `gate:req_encoding_unknown`。
- 捕获的数据会 **在发送前由 Gate 端脱敏**（`Authorization`、`Cookie` 等请求头的值，
  `password=` 等参数的值，以及令牌、密钥、电子邮件地址等）。
- 事件中最多保留 64 种请求头。User-Agent、Referer、`Sec-Fetch-*`、`X-Forwarded-*` 等用于检测的请求头无论出现在什么位置都会保留；
  超出的部分通过标签 `gate:headers_truncated` 和请求头数量（label `gate.header_count`）体现。
- **fail-open**：即使 TOKIWA 服务器停止，Gate 的代理功能也不会停止（事件会暂时缓存并重新发送）。
- **来源 IP**：启用 `trust_forwarded_for` 后，请在 `trusted_proxies` 中列出前置 LB / CDN 的地址。只读取这些对端发来的
  `X-Forwarded-For`，从右向左跳过可信代理，第一个其他地址即为客户端。遇到非 IP 的元素（如 `unknown`）即停止。
  其他对端发来的 `X-Forwarded-For` 会被忽略，并打上标签 `gate:untrusted_forwarded_for`。
- **慢速攻击**：一点点发送请求体的请求返回 408，同一 IP 并发请求过多时返回 429。**慢速发送请求头的攻击（slowloris）发生在
  Gate 之前的 uvicorn 阶段，Gate 无法阻止。** 直接暴露在互联网上时，请在前面放置具备请求头读取超时的 nginx 或负载均衡器。
- **重启时的策略**：最后获取的策略（封禁、诱饵、金丝雀）会保存到文件，启动后即使无法连接服务器也会执行；已过期的条目会被移除。
  在 Docker 中 `/data` 需要卷（`deploy/compose.yaml` 中的 `gate-state`）。
- **事件丢弃**：服务器停止期间发送队列溢出时，优先丢弃普通页面浏览（GET/HEAD、2xx/3xx、无查询字符串、无标签）。
  丢弃的数量会随下一批送达服务器的数据以 `gate.health` 事件报告，并产生检测 `sensor.events_dropped`。
- **fail-static**：无法获取策略时，保持最后一次的策略（以免出现“让服务器宕机就能解除封禁”这样的漏洞）。但 Gate 仍会遵守每条封禁自身的期限（TTL），到期即解除。
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
- **命令行**：监听／连接所属进程的命令行在发送前由代理遮盖其中的机密（`--password X`・`--api-key X` 等名称表明是机密的参数、
  `mysql -pX`・`redis-cli -a X`・`sshpass -p X`・`curl -u user:X`・`smbclient -U user%X` 等常见工具的选项、`*_KEY=X` 等环境变量赋值、
  URL 中的凭据）。程序名、选项名和路径会保留。作为位置参数传入的密码等可能不会被遮盖，因此在把机密放进参数的主机上，建议设置
  `TOKIWA_AGENT__SEND_CMDLINE=false`（只发送名称、可执行文件和用户）。作为参数传入的蜜罐令牌也会被遮盖，不会参与欺骗匹配。
- **新连接上限**：一个周期内的新连接超过 `agent.max_connections_per_cycle`（默认 1000）时，优先发送已建立、出站、进程可知的连接，
  其余不丢弃而是顺延到下一个周期。超出情况可通过端口快照的标签 `connections_truncated` 和检测 `sensor.connections_truncated`（中）
  得知（用于对抗用大量伪连接掩盖 C2 的手法）。
- **nginx 日志格式**：请使用 `log_format ... escape=json`（`lab/nginx/tokiwa-json.conf`）。没有 `escape=json` 时，`"` 会被写成
  `\x22`，不是合法的 JSON。代理会解码后摄取，但会发出警告。
- **日志时间**：带偏移的时间（ISO 8601 的 `+09:00` / `Z`、`$time_local` 等）最可靠。不带偏移的时间（自定义格式、Caddy 的 `wall` 等）
  按 `agent.log_timezone`（例如 `Asia/Tokyo`・`+09:00`・`UTC`）解释。未设置时视为 UTC 并对其数量发出警告（JST 的日志会偏差 9 小时）。
  无效值会在启动时报错。
- **无法读取的行**：无法作为 JSON 读取的行和无法解释的时间会被计数，第一次立即、此后最短每 `agent.health_report_seconds`
  （默认 300 秒）输出警告日志并发送 `agent.health` 事件。存在无法读取的行时会产生检测 `sensor.log_parse_failures`。
  即使令牌限定了 dataset，也会接受 `agent.health`。
- **Suricata 告警的方向**：EVE 告警的 `src_ip` 是所匹配数据包的方向。对于响应方向（`direction: to_client`，例如 ATTACK_RESPONSE）的告警，
  把发起连接的一方作为攻击者（来源）。规则有 `target` 时优先使用；ET 的 `metadata.attack_target` 为 `Client_Endpoint` 时不交换。
  判断结果保留在标签 `suricata.direction` / `suricata.attribution` / `suricata.swapped` 中，原始方向保留在 `raw` 中。

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
- 请求体默认最大 32 MiB（`server.max_ingest_body_bytes`，超过返回 413）。单个字符串字段超过 65,536 个字符时只保留开头部分，
  并给事件加上标签 `truncated` 和标记 `tokiwa.truncated`（`字段:原始长度`）。事件不会被拒绝，检测基于截断后的值进行。
- `kind` 包括 `http` / `port_snapshot` / `connection` / `ids_alert` / `dns` / `process` / `auth` / `deception` /
  `llm_app` / `custom` 等。Schema 详情请参阅服务器的 API 文档（`http://<server>:8788/api/docs`）。
- ⚠️ **摄取 API 不会在服务器端进行脱敏**（Gate 和 Agent 会在发送前脱敏）。
  直接发送时，请不要包含密码、令牌等机密信息。另外，在传给 LLM 之前一定会进行脱敏。

HTTP 的 JSON 聊天请求（默认发往 `/api/chat`、`/v1/chat/completions`、`/chat`）只要经过 Gate，
就会自动成为提示注入检测的对象（可通过 `detection.llm_app_paths` 更改）。
