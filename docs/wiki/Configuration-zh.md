> 🌐 [日本語](Configuration) · [English](Configuration-en) · **中文** · [Español](Configuration-es)

# 配置参考

## 配置的传递方式与优先级

越靠上的优先级越高。

1. **环境变量** `TOKIWA_*`（嵌套层级用 `__` 连接。例如：`TOKIWA_LLM__DAILY_BUDGET_USD=10` → `llm.daily_budget_usd`）
2. **YAML 文件**：由 `TOKIWA_CONFIG` 指定的路径（默认为当前目录下的 `tokiwa.yaml`。不存在则忽略）
3. **默认值**（`backend/src/tokiwa/config.py`）

此外，以下 2 项可以 **在运行时从 Web UI 覆盖**，其值保存在数据库中。

- LLM 设置（**LLM → Settings**（LLM → 设置））：提供商、模型、预算、输出语言、API 密钥等
- 检测器的启用 / 禁用（**Rules → Detectors**（检测规则 → 检测器））

在 Docker Compose 中，`.env` 会作为环境变量传入容器。在本地直接运行 `tokiwa serve` 时，
不会自动读取 `.env`。

### 书写注意事项

- **列表和字典用 JSON 书写**：`TOKIWA_DETECTION__DISABLED_DETECTORS='["web.scanner_ua"]'`
- **不要设置空值**。`TOKIWA_SERVER__SECRET_KEY=` 会被视为“空字符串签名密钥”（与未设置不同）。
- 建议机密信息（API 密钥、密码）通过环境变量而不是 YAML 传递。

### YAML 示例

```yaml
# tokiwa.yaml
server:
  base_url: https://tokiwa.example.internal
llm:
  daily_budget_usd: 10
  output_language: ja
triage:
  min_severity_for_llm: high
response:
  protected_cidrs: ["127.0.0.0/8", "::1/128", "10.0.0.0/24"]
  default_ttl_minutes: 30
deception:
  labyrinth_enabled: true
```

## 主要配置项

### 全局、服务器、数据库

| 键 | 默认 | 说明 |
|---|---|---|
| `env` | `dev` | `dev` / `prod` / `test` |
| `log_level` | `INFO` | 日志级别 |
| `server.host` / `server.port` | `0.0.0.0` / `8788` | 监听 |
| `server.base_url` | `http://localhost:8788` | 用户访问的 URL（用于通知中的链接等） |
| `server.cors_origins` | `["http://localhost:5173"]` | 仅在从其他源提供 UI 时需要 |
| `server.static_dir` | 无 | 已构建的 UI（`frontend/dist`）。指定后在 `/` 下提供 |
| `server.data_dir` | `./data` | 数据的保存位置（签名密钥等） |
| `server.secret_key` | 自动生成 | 登录（JWT）的签名密钥。未设置时生成并保存到 `data_dir/secret.key` |
| `server.token_ttl_minutes` | 720 | 登录的有效时间 |
| `database.url` | `sqlite+aiosqlite:///./data/tokiwa.db` | PostgreSQL 为 `postgresql+asyncpg://user:pass@host/db` |

### LLM（`llm.*`）

请参阅 [LLM 设置与成本](LLM-zh)。主要项：`provider`、`anthropic_api_key`（或环境变量 `ANTHROPIC_API_KEY`）、
`openai_base_url` / `openai_api_key`、`model_fast` / `model_deep`、`daily_budget_usd`、`output_language`、`redaction.*`。

### 检测（`detection.*`）

| 键 | 默认 | 说明 |
|---|---|---|
| `disabled_detectors` | `[]` | 要禁用的检测器 ID |
| `sigma_rule_dirs` | `["../rules/sigma"]` | Sigma 规则的存放位置 |
| `dedup_window_seconds` | 300 | 合并相同告警的时间窗口 |
| `llm_app_paths` | `/api/chat`, `/v1/chat/completions`, `/chat` | 作为提示注入监控对象的 HTTP 路径 |
| `session_idle_timeout_seconds` | 1800 | 在此时间内没有访问则视为另一个会话 |
| `ai_agent_threshold` | 0.7 | 判定为 AI 智能体的 AI 评分阈值 |
| `web.*` | — | Web 类速率检测的阈值（连续错误、登录失败、洪泛等） |

### 分诊（研判）与关联（`triage.*`）

| 键 | 默认 | 说明 |
|---|---|---|
| `auto_triage` | true | 自动对告警进行 LLM 分诊 |
| `min_severity_for_llm` | `medium` | 交给 LLM 的最低严重级别 |
| `escalate_confidence_below` | 0.6 | 轻量模型的置信度低于此值时升级到高级模型 |
| `escalate_severity` | `high` | 此严重级别及以上升级到高级模型 |
| `max_concurrent` | 4 | 同时分诊数 |
| `incident_window_minutes` | 60 | 将告警归并到同一安全事件的时间窗口 |
| `max_evidence_events` | 25 | 传给 LLM 的证据事件最大数量 |

### 处置（`response.*`）

| 键 | 默认 | 说明 |
|---|---|---|
| `auto_approve_enabled` / `auto_approve_actions` | false / `[]` | 自动批准（两项设置都需要） |
| `default_ttl_minutes` / `max_ttl_minutes` | 60 / 10080 | TTL 的默认值和上限 |
| `protected_cidrs` | `127.0.0.0/8`, `::1/128` | 绝不作为处置对象的范围 |
| `protect_server_addresses` | true | 保护服务器自身的 IP |
| `block_private_targets` | false | 禁止以私有地址为对象（保护管理网络） |
| `default_rate_limit_rpm` / `default_tarpit_delay_ms` | 60 / 2000 | 速率限制、tarpit 的默认值 |
| `nftables_enabled` | false | 使用 nftables 封禁 |
| `webhook_urls` / `webhook_allowed_hosts` / `webhook_block_private` | `{}` / `[]` / true | 作为处置的 Webhook 的发送目标与 SSRF 防护 |

### 欺骗防御（`deception.*`）、情报（`intel.*`）

请参阅 [欺骗防御（Mirage）](Deception-zh) 和 [漏洞情报](Threat-Intel-zh)。

### Gate（`gate.*`）、Agent（`agent.*`）

| 键 | 默认 | 说明 |
|---|---|---|
| `gate.upstream` | `http://127.0.0.1:3000` | 转发目标 |
| `gate.listen_host` / `gate.listen_port` | `0.0.0.0` / 8080 | 监听 |
| `gate.server_url` | `http://127.0.0.1:8788` | TOKIWA 服务器 |
| `gate.ingest_token` | 无 | API 令牌（scope: ingest + gate） |
| `gate.capture_body_bytes` | 4096 | 捕获请求体的前多少字节 |
| `gate.trust_forwarded_for` | false | 信任 `X-Forwarded-For` |
| `agent.server_url` | `http://127.0.0.1:8788` | TOKIWA 服务器 |
| `agent.ingest_token` | 无 | API 令牌（scope: ingest） |
| `agent.interval_seconds` | 10 | 主机传感器的采集间隔 |
| `agent.nginx_json_logs` / `caddy_json_logs` / `suricata_eve_logs` / `zeek_log_dirs` | `[]` | 要接入的日志 |
| `agent.verify_tls` | true | 校验服务器的 TLS 证书 |

### 通知（`notify.*`）、Copilot（`copilot.*`）

| 键 | 默认 | 说明 |
|---|---|---|
| `notify.default_webhook_url` | 无 | 无需在界面中注册即可使用的默认 Webhook |
| `notify.default_min_severity` | `high` | 默认 Webhook 的最低严重级别 |
| `notify.public_ui_url` | 无 | 通知中包含的 UI 链接地址 |
| `notify.language` | `both` | 通知的语言 |
| `notify.dedup_minutes` | 10 | 抑制相同通知的时间 |
| `notify.allowed_hosts` / `notify.block_private_destinations` | `[]` / true | 发送目标的限制（SSRF 防护） |
| `copilot.enabled` | true | Copilot（AI 助手） |
| `copilot.tier` | `deep` | 使用的模型层级 |
| `copilot.max_tool_iterations` | 8 | 单次提问中使用工具的最大次数 |

所有配置项都在 `backend/src/tokiwa/config.py` 中。Docker 用的示例请参阅仓库根目录下的 `.env.example`。
