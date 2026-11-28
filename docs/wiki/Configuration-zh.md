> 🌐 [日本語](Configuration) · [English](Configuration-en) · **中文** · [Español](Configuration-es)

# 配置参考

## 配置的传递方式与优先级

越靠上的优先级越高。

1. **环境变量** `TOKIWA_*`（嵌套层级用 `__` 连接。例如：`TOKIWA_LLM__DAILY_BUDGET_USD=10` → `llm.daily_budget_usd`）
2. **YAML 文件**：由 `TOKIWA_CONFIG` 指定的路径（默认为当前目录下的 `tokiwa.yaml`，可以不存在。`TOKIWA_CONFIG` 指定的文件不存在或是目录时，启动时记录 WARNING。`TOKIWA_CONFIG=`（空）表示不读取 YAML）
3. **默认值**（`backend/src/tokiwa/config.py`）

此外，以下 2 项可以 **在运行时从 Web UI 覆盖**，其值保存在数据库中。

- LLM 设置（**LLM → Settings**（LLM → 设置））：提供商、模型、预算、输出语言、API 密钥等
- 检测器的启用 / 禁用（**Rules → Detectors**（检测规则 → 检测器））

**在界面中保存的值，对该项优先于环境变量和 YAML**（数据库中的值优先）。重启或恢复数据库后仍然有效。
启动时，与静态设置不同的 LLM 项的名称会以 WARNING 记录到日志（不记录值）。在 LLM → Settings 的“在此保存的覆盖”中
可以确认哪些项来自数据库，通过 **重置所有覆盖**（`DELETE /api/v1/llm/config`，仅管理员，记录审计）可以恢复为静态设置。
如需通过环境变量 / YAML 固定 LLM 设置（例如强制 `TOKIWA_LLM__PROVIDER=mock`，使任何内容都不发送到外部 LLM），请设置
`TOKIWA_LLM__ALLOW_UI_OVERRIDE=false`（`llm.allow_ui_override`，默认 true）。此时数据库中的覆盖会被忽略，来自界面的更改
（`PUT /api/v1/llm/config`）返回 409。该设置本身无法在界面中更改。

在 Docker Compose 中，`.env` 会作为环境变量传入容器。在本地直接运行 `tokiwa serve` 时，
不会自动读取 `.env`。

### 书写注意事项

- **列表和字典用 JSON 书写**：`TOKIWA_DETECTION__DISABLED_DETECTORS='["web.scanner_ua"]'`
- **不要设置空值**（空字符串的含义因设置项而异）。空的 `TOKIWA_SERVER__SECRET_KEY=` 会被视为未设置，使用 `data_dir/secret.key` 中自动生成的密钥。自行设置时需要至少 32 个字符，过短时服务器无法启动。
- 建议机密信息（API 密钥、密码）通过环境变量而不是 YAML 传递。

### 检查配置（拼写错误、实际生效的值）

拼写错误的设置会被忽略，该项保持默认值。为便于发现，启动时将以下情况记录为 **WARNING**（只记录名称和路径，不记录值）：

- YAML 中的未知键（`llm.providr` → `did you mean llm.provider?`；键区分大小写）
- 不对应任何设置项的 `TOKIWA_*` 环境变量（`TOKIWA_LLM__PROVIDR`，或把 `__` 写成一个 `_` 的 `TOKIWA_LLM_PROVIDER` 等）
- `TOKIWA_CONFIG` 指定的文件不存在或是目录（Docker 的 bind mount 在源文件不存在时会创建目录）

设置 `TOKIWA_STRICT_CONFIG=1` 后，存在上述问题时拒绝启动（默认只警告）。Compose、健康检查和实验环境脚本使用的非设置变量
（`TOKIWA_BIND`、`TOKIWA_HEALTHCHECK_URL` 等）以及邮件通知的密码变量不在检查范围内。`tokiwa serve` 的启动日志还会以 INFO 输出一行：
读取的配置文件、`data_dir`、数据库（密码已遮蔽）和 LLM 提供方。

用 `tokiwa config show` 查看实际生效的值及其来源（`env` / `file` / `default`，加 `--db` 时还有在界面中保存的 `ui`）。
密钥显示为 `<set>`，URL 中的密码、查询参数以及 Webhook URL 的路径会被隐藏。

```bash
tokiwa config show                       # 全部设置项及来源
tokiwa config show --changed -s llm      # 仅显示与默认值不同的 llm.*
tokiwa config show --db                  # 同时反映界面中保存的 LLM 覆盖值（ui）
tokiwa config show --check               # 发现问题时退出码为 1（部署前检查）
docker compose -f deploy/compose.yaml exec tokiwa tokiwa config show
```

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
| `server.secret_key` | 自动生成 | 登录（JWT）的签名密钥（至少 32 个字符）。未设置或为空时生成并保存到 `data_dir/secret.key`（权限 0600） |
| `server.token_ttl_minutes` | 720 | 登录的有效时间 |
| `auth.setup_code_required` | `true` | 初始设置（创建第一个管理员）时要求输入启动日志和 `data_dir/setup-code` 中的一次性设置码 |
| `server.max_body_bytes` | 1048576（1 MiB） | 请求体上限，超过返回 413。适用于除摄取（ingest）以外的所有 API |
| `server.security_headers` | `true` | 为所有响应添加 CSP、`X-Frame-Options: DENY`、`nosniff` 和 `Referrer-Policy: no-referrer`。仅当代理自行设置策略或定制的 UI 与 CSP 不兼容时设为 `false` |
| `server.expose_docs` | `true` | 无需认证即可访问 API 文档（`/api/docs`、`/api/openapi.json`）。生产环境建议设为 `false` |
| `server.max_ingest_body_bytes` | 33554432（32 MiB） | `/api/v1/ingest/` 的请求体上限。超过的批次返回 413，Gate / 代理会**丢弃**该批次；增大 `batch_size` 时请一并调高 |
| `auth.login_max_failures` | 5 | 同一用户名 × 来源 IP 的登录失败达到此次数后，暂时拒绝（429）。0 表示禁用 |
| `auth.login_max_failures_per_ip` | 30 | 单个来源 IP 的失败次数上限（不区分用户名，防密码喷洒）。0 表示禁用 |
| `auth.login_lockout_minutes` | 15 | 上面两项的统计时间窗（分钟）。旧的失败移出时间窗后解除 |
| `auth.password_hash_concurrency` | 4 | 同时计算的密码哈希（scrypt）数量 |
| `database.url` | `sqlite+aiosqlite:///./data/tokiwa.db` | PostgreSQL 为 `postgresql+asyncpg://user:pass@host/db` |

### LLM（`llm.*`）

请参阅 [LLM 设置与成本](LLM-zh)。主要项：`provider`、`anthropic_api_key`（或环境变量 `ANTHROPIC_API_KEY`）、
`openai_base_url` / `openai_api_key`、`model_fast` / `model_deep`、`daily_budget_usd`、`output_language`、`redaction.*`。

### 检测（`detection.*`）

| 键 | 默认 | 说明 |
|---|---|---|
| `disabled_detectors` | `[]` | 要禁用的检测器 ID |
| `sigma_rule_dirs` | 根据包的位置解析（源码中为 `<仓库>/rules/sigma`，Docker 镜像中为 `/app/rules/sigma`） | Sigma 规则的存放位置。与启动时的工作目录无关。目录不存在时在启动时记录 ERROR 日志。指定相对路径时依次在工作目录、`backend/` 中查找 |
| `dedup_window_seconds` | 300 | 合并相同告警的时间窗口 |
| `llm_app_paths` | `/api/chat`, `/v1/chat/completions`, `/chat` | 作为提示注入监控对象的 HTTP 路径 |
| `session_idle_timeout_seconds` | 1800 | 在此时间内没有访问则视为另一个会话 |
| `ai_agent_threshold` | 0.7 | 判定为 AI 智能体的 AI 评分阈值 |
| `max_future_skew_seconds` | 120 | 允许传感器时钟超前的秒数。时间戳比这更靠后的事件改用接收时间，并加上标签 `clock_skew` 和标注 `ingest.original_timestamp`（原始时间）；审计日志 `ingest.clock_skew` 每个令牌每 10 分钟最多记录一次。过去的时间戳（延迟或重发的事件）保持不变 |
| `max_live_sessions` | 4096 | 内存中保留的会话数上限。满了以后先淘汰只有 1 个请求的低分会话，带有 AI 判定、金丝雀或诱饵证据的会话最后淘汰。淘汰过多时输出 WARNING 日志（大量只发 1 个请求的客户端可能重置会话特征）；正常负载下也出现时请调大 |
| `fp_suppress_hours` | 168 | 将告警标记为“误报”后，在此时间内抑制同一问题（相同规则、匹配内容、路径和来源 IP）的再次出现：再次出现只累加到原告警的计数，不产生新告警、LLM 分诊或通知。出现新的签名或严重级别升高时照常告警。设为 0 则不自动抑制。抑制的列表和解除通过 API `GET/POST /api/v1/alert-suppressions` |
| `allowlist_max_hours` | 720 | 声明已授权的漏洞扫描或负载测试来源 CIDR 的许可列表（由管理员通过 API 创建，必须指定期限）的最长期限。许可列表内的告警只以 info 记录，不进入分诊、通知、事件或处置建议 |
| `web.*` | — | Web 类速率检测的阈值（连续错误、登录失败、洪泛等） |
| `web.max_inspect_chars` / `web.max_params` / `web.max_headers` / `web.max_json_leaves` / `web.max_json_depth` / `web.max_multipart_parts` | 8192 / 64 / 64 / 128 / 16 / 32 | Web 签名检测的检查上限。超出数量上限的参数、请求头、JSON 值和 multipart 部分不会被丢弃，而是合并在一起检查；超出字符数上限的部分不检查。达到上限时记录在告警的 `details.inspection_truncated` 和标签 `inspection-truncated` 中；如果上限之前的内容像填充（同一字符重复、空的虚拟元素），会产生 `web.inspection_evasion`（low） |
| `web.inspect_custom_headers` / `web.extra_framing_headers` | true / `[]` | 应用自定义的请求头（X-Tenant-Id 等）也作为 SQLi、XSS、路径遍历、命令注入的检查对象。Accept、Sec-*、If-*、追踪类等框架性请求头不检查；在 `extra_framing_headers` 中添加名称（末尾 `*` 表示前缀匹配）可以排除更多。设为 false 恢复以前的行为（只检查 User-Agent、Referer、X-Forwarded-* 等） |
| `web.max_decode_rounds` | 8 | 对一个值重复进行 URL / HTML / JS 解码的最大次数（应对多重编码；值不再变化时即停止） |
| `web.header_count_low` / `web.header_count_medium` | 40 / 64 | 一个请求的请求头行数超过该值时，以 low / medium 发出 `web.header_anomaly`（用于发现通过大量添加请求头把检测所需的请求头挤出捕获范围的手法）。浏览器通常为 10～25 行，CDN 或负载均衡器每经过一层会增加几行。正常请求触发时请调高。设为 0 关闭该级别 |

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
| `auto_approve_cooldown_minutes` | 1440 | 人工拒绝或撤销后，同类型 + 同目标在此时间（分钟）内不会被自动批准（0 表示禁用） |
| `default_ttl_minutes` / `max_ttl_minutes` | 60 / 10080 | TTL 的默认值和上限 |
| `protected_cidrs` | `127.0.0.0/8`, `::1/128` | 绝不作为处置对象的范围 |
| `shared_cidrs` | `100.64.0.0/10`、RFC 1918、`fc00::/7` | 可能被大量用户共享的范围（运营商级 NAT、企业 NAT、代理）。对重叠目标的处置绝不自动批准并附带警告（人工仍可批准）。不内置 CDN / 云出口范围，如有需要请添加提供商最新公布的范围 |
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
| `gate.token_file` | 无 | 保存 API 令牌的文件。变化时和收到 401 时重新读取（轮换时无需重启）。可读时优先于 `ingest_token` |
| `gate.capture_body_bytes` | 4096 | 捕获请求体的前多少字节 |
| `gate.trust_forwarded_for` | false | 信任 `X-Forwarded-For` |
| `gate.max_request_headers` | 100 | 请求头行数超过此值的请求不转发给上游，返回 431（0 表示不限制） |
| `gate.forward_client_headers` | `[]` | 默认会移除的 `X-Real-IP`、`Forwarded`、`CF-Connecting-IP`、`X-Original-URL` 等请求头中，要原样转发给上游的那些（仅限前置的可信代理所添加的） |
| `gate.tarpit_max_concurrent` / `gate.tarpit_max_per_client` | 256 / 8 | tarpit 同时挂起的请求上限（总计 / 同一 IP）。超出的请求返回 429。0 表示不限制 |
| `gate.trusted_proxies` | `[]` | 读取其 `X-Forwarded-For` 的对端（前置 LB / CDN 的 IP / CIDR）。为空时保持旧行为（信任所有对端）并警告 |
| `gate.body_idle_timeout_seconds` / `gate.body_total_timeout_seconds` | 15 / 120 | 请求体的空闲 / 总时间上限。超出返回 408。0 表示不限制 |
| `gate.max_requests_per_client` | 64 | 同一来源 IP 正在处理的请求数上限。超出返回 429。0 表示不限制。在 LB 之后需要 `trust_forwarded_for` + `trusted_proxies`（否则所有用户共用一个地址） |
| `gate.persist_policy` / `gate.policy_cache_file` / `gate.policy_cache_max_age_hours` | true / 无（`<server.data_dir>/gate-policy-<sensor_id>.json`）/ 168 | 保存获取到的策略，启动时服务器不可达也强制执行 |
| `agent.server_url` | `http://127.0.0.1:8788` | TOKIWA 服务器 |
| `agent.ingest_token` | 无 | API 令牌（scope: ingest） |
| `agent.interval_seconds` | 10 | 主机传感器的采集间隔 |
| `agent.nginx_json_logs` / `caddy_json_logs` / `suricata_eve_logs` / `zeek_log_dirs` | `[]` | 要接入的日志 |
| `agent.verify_tls` | true | 校验服务器的 TLS 证书 |
| `agent.send_cmdline` | true | 发送进程的命令行（机密在发送前遮盖）。false 时只发送名称、可执行文件和用户 |
| `agent.max_connections_per_cycle` | 1000 | 每个周期发送的新连接上限（超出部分顺延到下一个周期） |
| `agent.log_timezone` | 无 | 不带偏移的日志时间的时区（`Asia/Tokyo`・`+09:00`・`UTC`）。未设置时视为 UTC 并警告 |
| `agent.health_report_seconds` | 300 | 报告无法读取的行／时间的最短间隔（`agent.health` 事件） |

### 通知（`notify.*`）、Copilot（`copilot.*`）

| 键 | 默认 | 说明 |
|---|---|---|
| `notify.default_webhook_url` | 无 | 无需在界面中注册即可使用的默认 Webhook |
| `notify.default_min_severity` | `high` | 默认 Webhook 的最低严重级别 |
| `notify.public_ui_url` | 无 | 通知中包含的 UI 链接地址 |
| `notify.language` | `both` | 通知的语言 |
| `notify.dedup_minutes` | 10 | 抑制相同通知的时间 |
| `notify.include_summary` | false | 在通知中包含 LLM 写的文字（安全事件摘要、处置理由） |
| `notify.include_source_ip` | true | 在通知中包含来源 IP 和 IP / CIDR 处置目标（false 时显示 `(hidden)`） |
| `notify.allowed_hosts` / `notify.block_private_destinations` | `[]` / true | 发送目标的限制（SSRF 防护） |
| `notify.smtp_password_envs` | `[]` | 邮件 `password_env` 可额外使用的环境变量名（默认可用 `TOKIWA_NOTIFY_SMTP_*` / `TOKIWA_SMTP_PASSWORD*`） |
| `notify.smtp_allowed_hosts` / `notify.smtp_block_private` | `[]` / false | SMTP 发送目标的限制（考虑到内部中继，默认不拒绝私有地址） |
| `notify.smtp_allow_plaintext_auth` | false | 允许不使用 TLS 的 SMTP 认证 |
| `copilot.enabled` | true | Copilot（AI 助手） |
| `copilot.tier` | `deep` | 使用的模型层级 |
| `copilot.max_tool_iterations` | 8 | 单次提问中使用工具的最大次数 |
| `copilot.min_role` | `analyst` | 创建会话和发送消息所需的最低角色（`viewer` / `analyst` / `admin`）。一次提问最多调用 8 次 deep 层级，且日预算全局共用，因此默认不允许 viewer |
| `copilot.messages_per_minute` | 6 | 每个用户每分钟可发送的消息上限（0 表示不限）。超出时返回 429 |

所有配置项都在 `backend/src/tokiwa/config.py` 中。Docker 用的示例请参阅仓库根目录下的 `.env.example`。
