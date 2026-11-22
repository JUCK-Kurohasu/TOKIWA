> 🌐 [日本語](Data-Handling) · [English](Data-Handling-en) · **中文** · [Español](Data-Handling-es)

# 数据处理

本页汇总 **TOKIWA 接收什么、保存什么、向外部发送什么、保留多久、谁能查看**。
内容基于 v0.1.0 的代码和默认值。无法从代码中确认的内容标注为“未确认”。

> ⚠️ **要点（使用默认值时）**
> - Gate 最多保存请求体的前 4,096 字节。秘密值、电子邮件地址和卡号会被遮盖，但
>   **姓名、电话号码、住址、出生日期、登录 ID 等不会被遮盖**。
> - 设置 LLM 的 API 密钥后，`medium` 及以上的告警和安全事件会连同证据事件的摘录一起
>   **自动发送给外部的 LLM 提供商**。
> - **自动删除尚未实现**。已保存的数据会一直保留，直到有人手动删除。
> - 包括 `viewer` 在内的所有角色都能查看包含请求体的原始事件。
>
> 有关个人数据处理的法律判断，请由部署 TOKIWA 的组织自行作出。本页汇总的是供判断参考的事实。

## 收集与保存

### 脱敏在传感器端进行

- Gate 和 Agent 会 **在把事件发送给服务器之前，在各自的进程中** 进行脱敏。所用的设置是传给该进程的
  `llm.redaction.*`（各项见 [LLM 设置与成本](LLM-zh)）。
- 服务器会 **原样保存** 收到的事件（接收时不会再次脱敏）。修改服务器端的 `llm.redaction.*`，
  不会改变从 Gate / Agent 收到的事件的保存内容。
- 自行发送到接收 API（`POST /api/v1/ingest/events`）的事件也不经脱敏直接保存。请在发送端进行脱敏。
- 单个字段会按 `llm.redaction.max_field_chars`（默认 2,048 个字符）截断（Gate 的请求体按 `gate.capture_body_bytes` 截断）。

### 各传感器收集的项目

| 传感器（dataset） | 保存的内容 | 遮盖的内容 | 不保存的内容 |
|---|---|---|---|
| **Gate**（`gate.http`） | 来源 / 目标的 IP 与端口、方法、Host、路径、查询、请求头（最多 64 种；用于检测的请求头无论位置都会保留）及其顺序、User-Agent、Referer、Content-Type、**文本类请求体的前 `gate.capture_body_bytes`（默认 4,096）字节**、请求体大小、状态码、响应大小与 Content-Type、处理时间 | `llm.redaction.sensitive_headers` 中请求头的值（`Authorization`、`Cookie` 等），以及下文“会被遮盖”的项目 | 响应正文、响应头（Content-Type 除外）、二进制请求体（只记录大小）、超过 64 种的请求头（只保留标签 `gate:headers_truncated` 和请求头数量） |
| **Gate 的诱饵响应**（`gate.deception`） | 与上面相同的 HTTP 内容再记录一条（包括输入到诱饵登录表单中的值） | 同上 | 同上（这些请求不会转发给受保护的应用） |
| **nginx / Caddy**（`nginx.access` / `caddy.access`） | 来源 IP 与端口、方法、Host、路径、查询、日志中包含的请求头、状态码、大小、处理时间、原始日志行（`raw`，脱敏后，最多 4 KB） | 请求头的值（同上）、`password`、`token`、`cookie` 等键的值，以及下文“会被遮盖”的项目 | 请求体（访问日志中不包含） |
| **Zeek**（`zeek.conn` / `zeek.http` / `zeek.notice`） | 连接（IP、端口、字节数、状态）、HTTP（路径、查询、UA、Referer、状态码）、notice、原始行（`raw`，最多 4 KB） | `password` 等键的值，以及下文“会被遮盖”的项目 | 上述 3 种以外的日志。另外，`http.log` 的 **`username` 列不在遮盖范围内**，会原样保留在 `raw` 中 |
| **Suricata**（`suricata.eve`） | `alert` / `http` / `flow` / `dns` 记录（IP 与端口、HTTP 的路径、查询和请求头、DNS 的查询名与应答）、原始 EVE 记录（`raw`，最多 4 KB） | 请求头的值、按键名遮盖，以及下文“会被遮盖”的项目 | `tls`、`fileinfo`、`stats` 等其他类型。如果 EVE 配置为输出载荷（payload），其内容可能在 4 KB 范围内进入 `raw` |
| **主机传感器**（`host.ports` / `host.connections`） | 主机名、主机 IP（最多 32 个）、OS、监听套接字、新的 TCP 连接（双方的 IP 与端口），以及相应进程的名称、可执行文件、命令行（最多 512 个字符）、OS 用户名 | 命令行中 `password=...` 形式的值等 | —（作为普通参数传入的密码可能不会被遮盖） |
| **接收 API**（直接发送） | 所发送事件的全部内容 | **无**（服务器不做脱敏） | — |
| **欺骗防御的触发记录** | 被触碰的资产、来源 IP、事件 ID、路径、方法、UA、陷阱值（TOKIWA 生成的伪造值）以及该值出现的字段名 | — | —（删除资产后触发记录仍会保留） |

### 会被遮盖与不会被遮盖的内容

被遮盖的值会替换为 `[REDACTED:<类型>]`。

| 会被遮盖 | 不会被遮盖（示例） |
|---|---|
| 私钥、JWT、主要服务的 API 密钥 / 令牌格式（Anthropic、OpenAI、AWS、GitHub、Slack、Google）、`Bearer` / `Basic` 认证的值 | 姓名、电话号码、住址、出生日期 |
| 紧跟在 `password=`、`token=`、`secret=`、`api_key=`、`auth=`、`session=` 等之后的 3 个字符以上的值 | 登录 ID（`username=` 等的值）、2 个字符以下的密码 |
| 嵌入 URL 的凭据（`https://user:pass@...`） | 经 URL 编码的电子邮件地址（包含 `%40`） |
| 通过 Luhn 校验的卡号 | IPv6 地址（`mask_ips` 只针对 IPv4） |
| 电子邮件地址（`mask_emails`，默认 ON） | 事件中的来源 / 目标 IP 字段（即使开启 `mask_ips` 也不在范围内） |
| 字符串中的 IPv4 地址（`mask_ips`，默认 OFF） | |

### 服务器内数据被复制的位置

同一份个人数据会在检测和分诊过程中被复制到多张表中。处理删除或披露请求时，需要检查以下全部内容。

| 表 | 可能包含个人数据的项目 |
|---|---|
| `events` | 事件整体（上表中的内容，包括 `raw`） |
| `alerts` | 来源 IP、标题、`entities`（路径、Host、参数名）、`details` 中的匹配片段（Web 类检测最多 200 个字符）、分诊结果 |
| `incidents` | 来源 IP 列表、LLM 写的摘要（最多 4,000 个字符）、分诊结果 |
| `actor_sessions` | 来源 IP、User-Agent、行为特征量 |
| `llm_calls` | 传给 LLM 的输入（已脱敏，最多 100,000 个字符）和应答。提供商为 `mock` 时也会记录 |
| `copilot_messages` | 与 Copilot（AI 助手）的对话及工具结果（包括事件请求体的前 300 个字符等） |
| `deception_trips` | 上表中的触发记录 |
| `response_actions` | 处置的目标 IP 和理由（包括 LLM 写的文字） |
| `audit_log` | 操作者的用户名、对象、详情 |
| `users` | TOKIWA 的用户名、密码哈希、最后登录时间 |
| `notification_channels` | 通知收件人的电子邮件地址、SMTP 用户名、Webhook 的 URL |
| `settings_kv` | 在界面中输入的 LLM API 密钥（明文） |

### 减少收集

```bash
# 传给 Gate 进程
export TOKIWA_GATE__CAPTURE_BODY_BYTES=0   # 不保存请求体（只记录大小）。与 --capture-body-bytes 0 相同
# 增加值会被整体遮盖的请求头（默认的 7 个也要重新列出）
export TOKIWA_LLM__REDACTION__SENSITIVE_HEADERS='["authorization","cookie","set-cookie","proxy-authorization","x-api-key","x-auth-token","x-csrf-token","x-forwarded-user"]'

# 传给 Agent 进程
export TOKIWA_AGENT__CONNECTIONS=false     # 不发送新的 TCP 连接
export TOKIWA_AGENT__HOST_SENSOR=false     # 不发送监听端口和进程信息
```

- 如果把 `deception.canary_header`（默认 `X-Debug-Auth`）加入 `sensitive_headers`，将无法检测 AI 金丝雀。
- 请不要在 nginx 的 `log_format` 中加入 Cookie、Authorization 或请求体（见 `lab/nginx/tokiwa-json.conf` 中的注释）。
- 开启 `mask_ips` 可能影响检测和处置提议，请先在测试环境中确认后再使用（影响范围未确认）。
- 为 Gate 加上 `--access-log`（默认 OFF）时，uvicorn 标准的访问日志（客户端地址和请求行）会输出到标准输出。该日志不经过 TOKIWA 的脱敏。

## 向外部发送

### 发送目标一览

| 发送目标 | 时机 | 发送的内容 | 停止方法 |
|---|---|---|---|
| LLM 提供商：自动分诊 | 创建 `triage.min_severity_for_llm`（默认 `medium`）及以上的告警时；创建安全事件时，以及其严重程度、攻击阶段等发生变化时 | 告警 / 安全事件的内容（标题、说明、来源 IP、entities）、最多 `triage.max_evidence_events`（默认 25）条证据事件的摘录、AI 会话的特征量、相关漏洞 | `triage.auto_triage=false`，或不使用外部提供商（见下文） |
| LLM：手动分诊 | `analyst` 及以上的用户在界面或 API 中执行时（与 `auto_triage` 和最低严重程度无关，都会执行） | 同上 | 不使用外部提供商 |
| LLM：Copilot | 用户提问时 | 问题、对话历史、只读工具的结果（事件的路径、查询、UA、请求体前 300 个字符、告警、安全事件、资产等） | `copilot.enabled=false` |
| LLM：漏洞建议（advisory） | 发现与资产匹配的漏洞时，以及定期执行时 | 漏洞信息，匹配资产的名称、类型、重要程度和软件 | `intel.enabled=false` |
| LLM：Web 调研 | 每隔 `intel.research_interval_hours`（默认 12）小时，仅在提供商不是 `mock` 时 | 调研主题、资产的软件列表（厂商、产品、版本）。搜索在提供商一侧进行 | `intel.research_enabled=false` |
| 通知渠道（Webhook / Slack / Discord / 电子邮件） | 创建告警和安全事件时、安全事件严重程度上升时、提出处置时 | 见下文“通知中包含的内容” | 禁用或删除渠道、取消 `notify.default_webhook_url`、`notify.notify_action_proposals=false` |
| 处置 `webhook` / `notify` | 仅在该处置被批准时 | 处置的 ID、类型、目标 IP、TTL、安全事件 / 告警的 ID | 不批准；不设置 `response.webhook_urls` |
| 漏洞情报源 | 每隔 `intel.sync_interval_minutes`（默认 360）分钟 | **只有查询**：时间范围（NVD、JVN、GHSA）、CVE ID（EPSS）、资产软件的生态系统、包名和版本（OSV）。不发送遥测数据 | `intel.enabled=false`，或 `intel.sources.<名称>=false` |

### 发送给 LLM 的证据内容

分诊时，只从每条证据事件中提取以下项目发送。原始日志行（`raw`）不会发送。

- ID、时间、类型、来源 / 目标的 IP 与端口、主机名、会话 ID、标签
- HTTP：方法、Host、路径、查询、状态码、大小、Content-Type、部分请求头（User-Agent、Referer、Origin、
  Accept 系列、`X-Forwarded-For` 等 13 种）及请求头顺序、**请求体的前 512 个字符**
- 非 HTTP：除 `raw`、标签等之外的事件内容（包括主机传感器的命令行等）

发送前，服务器会再用自身的 `llm.redaction.*` 脱敏一次，并包裹在“不可信数据”的块中。
提供商一侧的保存期限和使用条件取决于各提供商的条款（TOKIWA 无法控制；具体内容未确认）。

### 不向外部 LLM 发送

```bash
# 传给服务器
export TOKIWA_LLM__PROVIDER=mock               # 不向外部发送（LLM 的判定改由模拟和规则给出）
export TOKIWA_TRIAGE__AUTO_TRIAGE=false        # 完全不做自动分诊（llm_calls 的记录也会减少）
export TOKIWA_COPILOT__ENABLED=false           # 停用 Copilot
```

- **默认情况下界面设置优先于环境变量**。如果在 **LLM → Settings**（LLM → 设置）中保存了提供商，即使用环境变量设为 `mock`，
  也会使用界面中的设置。要固定“不向外部发送”，请同时传入 `TOKIWA_LLM__ALLOW_UI_OVERRIDE=false`（只能通过环境变量或配置文件设置）：
  界面中的保存会被拒绝，数据库中已有的覆盖也会被忽略（启动时以警告列出项目名）。**LLM → Settings** 的“Current status”（当前状态）
  会显示实际在用的提供商和被覆盖的项目。脱敏设置（`llm.redaction.*`）无法在界面中修改。
- 使用 `mock` 时分诊仍会运行，其输入会保存在 `llm_calls` 中（不会向外部发送）。因超出预算而未发送的调用，
  其输入也会被记录。
- 使用在组织内部运行的 OpenAI 兼容服务器（`llm.provider=openai_compat`），可以把发送目标限制在组织内部（[LLM 设置与成本](LLM-zh)）。
- 在服务器上设置 `mask_ips=true` 后，预计 LLM 将无法给出处置的目标 IP，因而不会由 LLM 生成封禁等提议
  （根据代码推断，实际行为未确认）。

### 通知中包含的内容

| 通知 | 包含的内容 |
|---|---|
| 告警 | 标题（最多 200 个字符）、说明（最多 600 个字符）、来源 IP、类别、规则 ID、AI 评分 |
| 安全事件 | 标题、来源 IP（正文中 5 个，Webhook 的 `data` 中最多 20 个）、行为者类型、AI 评分、告警数、攻击阶段、**摘要（最多 600 个字符，仅当 `notify.include_summary=true` 时）** |
| 处置的审批请求 | 处置类型、目标 IP、TTL、提议者、**理由（最多 500 个字符，仅当 `notify.include_summary=true` 时）** |

- 不包含事件的请求体、查询和请求头。但告警的标题和说明中可能含有路径、参数名等攻击者可控字符串的片段。
- 安全事件的摘要和处置的理由可能是 LLM 在分诊时写的文字。由于 LLM 可能写入证据中的个人信息，默认不包含在通知中（`notify.include_summary=true` 时包含；真实 LLM 中发生的频率未确认）。
- 设置 `notify.include_source_ip=false` 后，来源 IP 和 IP / CIDR 处置目标显示为 `(hidden)`（也会从 Webhook 的 `data` 中移除）。
- 在 Slack、Discord 和邮件中，正文里的 URL 会改为不可点击的形式（`hxxps://`），Discord 的格式（链接、强调）会被禁用。

## 保留期限

- **尚未实现自动删除（保留期限设置或定期清理）**。事件、告警、事件单（incident）、LLM 调用记录等在被手动删除前会一直保留
  （[#80](https://github.com/JUCK-Kurohasu/TOKIWA/issues/80)、
  [#171](https://github.com/JUCK-Kurohasu/TOKIWA/issues/171)）。
- 特定 IP 地址、AI 会话或某一时间点之前的数据，可用 CLI `tokiwa data purge` 删除（见下文“应对数据主体的请求”）。
- 界面和 API 只能删除用户、API 令牌、规则、资产、欺骗资产、Copilot 对话、端口基线和通知渠道。
- 删除 Copilot 对话后，该对话中产生的 LLM 调用记录（`llm_calls`）仍会保留。删除欺骗资产后，触发记录仍会保留。
- 无法连接服务器期间，Gate 和 Agent 会把事件暂存在 **内存** 中（Gate 默认最多 10,000 条，Agent 最多 50,000 条；不写入磁盘）。
- 数据保存在 `database.url` 指定的数据库中（默认 `./data/tokiwa.db`）。TOKIWA 新建的 SQLite 文件和数据目录仅所有者可访问（0600 / 0700），
  登录签名密钥 `secret.key` 也是 0600（已存在的文件和目录的权限不会更改）。数据库备份中也包含同样的数据。

## 谁能查看

### 按角色（API 权限）

[Web UI 指南](Web-UI-zh) 中的角色表说明的是各角色“能执行的操作”。各角色能读取哪些数据由 API 权限决定，如下所示
（界面上不显示的项目也可以通过 API 获取）。

| 数据 | `viewer` | `analyst` | `admin` |
|---|:-:|:-:|:-:|
| 原始事件（请求体、查询、头部值、`raw`、主机进程的命令行） | 打码¹ | ✅ | ✅ |
| 事件的来源、目标、方法、主机、路径、状态码、User-Agent | ✅ | ✅ | ✅ |
| AI 会话（来源 IP、User-Agent；会话内的事件按第一行处理） | ✅ | ✅ | ✅ |
| 告警（含 `details` 中的匹配内容；证据事件按第一行处理）、事件单（摘要、分诊结果） | ✅ | ✅ | ✅ |
| 欺骗触发记录（令牌值对 viewer 打码）、处置列表（目标 IP、理由） | ✅ | ✅ | ✅ |
| LLM 调用列表（用途、费用、状态；不含输入和响应正文²） | ✅ | ✅ | ✅ |
| 使用 Copilot（其工具可搜索事件等） | —³ | ✅ | ✅ |
| LLM 调用的输入和响应正文 | — | — | ✅ |
| 其他用户的 Copilot 对话、读取访问记录（`GET /api/v1/audit/access`） | — | — | ✅ |
| 审计日志、用户列表、通知渠道设置 | — | — | ✅ |

- ¹ 对 `viewer`，查询、请求体、头部值（User-Agent、Host、Content-Type、Accept、Content-Length 以外）、Referrer 的查询部分、
  `raw`、Gate 以外传感器的日志行、命令行和 LLM 应用的提示词会被替换为 `[redacted: analyst role required]`。
  路径仍然可见（如果应用会把个人数据放进路径，请注意）。
- ² 对被拒绝的对话，列表的 `error` 字段会包含模型输出的前 500 个字符。
- ³ 默认 `copilot.min_role: analyst`；改为 `viewer` 后 viewer 也可使用。每个用户每分钟最多发送 `copilot.messages_per_minute` 条（默认 6）。
- 实时推送（`GET /api/v1/stream`）会向所有已登录用户发送告警（含 `details`）、事件单和处置的内容，
  以及欺骗触发（来源 IP）。事件只发送数量，不发送 LLM 调用的输入和响应。
- **读取访问记录**：事件和 AI 会话的列表与详情、LLM 调用详情、Copilot 工具执行会记录到 `access_log`
  （谁、哪个视图、什么条件、多少条；同一用户以同一条件的重复读取每 5 分钟合并为一行）。
  登录成功与失败、登出以及首次设置会记入审计日志。查看告警和事件单不会被记录。

### TOKIWA 之外能查看的人

- 能读取数据库文件及其备份的人（OS 用户、备份管理员）
- LLM 提供商（已发送的范围）
- 通知目标服务（Slack、Discord、邮件服务器、Webhook 接收方）及这些渠道的成员
- 运行 Gate / Agent 的主机的管理员（在事件发送前留在内存中期间）

## 应对数据主体的请求

特定 IP 地址、AI 会话或时间范围的数据，可在服务器主机上用 CLI 导出和删除（界面和 API 中没有此功能）。

- **查找**：事件可按来源 IP（`GET /api/v1/events?source_ip=...`）或路径、User-Agent 的部分匹配（`q=`）筛选。
  没有按请求体或查询内容搜索的 API。
- **导出**：`tokiwa data export --ip 203.0.113.7 --out subject.jsonl`（也可用 `--session` / `--before` 缩小范围；输出文件为 0600）。
- **删除**：`tokiwa data purge --ip 203.0.113.7` 只显示将删除多少条（dry run）。加上 `--yes` 才会实际删除。
  - 事件、AI 会话和欺骗触发记录按行删除。
  - 告警保留行，只清除 `details`。
  - `llm_calls` 保留费用记录，只清除输入和响应正文（正文中以独立词形式出现该 IP 的行，以及相关告警的行）。
  - 导出和删除（包括 dry run）会以 `data.export` / `data.purge` 记入审计日志。
- **无法以此删除的内容**：不能按 IP 以外的标识（如登录 ID）搜索或删除。事件单摘要、通知发送记录、
  数据库备份以及用户另行保存的内容不在范围内。必要时请直接检查数据库（见上文“服务器内数据被复制的位置”），
  手动编辑数据库前请先停止服务器并备份。
- **已发送到外部的内容**：发送给 LLM 提供商或通知目标的内容无法从 TOKIWA 撤回。

## 运维人员应确认的要点

适用哪些法律法规、需要做什么，应由部署 TOKIWA 的组织负责判断，必要时请与专业人士确认。
以下是一般性要点的列表，并不完整。

- **使用目的**：是否需要明确、告知或公布将受保护应用的用户数据（表单输入、IP 地址等）用于安全监控。
- **最小化收集**：是否需要保存请求体（`gate.capture_body_bytes`）？日志格式或请求头中是否有不必要的项目？
- **向外部提供**：发送给 LLM 提供商或通知服务属于委托处理、向第三方提供还是向境外转移？接收方的保存期限和二次使用条件如何？
- **保留期限**：保留多少天。由于没有自动删除，需要确定删除流程和负责人。
- **访问权限**：把 `viewer` 及以上权限授予谁。在不记录查看行为的前提下进行管理。
- **安全管理**：数据库文件及其备份的权限与加密。在界面中输入的 API 密钥会以明文保存在数据库中。
- **数据主体的请求**：收到披露、更正、删除、停止使用等请求时的流程和期限。
- **发生泄露时**：根据本页掌握哪些表、哪些外部发送目标存有数据。
- **员工监控**：主机传感器或 Gate 记录员工的通信或操作时的内部规定与告知。
- **欺骗防御**：诱饵和 AI 金丝雀的措辞与部署位置（[欺骗防御（Mirage）](Deception-zh)）。

## 相关页面

- [LLM 设置与成本](LLM-zh)：提供商和脱敏设置
- [接入传感器](Sensors-zh)：Gate 和 Agent 的设置
- [配置参考](Configuration-zh)
- [Web UI 指南](Web-UI-zh)：角色与界面
