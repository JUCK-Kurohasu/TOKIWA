> 🌐 [日本語](CLI) · [English](CLI-en) · **中文** · [Español](CLI-es)

# CLI 参考

所有操作都通过 `tokiwa` 命令进行。从源码使用时，在 `backend/` 目录中执行 `uv run tokiwa ...`；
使用 Docker 镜像时为 `tokiwa ...`（或将子命令名作为容器的参数）。
各命令的最新选项可以通过 `--help` 查看。

| 命令 | 内容 |
|---|---|
| `tokiwa version` | 显示版本 |
| `tokiwa serve` | 服务器（API、UI、摄取、后台作业） |
| `tokiwa user` | 用户管理 |
| `tokiwa token` | 传感器用 API 令牌 |
| `tokiwa gate` | 反向代理型传感器 |
| `tokiwa agent` | 主机传感器、日志转发 |
| `tokiwa intel` | 漏洞情报源 |
| `tokiwa sim` | 实验环境用流量模拟器 |
| `tokiwa eval` | 评估框架 |
| `tokiwa data` | 删除 / 导出指定 IP 或会话的数据 |

> ⚠️ 直接访问数据库的命令（`user`、`token`、`intel` 等）必须在与服务器 **相同的设置**（相同的当前目录，
> 或相同的 `TOKIWA_DATABASE__URL`）下执行。默认数据库路径 `./data/tokiwa.db` 是相对路径。

## tokiwa serve

```bash
tokiwa serve [--host HOST] [--port 8788] [--reload] [--no-jobs]
```

| 选项 | 说明 |
|---|---|
| `--host` / `--port` | 监听（默认为配置值，端口 8788） |
| `--reload` | 代码变更时自动重启（开发用） |
| `--no-jobs` | 不启动定时作业（情报同步、过期处理等） |

API 文档位于 `http://<server>:8788/api/docs`，健康检查为 `/api/v1/health`。
API 文档（`/api/docs`、`/api/openapi.json`）无需认证即可访问，生产环境建议通过 `server.expose_docs: false`
（环境变量 `TOKIWA_SERVER__EXPOSE_DOCS=false`）将其关闭。健康检查无需认证，但只有已登录时才返回版本号。

## tokiwa user create

```bash
tokiwa user create <username> [--role admin|analyst|viewer]
```

会以交互方式询问密码（隐藏输入，需输入 2 次）。角色默认为 `analyst`。

## tokiwa token create

```bash
tokiwa token create <name> [--scope ingest] [--scope gate] [--sensor-id ID ...] [--dataset PATTERN ...]
```

默认作用域 **仅为** `ingest`。Gate 用的令牌需显式指定 `--scope ingest --scope gate`（`gate` 作用域可以读取包含诱饵路径、金丝雀值和封禁列表的 Gate 策略，只应授予 Gate）。令牌（`tkw_...`）**仅显示一次**。
`--sensor-id` / `--dataset`（可重复）把令牌绑定到传感器 ID 和 dataset（[接入传感器](Sensors-zh)）。
`--expires-in-days N` 可设置有效期（默认永不过期）。过期的令牌返回 401。

## tokiwa token list / revoke / rotate

```bash
tokiwa token list [--all]                                  # 列表（不显示密钥；--all 包含已吊销）
tokiwa token revoke <id|name>                              # 立即吊销
tokiwa token rotate <id|name> [--grace-hours 24] [--expires-in-days N]   # 签发新令牌（只在标准输出显示一次）
```

无需管理员登录（忘记密码、事件处理中）也可以在服务器主机上停用令牌。每次操作都以 actor `cli` 记入审计日志。
`rotate` 签发名称、作用域和绑定都相同的新令牌，并让旧令牌在 `--grace-hours`（默认 24 小时，0 表示立即吊销）内继续有效。
Gate 会在令牌文件变化时自动重新读取，因此把新令牌写入文件即可无需重启完成切换。名称对应多个有效令牌时请指定 id。

## tokiwa data purge / export

```bash
tokiwa data purge  [--ip IP] [--session ID] [--before 2026-11-01] [--yes]   # 默认只显示数量（dry run）
tokiwa data export [--ip IP] [--session ID] [--before ...] [--out subject.jsonl]
```

按来源 IP、行为者会话或时间范围，批量删除或导出已保存的数据（个人的查阅 / 删除请求、误导入的客户数据等）。条件以 AND 组合。
范围：`events`、`actor_sessions`、`deception_trips` 删除行；`alerts` 清空 `details`（为保留与安全事件的关联，行本身保留）；
`llm_calls` 只清空提示词和响应正文（费用记录保留）。LLM 记录按带词边界的 IP / 会话 ID 匹配（`10.0.0.1` 不会匹配 `10.0.0.15`）。
`export` 输出 JSONL（每行一条 `{"table": ..., "row": {...}}`），`--out` 文件权限为 600。两者都会以 actor `cli` 记入审计日志。
安全事件摘要、Copilot 会话和备份不在范围内。

## tokiwa gate run

```bash
tokiwa gate run --upstream http://127.0.0.1:3000 [--listen 0.0.0.0:8080] [--server http://127.0.0.1:8788] \
  [--token-file PATH] [--trust-forwarded-for] ...
```

| 选项 | 默认 | 说明 |
|---|---|---|
| `--upstream` | 配置值 | 转发目标的 URL |
| `--listen` | `0.0.0.0:8080` | 监听 `host:port` |
| `--server` | 配置值 | TOKIWA 服务器的 URL |
| `--token` / `--token-file` | — | API 令牌（推荐使用环境变量 `TOKIWA_GATE__INGEST_TOKEN` 或文件；文件在变化时和收到 401 时重新读取） |
| `--sensor-id` | `gate-1` | 记录到事件中的传感器 ID |
| `--capture-body-bytes` | 4096 | 捕获请求体的前多少字节 |
| `--trust-forwarded-for` | off | 将 `X-Forwarded-For` 的最右端作为来源（仅限可信的 LB 之后） |
| `--policy-refresh` | 5 | 策略拉取间隔（秒） |
| `--batch-size` / `--flush-interval` | 100 / 1.0 | 发送的批次 |
| `--upstream-timeout` | 30 | 上游的读写超时（秒） |
| `--max-queue` | 10000 | 待发送队列的上限（超出时从最旧的开始丢弃） |
| `--preserve-host` / `--rewrite-host` | preserve | Host 请求头是原样发送，还是改写为上游的值 |
| `--access-log` | off | uvicorn 的访问日志 |
| `--log-level` | 配置值 | 日志级别 |

## tokiwa agent

```bash
tokiwa agent run  [--server-url URL] [--nginx PATH ...] [--caddy PATH ...] [--suricata PATH ...] [--zeek-dir PATH ...]
tokiwa agent once [--print] [--max-events 1000] ...
```

| 选项 | 说明 |
|---|---|
| `--server-url` | TOKIWA 服务器的 URL |
| `--token` | API 令牌（推荐使用环境变量 `TOKIWA_AGENT__INGEST_TOKEN`） |
| `--sensor-id` | 传感器 ID（默认为主机名） |
| `--interval` | 主机传感器的采集间隔（秒） |
| `--host-sensor / --no-host-sensor` | 采集监听端口和连接 |
| `--connections / --no-connections` | 报告新的 TCP 连接 |
| `--nginx` / `--caddy` / `--suricata` / `--zeek-dir` | 要接入的日志（可多次指定） |
| `--from-beginning / --from-end` | 从何处开始读取日志（默认：末尾） |
| `once --print` | 只采集一次，不发送，而是显示 JSON（用于检查运行情况） |

## tokiwa intel

```bash
tokiwa intel sync [-s kev] [-s nvd]   # 执行 1 次同步（默认：所有已启用的数据源）
tokiwa intel status                   # 各数据源的同步状态
tokiwa intel show CVE-2021-44228 [--json]   # 显示 1 条已整合的记录（CVE / GHSA / JVNDB 的 ID）
```

## tokiwa sim

```bash
tokiwa sim profiles
tokiwa sim run      [--profile mixed] [--target http://localhost:8080] [--sessions N] [--seed 1] \
                    [--time-scale 1.0] [--spread 60] [--max-requests 2000] [--max-rps 50] \
                    [--spoof-xff] [--record FILE.jsonl] [--loop] [--i-own-this-target]
tokiwa sim generate --out FILE.jsonl [--profile mixed] [--sessions N] [--seed 1] [--start ISO8601] [--spread 1800] [--no-canary]
tokiwa sim ingest   [--server http://localhost:8788] [--token-file PATH] [--profile mixed] [--batch-size 200]
```

| 子命令 | 内容 |
|---|---|
| `profiles` | 列出 profile |
| `run` | 向实验环境的目标（Gate）实际发送流量 |
| `generate` | 不使用网络，生成带标签的数据集（seed 相同则生成相同的文件） |
| `ingest` | 将合成事件直接发送到摄取 API（无需 Gate） |

`--profile` 的指定方式如 `ai_agent`、`ai_agent,scanner`、`ai_agent=2,benign_browser=5`、`mixed`。
`--time-scale` 小于 1 时会更快结束，但请求的节奏会改变，也会影响 AI 判定所用的特征。

## tokiwa eval

```bash
tokiwa eval run --dataset FILE.jsonl [--llm mock|live] [--budget-usd N] [--out DIR] \
                [--compare PREV] [--fail-on-regression] [--allow-mismatch] [--speed 0] [--json]
tokiwa eval compare <current> <previous> [--fail-on-regression] [--allow-mismatch]
tokiwa eval import-artex <source> --out FILE.jsonl [--host HOST] [--session LABEL] [--source-ip IP]
tokiwa eval info FILE.jsonl
```

| 选项 | 说明 |
|---|---|
| `--llm` | `mock`（免费、离线，默认）或 `live`（使用已配置的提供商。**会产生费用**） |
| `--budget-usd` | 使用 `--llm live` 时 **必填**。本次运行的费用上限 |
| `--out` | 输出位置（默认 `eval/runs/<UTC 时间>`） |
| `--compare` / `--fail-on-regression` | 与上次结果比较 / 若指标变差则以退出码 1 结束。两次运行的条件（数据集 sha256、LLM 提供商、启用的检测器、已加载的 Sigma 规则数、阈值、批处理设置）不同时视为“不可比较”，退出码为 3 |
| `--allow-mismatch` | 即使条件不同也进行比较并判定是否变差（差异以警告显示） |
| `--speed` | 0 = 最快，1 = 实时，10 = 10 倍速 |
| `--enable-detector` / `--disable-detector` | 强制启用 / 禁用检测器 |
| `--keep-work` | 保留评估用的临时数据库 |
