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

## tokiwa user create

```bash
tokiwa user create <username> [--role admin|analyst|viewer]
```

会以交互方式询问密码（隐藏输入，需输入 2 次）。角色默认为 `analyst`。

## tokiwa token create

```bash
tokiwa token create <name> [--scope ingest] [--scope gate]
```

默认作用域为 `ingest` 和 `gate`。令牌（`tkw_...`）**仅显示一次**。

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
| `--token` / `--token-file` | — | API 令牌（推荐使用环境变量 `TOKIWA_GATE__INGEST_TOKEN` 或文件） |
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
                [--compare PREV] [--fail-on-regression] [--speed 0] [--json]
tokiwa eval compare <current> <previous> [--fail-on-regression]
tokiwa eval import-artex <source> --out FILE.jsonl [--host HOST] [--session LABEL] [--source-ip IP]
tokiwa eval info FILE.jsonl
```

| 选项 | 说明 |
|---|---|
| `--llm` | `mock`（免费、离线，默认）或 `live`（使用已配置的提供商。**会产生费用**） |
| `--budget-usd` | 使用 `--llm live` 时 **必填**。本次运行的费用上限 |
| `--out` | 输出位置（默认 `eval/runs/<UTC 时间>`） |
| `--compare` / `--fail-on-regression` | 与上次结果比较 / 若指标变差则以退出码 1 结束 |
| `--speed` | 0 = 最快，1 = 实时，10 = 10 倍速 |
| `--enable-detector` / `--disable-detector` | 强制启用 / 禁用检测器 |
| `--keep-work` | 保留评估用的临时数据库 |
