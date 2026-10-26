> 🌐 [日本語](Quick-Start) · [English](Quick-Start-en) · **中文** · [Español](Quick-Start-es)

# 快速开始

本文介绍如何在本机启动 TOKIWA，并使用附带的攻击模拟器体验“检测 AI 智能体的攻击 → 人工批准 → 封禁”的完整流程。
不使用 Docker。所需时间约为 10～15 分钟。

> 接近生产环境的长期运行配置（Docker Compose）请参阅 [安装与运维](Installation-zh)。

## 前提条件

| 软件 | 版本 | 用途 |
|---|---|---|
| Python | 3.12 及以上 | 后端 |
| [uv](https://docs.astral.sh/uv/) | 最新 | Python 依赖管理 |
| Node.js / npm | 22 系列 | 构建 Web UI |
| git | — | 获取源码 |

已在 Linux 上验证运行。预计 macOS 也能按相同步骤运行，但尚未验证。Windows 尚未验证。
**即使没有** LLM 的 API 密钥也能运行（此时使用模拟 LLM 和基于规则的判定运行）。

## 1. 获取与安装

```bash
git clone https://github.com/JUCK-Kurohasu/TOKIWA.git
cd TOKIWA

cd frontend && npm install && npm run build && cd ..   # 构建 Web UI（frontend/dist）
cd backend && uv sync                                   # 安装后端依赖
```

## 2. 启动服务器

```bash
# 在 backend/ 中执行
TOKIWA_SERVER__STATIC_DIR=../frontend/dist uv run tokiwa serve
```

在浏览器中打开 <http://localhost:8788>。首次访问会进入 **初始设置页面（/setup）**，在此创建第一个管理员。

- 用户名：3～64 个字符（英文字母、数字以及 `_` `.` `-`）
- 密码：10 个字符以上

数据（SQLite 数据库和签名密钥）保存在 `backend/data/`。

> 💡 如果要一边修改 UI 一边使用，可在仓库根目录执行 `make dev`，会同时启动 API（:8788，自动重载）和
> UI 开发服务器（:5173）。

### 使用 LLM 时（可选）

在启动服务器之前，通过环境变量传入 API 密钥。

```bash
export ANTHROPIC_API_KEY=sk-ant-...      # 设置后提供商会自动变为 Anthropic
```

默认的每日预算为 **$5**。超出后会切换为基于规则的判定。详情请参阅 [LLM 设置与成本](LLM-zh)。

## 3. 搭建迷你实验环境并发送攻击流量

在附带的演示用受害者应用（靶机应用）前放置 TOKIWA Gate，再用模拟器发送攻击流量。
**使用 3 个终端**（加上服务器用的终端共 4 个）。

```
 模拟器       ──▶ Gate :8080 ──▶ 受害者应用 :3000（没有漏洞的演示商店）
                    │
                    ▼
            TOKIWA Server :8788
```

**终端 A — 受害者应用**（所有响应都是固定的，实际上并不存在漏洞）

```bash
cd lab/victim
../../backend/.venv/bin/uvicorn app:app --host 127.0.0.1 --port 3000
```

**终端 B — 创建 Gate 用的 API 令牌，并启动 Gate**

```bash
cd backend
uv run tokiwa token create gate-1        # tkw_... 只显示一次，请记下
export TOKIWA_GATE__INGEST_TOKEN=tkw_...  # 比命令行参数更安全（不会出现在 ps 中）
uv run tokiwa gate run --upstream http://127.0.0.1:3000 --listen 127.0.0.1:8080 \
  --server http://127.0.0.1:8788 --trust-forwarded-for
```

> ⚠️ 请在与服务器 **相同的目录（`backend/`）、相同的环境变量** 下执行 `tokiwa token create`。
> 数据库的位置（默认 `./data/tokiwa.db`）是相对于运行时当前目录的相对路径。

`--trust-forwarded-for` 是仅用于实验环境的设置，让模拟器可以通过 `X-Forwarded-For` 声明来源 IP。
在生产环境中，除非“位于可信的负载均衡器之后”，否则不要添加该选项。

**终端 C — 用模拟器发送攻击流量**

```bash
cd backend
uv run tokiwa sim run --target http://127.0.0.1:8080 --time-scale 0.1 --spread 10 --spoof-xff
```

发送的流量混合了正常用户、扫描器、人类攻击者、AI 智能体、针对 LLM 应用的攻击者这 5 类
（几分钟内结束）。发送目标被限制为本地 / 私有地址，载荷仅为用于检测测试的无害字符串。

> `--time-scale 0.1` 会把等待时间缩短为 1/10，以便尽快结束。由于请求的“节奏”会与实际不同，
> 如果想严格观察判定结果，请省略此选项（默认 1.0）。

## 4. 查看结果

在 Web UI 中打开以下页面。

| 页面 | 看点 |
|---|---|
| **Dashboard**（仪表盘） | 告警数、未关闭的安全事件、AI 会话数、待批准的处置 |
| **AI sessions**（AI 会话） | 每个来源的 AI 评分。AI 智能体的会话会以紫色的 **AI agent**（AI 智能体）标记排在前列 |
| **Incidents**（安全事件） | 同一来源的告警被归并在一起，并附上攻击阶段（侦察 → 初始入侵等）和 LLM 的分诊（研判）结果 |
| **Alerts**（告警） | 各个检测结果（SQL 注入、扫描器、访问诱饵、遵循 AI 金丝雀等） |

## 5. 批准并封禁

1. 打开 **Response**（处置）页面的 **Awaiting approval**（待批准）标签页。这里列出了 LLM（或规则）提议的 `block_ip` 等处置。
2. **Approve**（批准）针对 AI 智能体来源 IP 的 `block_ip`。
3. 几秒之内（Gate 拉取策略的间隔默认为 5 秒），Gate 就会对来自该 IP 的请求返回 **403**。

```bash
# 批准后检查（<IP> 为已批准的来源）
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: <IP>" http://127.0.0.1:8080/   # → 403
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: 192.0.2.1" http://127.0.0.1:8080/  # → 200（其他 IP 可以通过）
```

4. 在 **Active**（生效中）标签页中点击 **Revert**（撤销），即可解除封禁（即使什么都不做，到 TTL＝默认 60 分钟后也会自动过期）。

只要不批准，提议的处置就 **绝不会执行**。

## 6. 清理

在各个终端中按 Ctrl-C 停止。如果要删除数据从头开始，请删除 `backend/data/`。

## 下一步阅读

- 保护自己的应用：[接入传感器](Sensors-zh)
- 界面的详细说明：[Web UI 指南](Web-UI-zh)
- 长期运行配置：[安装与运维](Installation-zh)
