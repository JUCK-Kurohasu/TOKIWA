> 🌐 [日本語](Lab-and-Evaluation) · [English](Lab-and-Evaluation-en) · **中文** · [Español](Lab-and-Evaluation-es)

# 实验环境与评估

TOKIWA 附带用于试验检测的 **实验环境**、**攻击流量模拟器** 和 **评估框架**。
此外，还提供了以攻击方 ARTEX 为对手的 **紫队演练** 步骤。

> ⚠️ 模拟器和 ARTEX 只能指向 **您自己管理并拥有测试许可的目标**。

## 实验环境的构成

```
 模拟器 / ARTEX       ──▶ Gate :8080（捕获 + 封禁）──▶ 受害者应用 :3000（演示商店。无漏洞）
                              │
                              ▼
                       TOKIWA :8788（API + UI） ◀── Agent（可选: nginx JSON 日志 / 主机）
```

**受害者应用（靶机应用）**（`lab/victim/app.py`）看起来像一个具备登录、搜索、商品 API、聊天（`/api/chat`）、OpenAPI 等功能的
演示商店，但 **实际上并不存在漏洞**。它没有数据库、文件读取或 shell，所有响应都是固定的。
不过，为了诱发 AI 智能体的“出错后的适应”，它会返回看似真实的错误
（引号为奇数个 → 类似 SQL 错误的 500，`<script` → 类似 WAF 的 403 等）。首页上有实验环境用的 AI 金丝雀
（使用 `LAB_AI_CANARY=0` 禁用）。

### 不使用 Docker 运行（已验证）

即 [快速开始](Quick-Start-zh) 中“3. 搭建迷你实验环境并发送攻击流量”的步骤。

### 使用 Docker Compose 运行

```bash
docker compose -f lab/compose.yaml up --build -d            # tokiwa + gate + victim
# 打开 http://localhost:8788，首次访问时创建管理员

docker compose -f lab/compose.yaml --profile sim run --rm sim                          # 默认混合流量
SIM_PROFILE=ai_agent docker compose -f lab/compose.yaml --profile sim run --rm sim     # 仅 AI 智能体
SIM_PROFILE=ai_agent=2,benign_browser=4 SIM_TIME_SCALE=0.2 docker compose -f lab/compose.yaml --profile sim run --rm sim
docker compose -f lab/compose.yaml --profile ingest run --rm sim-ingest                # 不经过 Gate 直接投放
docker compose -f lab/compose.yaml --profile agent up -d                               # nginx(:8081) + agent
docker compose -f lab/compose.yaml down                                                # 停止（加 -v 会同时删除数据）
```

使用真实 LLM 运行时，请像 `TOKIWA_LLM_PROVIDER=auto ANTHROPIC_API_KEY=... TOKIWA_LLM_BUDGET_USD=2` 这样附加变量后启动
（实验环境的默认每日预算为 $1）。

> ✅ **已确认（2026-11-10，审计 L14，沙箱环境；未记录 Docker / Compose 版本）**：执行 `up -d` 后 `tokiwa-init` 正常结束，
> `tokiwa` / `gate` / `victim` 均为 healthy；在 UI 中完成初始设置；从 `--profile sim` 的 `sim` 开始，经过告警 → 安全事件 →
> 处置提议 → 批准 → 在 Gate 处封禁（403）。从批准到封禁生效约需 4〜8 秒。
>
> ⚠️ 在该环境中，由于 Docker Hub 的速率限制（429）、ghcr.io 的 403 以及拦截 TLS 的代理，直接执行 `up --build` 失败；
> 通过构建参数（`NODE_IMAGE` / `PYTHON_IMAGE` / `UV_IMAGE`）替换基础镜像，并手动重新标记 victim 的基础镜像后才启动成功
> （详见 `lab/README.md` 的“検証状況”）。**未确认**：`--profile ingest` 和 `--profile agent`，以及使用真实 LLM 运行。

## 模拟器（`tokiwa sim`）

| Profile | 真实标签 | 行为 |
|---|---|---|
| `benign_browser` | 正常 | 用浏览器购物的普通用户 |
| `scanner` | 自动扫描器 | 基于字典 + 特征签名的机械式扫描（恒定速率） |
| `human_attacker` | 人类 | 以人类的节奏手动尝试 SQLi / XSS |
| `ai_agent` | AI 智能体 | 类似 ARTEX 的自主智能体（从 JS / OpenAPI 发现 API、出错后变异、突发与等待思考、遵循金丝雀） |
| `llm_app_attacker` | 人类 | 针对 `/api/chat` 的提示注入、越狱 |

```bash
cd backend
uv run tokiwa sim profiles
uv run tokiwa sim run --profile ai_agent --target http://localhost:8080
uv run tokiwa sim run --profile ai_agent=2,benign_browser=5 --seed 7 --record ../eval/datasets/live.jsonl
```

安全限制：

- 发送目标仅限 localhost、私有 IP，以及解析到这些地址的域名。除非加上 `--i-own-this-target`，否则其他目标一律拒绝
  （仅限您自己拥有并获得测试许可的目标）。
- 不跟随重定向，也不使用代理相关的环境变量。请求总数（默认 2,000）和速率（默认 50 rps）都有上限。
- 载荷是用于检测测试的无害字符串（外部引用使用 `.invalid` 域名）。

## 评估框架（`tokiwa eval`）

将带标签的数据集送入 TOKIWA 的处理流程（摄取 → 检测 → 关联 → 分诊（研判）），计算各项指标。
评估在一次性的数据库中进行，因此不会影响正在运行的服务器。不会向检测器或 LLM 透露真实标签。

```bash
cd backend
uv run tokiwa sim generate --out ../eval/datasets/mix.jsonl                  # 离线生成（seed 相同则生成相同的文件）
uv run tokiwa eval run --dataset ../eval/datasets/lab-mini.jsonl             # 模拟 LLM（免费、离线）
uv run tokiwa eval run --dataset ../eval/datasets/mix.jsonl --compare ../eval/runs/<上次> --fail-on-regression
uv run tokiwa eval run --dataset ../eval/datasets/mix.jsonl --llm live --budget-usd 0.50   # 真实 LLM（会产生费用）
uv run tokiwa eval compare ../eval/runs/<本次> ../eval/runs/<上次>
```

结果会以 `metrics.json` 和 `report.md` 的形式输出到 `eval/runs/<UTC 时间>/`。

| 指标 | 含义 |
|---|---|
| 攻击会话检测率（medium 及以上） | **主要指标**。至少带有 1 条 medium 及以上告警的攻击会话所占的比例 |
| 攻击会话检测率（不限严重程度） | 次要指标。即使只有 1 条 info / low 告警也视为已检测 |
| 正常会话误报率 | 被打上告警的正常会话所占的比例 |
| 告警精确率 | 仅归属于攻击会话的告警所占的比例（也按检测器分别给出） |
| AI 归因 P / R / F1 / AUC | 按“是否为 AI 智能体”判定会话时的精度 |
| LLM 一致率 | 分诊的判定（行为者类型、是否恶意、是否 AI）与真实标签一致的比例 |
| 成本与延迟 | LLM 的费用，摄取 → 告警、告警 → 分诊的延迟 |

所有比率都会附带分子 / 分母和 95% 区间（Clopper–Pearson）输出，试验次数少于 30 的值在 `report.md` 中标为 **参考值**
（附带的 lab-mini 只有 3 个正常会话和 2 个 AI 会话，“误报 0/3”的区间为 0〜70.8%）。`--llm mock` 下的“LLM 一致率”是基于规则的
替代判定与自身的一致，**并非 LLM 的质量**；费用分别显示实际费用 $0 和“估算 token × 价格表”的预估费用。
`--compare` 在两次运行的条件（数据集 sha256、LLM 提供商、启用的检测器、已加载的 Sigma 规则数、阈值）不同时警告“不可比较”，
此时 `--fail-on-regression` 的退出码为 3（有意的比较请使用 `--allow-mismatch`）。告警总数和各检测器的告警数也会被比较。

> 附带的数据集（`eval/datasets/lab-mini.jsonl`）是基于与检测器相同的假设合成的。请认为此处的数值
> **会高于真实环境**。

## 与 ARTEX 的紫队演练

模拟器的 `ai_agent` 只是一个假设模型，因此 **用真实的 AI 智能体进行验证才是真正的考验**。

1. 启动实验环境（见上文）。
2. 启动 ARTEX。ARTEX 默认的流量记录代理 **使用 :8788，会与 TOKIWA 冲突**，因此请将
   ARTEX 一方改为其他端口（例如：`./start.sh -addr :8787 -proxy :18788`）。
3. **创建任务之前**，在 ARTEX 的系统设置中开启流量记录（设置键 `traffic_capture`）和 LLM 记录（`llm_record`），并清除目标主机
   以往的记录。两种记录默认都是关闭的，关闭时不会留下事后评估所需的数据。ARTEX 的记录按主机而非按任务保存
   （详见 `docs/purple-team.md` §2）。
4. 将 ARTEX 任务的目标 **仅设为实验环境的 Gate（`http://<实验环境主机>:8080`）**。
5. 演练期间在 TOKIWA 中观察以下内容：
   - **AI sessions**（AI 会话）：ARTEX 的会话是否被归类为 AI 智能体并获得高评分
   - **Alerts**（告警）：`ai.agent_session`、`ai.adaptive_mutation`、`ai.semantic_recon`、`ai.llm_client_fingerprint`、`deception.trip` 等
   - **Incidents**（安全事件）：行为者判定是否为 AI 智能体，攻击阶段是否逐步推进
   - **Response**（处置）：封禁等是否 **停留在提议阶段**，在批准之前不会执行
6. 事后可以将 ARTEX 的记录转换为数据集，反复进行再评估。

```bash
cd backend
uv run tokiwa eval import-artex <解压 ARTEX 任务归档后的目录> --host <实验环境主机> \
  --since <演练开始 UTC> --until <演练结束 UTC> --split-gap-minutes 30 --out ../eval/datasets/artex-<日期>.jsonl
uv run tokiwa sim generate --profile benign_browser=10 --out ../eval/datasets/benign.jsonl
cat ../eval/datasets/artex-<日期>.jsonl ../eval/datasets/benign.jsonl > ../eval/datasets/purple-<日期>.jsonl
uv run tokiwa eval run --dataset ../eval/datasets/purple-<日期>.jsonl
```

`import-artex` 可以读取任务归档（`traffic/traffic.json`）、证据 ZIP、记录索引（SQLite）和 API 转储。
ARTEX 记录的时间是 **响应完成时间，精度为 1 秒**，并且不包含来源 IP（使用 `--source-ip` 补充）。导入事件的间隔和突发只是
近似值，请务必以演练期间 Gate 的实时捕获来评估请求节奏。请求头的顺序也没有意义。可以用 `--since` / `--until` 缩小时间段，
用 `--split-gap-minutes` 在无通信的间隔处拆分会话。导入 0 条时，会显示记录可能处于关闭状态、记录中包含的主机以及时间范围。
TOKIWA 只读取 ARTEX 的记录格式，不包含 ARTEX 的代码。
