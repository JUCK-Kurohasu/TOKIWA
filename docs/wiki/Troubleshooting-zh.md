> 🌐 [日本語](Troubleshooting) · [English](Troubleshooting-en) · **中文** · [Español](Troubleshooting-es)

# 故障排除

## 启动与登录

**在浏览器中打开时显示 404 / 只能看到 API**
UI 尚未构建，或者没有设置提供 UI 的目录。执行 `cd frontend && npm run build` 之后，
附加 `TOKIWA_SERVER__STATIC_DIR=../frontend/dist` 启动服务器。开发期间也可以使用 `make dev`（UI 在 :5173）。
使用 Docker 镜像时，请检查是否覆盖了 `TOKIWA_SERVER__STATIC_DIR`（默认 `/app/frontend/dist`）。

**首次启动时出现的是登录界面，而不是管理员注册界面**
首次的管理员注册界面（/setup）只会在服务器数据库中一个用户都没有时显示。请先确认状态。

```bash
curl -s http://localhost:8788/api/v1/auth/status
```

- `{"setup_required":false,...}` → 数据库中已经有用户（以前设置过的数据仍然保留）。
  请使用该账户登录，或按下面“想完全重置”的步骤清除数据，或按上面的步骤创建另一个管理员。
- `{"setup_required":true,...}` → 请在浏览器中重新打开 `http://localhost:8788/`。旧版本的 UI 在直接打开 `/login` 时，
  即使需要初始设置也会停留在登录界面（现在会跳转到 /setup）。
- 无法连接 → 服务器没有运行（`cd backend && uv run tokiwa serve`）。旧版本的 UI 在无法连接 API 时也会显示登录界面
  （现在会显示 **Cannot reach the server**（无法连接到服务器））。

**忘记了管理员密码**
在与服务器相同的设置下执行 `uv run tokiwa user create <新名称> --role admin` 创建另一个管理员，
然后在 **Settings → Users**（设置 → 用户）中通过 **Reset password**（重置密码）修改原账户的密码。

**重启后被登出**
签名密钥（`data/secret.key`）可能已丢失。请检查数据目录是否已持久化。

## 传感器与摄取

**已经经过 Gate，但事件没有到达**
1. 检查 Gate 的日志中是否出现摄取相关的 401 / 403 错误（令牌错误、作用域不足、已吊销）。
   令牌需要同时具备 `ingest` 和 `gate` 两个作用域。
2. 检查 `--server` 是否为能够访问到 TOKIWA 服务器的 URL。
3. 在运行 Gate 的主机上执行 `curl http://127.0.0.1:8080/__tokiwa/health`，可以看到发送统计
   （已发送、已丢弃等）。

**用 `tokiwa token create` 创建的令牌显示“invalid token”**
命令和服务器可能在使用不同的数据库。默认数据库路径（`./data/tokiwa.db`）是相对路径，因此请
在与服务器相同的目录（`backend/`）、相同的环境变量下执行。在 Docker 中请使用
`docker compose ... exec tokiwa tokiwa token create ...`。

**所有访问看起来都来自同一个 IP（负载均衡器的 IP）**
如果 Gate 位于负载均衡器之后，请设置 `--trust-forwarded-for`（`TOKIWA_GATE__TRUST_FORWARDED_FOR=true`）。
**仅在可信的负载均衡器之后** 使用。在其他环境中，来源 IP 会被伪造。

**WebSocket 无法使用了**
Gate v0.1 不支持 WebSocket（返回 501）。请让 WebSocket 的路径不经过 Gate 进行路由。

## 处置

**已批准但没有封禁**
- Gate 拉取策略的间隔默认为 5 秒。请稍等片刻后再检查。
- 检查处置的状态是否变为 `failed`。如果与受保护对象（`response.protected_cidrs`）或服务器自身的 IP
  重叠，会在执行前的再次校验中失败。
- 检查封禁对象的 IP 是否与 Gate 看到的来源 IP 一致（位于负载均衡器之后时，请参阅上面的条目）。

**待批准的处置太多**
相同类型、相同对象的提议会合并为 1 个，但会按来源分别创建。请提高交给 LLM 的最低严重级别
（`triage.min_severity_for_llm`），或者拒绝明显不需要的提议。误报较多的检测器可以在
**Rules → Detectors**（检测规则 → 检测器）中禁用。

## LLM

**没有使用 LLM（返回的是模拟应答）**
在 **LLM → Settings**（LLM → 设置）的 **Current status**（当前状态）中检查提供商及其是否可用。为 `auto` 时，若没有 Anthropic 的 API 密钥则为 `mock`。
请检查是否在服务器启动前设置了 `ANTHROPIC_API_KEY`，或是否已在 UI 中输入密钥，并执行 **Connection test**（连接测试）。

**LLM 分诊（研判）中途停止了**
可能已用完每日预算（`llm.daily_budget_usd`，默认 $5）。当天会切换为基于规则的判定。
请在 **LLM → Usage**（LLM → 用量）中检查。

**LLM 拒绝了应答（refusal）**
模型安全功能导致的拒答（refusal）被视为正常行为。该告警会回退到基于规则的判定。
可以在 **LLM → Call log**（LLM → 调用记录）中检查状态。

## 漏洞情报

**同步失败**
需要从运行 TOKIWA 的环境向各服务（NVD、CISA、FIRST、OSV、JVN、GitHub 等）发起出站通信。
NVD 没有 API 密钥时获取速率限制较严格，GitHub 也是有令牌时更稳定。
由于提供方改版，JVN 可能无法获取（尚未验证）。

## Docker

**`PermissionError: /data/...` 或“/data is not writable”**
容器以 uid 10001 运行。使用 bind mount 时，请用
`sudo chown -R 10001:10001 <dir>` 修改主机端目录的属主（使用命名卷时会自动设置正确）。

**容器变为 `unhealthy`**
用 `docker inspect --format '{{json .State.Health}}' <container>` 检查原因。没有 HTTP 的角色（agent / sim）请设置
`TOKIWA_HEALTHCHECK_URL=none`，Gate 请设置 `http://127.0.0.1:8080/__tokiwa/health`。

**在反向代理之后实时更新停止**
请关闭 SSE（`/api/v1/stream`）的缓冲，并延长读取超时（参见 [安装与运维](Installation-zh) 中的 nginx 示例）。

## 数据

**想完全重置（从头开始）**
⚠️ 事件、告警、用户、API 令牌和签名密钥都会被删除。之后需要为传感器重新创建并配置令牌。

```bash
# 从源码运行时：先停止服务器
rm -rf backend/data            # 如果修改过 TOKIWA_SERVER__DATA_DIR / TOKIWA_DATABASE__URL，则删除对应位置

# Docker Compose（deploy/compose.yaml）：-v 会同时删除卷（tokiwa-data、postgres-data）
docker compose -f deploy/compose.yaml down -v && make up

# 实验环境（lab/compose.yaml）：实验用令牌也会重新创建
docker compose -f lab/compose.yaml down -v && docker compose -f lab/compose.yaml up --build -d
```

使用外部 PostgreSQL 时，请删除并重新创建数据库。重启后打开 UI 会进入初始设置界面。
浏览器中残留的旧登录信息会因为签名密钥变化而失效（如有需要可清除站点数据）。

**升级后出现错误**
v0.1 没有 Schema 的自动迁移。请通过发布说明或 `HANDOFF.md` 检查 Schema 的变更，
必要时从备份中恢复。

---

如果问题仍未解决，请在 [Issue](https://github.com/JUCK-Kurohasu/TOKIWA/issues) 中附上执行的命令、日志（**隐去机密信息**）和环境信息告知我们。
