> 🌐 [日本語](Response) · [English](Response-en) · **中文** · [Español](Response-es)

# 处置（审批流程）

TOKIWA 发现威胁时会 **提议** 处置，但 **在人工批准之前不会执行任何操作**。
所有封禁都有期限（TTL），并且可以撤销。

## 生命周期

```
proposed（提议）──批准──▶ approved ──执行成功──▶ active（生效）──到期失效──▶ expired
    │                        │                       └──撤销──▶ reverted
    └──拒绝──▶ rejected      └──执行失败──▶ failed
```

| 操作 | 执行者 | 备注 |
|---|---|---|
| 提议 | LLM（分诊）/ 规则 / 用户 | 如果已存在相同类型、相同对象的提议，则不新建，而是追加理由 |
| 批准、拒绝 | `analyst` 及以上 | 批准后立即执行 |
| 撤销 | `analyst` 及以上 | 仅限处于 `active` 且可撤销的处置 |
| 到期失效 | 自动（每 30 秒检查一次） | 超过 TTL 后解除 |

所有操作都会记录到审计日志中。

## 处置类型

| 类型 | 对象 | 效果 |
|---|---|---|
| `block_ip` | IP / CIDR | Gate 对该来源返回 403 |
| `rate_limit` | IP / CIDR | Gate 限制每分钟的请求数（默认 60）。超出时返回 429 |
| `tarpit` | IP / CIDR | Gate 延迟响应（默认 2,000 ms，上限 30 秒） |
| `deceive` | IP / CIDR | Gate 对该来源的所有响应都替换为诱饵 |
| `nftables_block` | 单个 IP | 添加到主机的 nftables set 中（**默认禁用**） |
| `deploy_canary` | 路径 | 部署欺骗防御资产（诱饵、honeytoken、AI 金丝雀） |
| `notify` | — | 发送到通知渠道 |
| `webhook` | — | 向已配置的 Webhook 发送固定格式的 JSON |

与 Gate 相关的处置，会在 Gate 下一次拉取策略时（默认 5 秒以内）生效。

## 安全机制

1. **未经批准不会执行**。执行处理只接受已批准（带有批准者和批准时间）的记录。
   这一点通过测试（所有类型 × 所有提议来源的组合、并发批准、代码静态检查）来保证。
2. **LLM 的自由文本不会传到执行系统**。执行器接收的只有经过校验的类型、规范化的 IP / CIDR、带类型的参数和 TTL。
   不会生成 shell 命令字符串。
3. 校验提议时，以下对象会被拒绝。
   - 无法解析为 IP / CIDR 的内容（主机名、包含 `;` 的字符串等）
   - 范围过大（IPv4 大于 /16、IPv6 大于 /48。如 `0.0.0.0/0` 等）
   - 与 **受保护对象**（`response.protected_cidrs`。默认 `127.0.0.0/8`、`::1/128`）重叠的对象
   - 服务器自身的 IP 地址（`response.protect_server_addresses`，默认 ON）
4. 在执行之前，会按当前设置 **再次校验**（例如在提议之后新增了受保护对象时，状态会变为 `failed`）。

> 💡 强烈建议事先将管理终端、监控系统、上游负载均衡器的 IP 添加到 `response.protected_cidrs` 中。

## TTL（有效期）

- 默认 60 分钟（`response.default_ttl_minutes`），上限 7 天（`response.max_ttl_minutes`）。超过上限的指定值会被截断。
- 到期后自动解除。

## 自动批准（默认 OFF）

可以只对特定类型省略批准。仅在 **两项设置都** 启用时才会生效。

```yaml
response:
  auto_approve_enabled: true
  auto_approve_actions: ["rate_limit", "tarpit"]   # 仅限此处列出的类型
```

自动批准的处置，其批准者会记录为 `policy`。由于误报的影响很大，是否对封禁（`block_ip`）启用自动批准，请慎重判断。

> 要求提议者与批准者为不同人员的“双人批准”，在 v0.1 中尚未强制执行（计划在下一个开发阶段作为设置项添加）。

## 使用 nftables 封禁（可选）

用于连不经过 Gate 的流量也要阻止的场景。**默认禁用**，只要不启用就一定会失败。
TOKIWA 不会创建 table、set 或规则，只会向 set 中添加、删除元素，因此需要管理员事先准备好。

```bash
nft add table inet tokiwa
nft add set inet tokiwa blocklist  '{ type ipv4_addr; flags timeout; }'
nft add set inet tokiwa blocklist6 '{ type ipv6_addr; flags timeout; }'
nft add chain inet tokiwa input '{ type filter hook input priority 0; policy accept; }'
nft add rule inet tokiwa input ip  saddr @blocklist  drop
nft add rule inet tokiwa input ip6 saddr @blocklist6 drop
```

然后设置 `TOKIWA_RESPONSE__NFTABLES_ENABLED=true`。上述语法，以及以非 root 用户运行时所需的权限
（`CAP_NET_ADMIN` 等），请在您所用的发行版上自行核实（尚未验证）。

## 通知

在 **Settings → Notifications**（设置 → 通知渠道）中注册 Webhook / Slack / Discord / 电子邮件后，会在以下时机发送通知。

| 触发事件 | 条件 |
|---|---|
| 创建告警 | 达到该渠道的最低严重级别及以上 |
| 创建安全事件 | 同上 |
| 更新安全事件 | 仅在严重级别上升时 |
| 提议处置 | 作为批准请求发送（可通过 `notify.notify_action_proposals` 停用） |

- 相同内容每 10 分钟最多发送 1 次（`notify.dedup_minutes`）。但严重级别上升时仍会发送。
- 通知的语言由 `notify.language`（`ja` / `en` / `both`）决定。链接使用 `notify.public_ui_url`。
- **SSRF 防护**：发送目标仅限 http / https，且不跟随重定向。默认情况下，如果域名解析的结果是私有
  地址（回环地址、内网、云元数据等），则拒绝发送。也可以通过
  `notify.allowed_hosts` 限定允许的主机。
- 建议不要将邮件密码保存在数据库中，而是通过 `password_env`（环境变量名）传入。
