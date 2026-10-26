> 🌐 [日本語](Threat-Intel) · [English](Threat-Intel-en) · **中文** · [Español](Threat-Intel-es)

# 漏洞情报

定期导入漏洞信息，与已登记的资产进行比对，并给出带优先级的建议（安全通告）。
此外，还会通过 LLM 的 Web 搜索，定期调查 0day 和漏洞利用的报告。

## 导入的数据源

| 数据源 | 内容 |
|---|---|
| CISA KEV | 已确认被实际利用的漏洞目录 |
| EPSS | 30 天内被利用的概率估计值 |
| NVD | CVE 详情、CVSS、受影响的产品（CPE） |
| OSV | 开源软件包（PyPI、npm、Go、Maven 等）的漏洞 |
| JVN | 日本的漏洞信息 |
| GitHub Security Advisories（GHSA） | GitHub 的安全通告 |
| RSS | JPCERT/CC、IPA、CISA、The Hacker News、BleepingComputer（默认） |

- 默认每 360 分钟（6 小时）同步一次（`intel.sync_interval_minutes`）。
- 同步需要向这些服务发起 **出站通信**。
- NVD 在没有 API 密钥时，获取速率限制会更严格。GitHub 也是有令牌时更稳定。

```bash
export TOKIWA_INTEL__NVD_API_KEY=...       # 可选
export TOKIWA_INTEL__GITHUB_TOKEN=...      # 可选
```

> ⚠️ JVN 已公告将在 2026 年 4 月以后对 MyJVN 进行改版。以旧数据源为前提的获取方式可能已无法使用，
> 真实数据下的运行情况尚未验证。

## 使用方法

1. **登记资产**：在 **Assets**（资产）页面，登记需要保护的主机、服务、Web 应用、LLM 应用，以及在其上运行的软件
   （厂商、产品名、版本、CPE、OSV 生态系统）。
2. **等待同步（或手动执行）**：可以从 **Intelligence → Sources**（情报 → 数据源状态）开始同步。也可以通过 CLI 执行。

   ```bash
   cd backend
   uv run tokiwa intel sync              # 所有已启用的数据源
   uv run tokiwa intel sync -s kev       # 仅指定的数据源
   uv run tokiwa intel status            # 各数据源的同步状态
   uv run tokiwa intel show CVE-2021-44228
   ```

3. **查看结果**：在 **Intelligence**（情报）页面的各个标签页中查看。

| 标签页 | 内容 |
|---|---|
| **Vulnerabilities**（漏洞） | 将所有数据源按 CVE 整合后的结果（是否命中 KEV、EPSS、CVSS） |
| **Asset matches**（资产匹配） | 与资产中的软件相匹配的漏洞。可以管理状态（未处理 / 已处理等） |
| **Advisories**（安全通告） | 由 LLM 给出的带优先级的建议。优先针对命中 KEV、高 EPSS、资产匹配的情况生成 |
| **News**（新闻） | RSS 文章 |
| **Web research**（Web 调研） | 由 LLM 进行的 0day、漏洞利用报告的调查结果。也可以指定主题手动执行 |
| **Sources**（数据源状态） | 各数据源的最后同步时间和条目数 |

## 安全通告与检测规则提议

安全通告中，除了影响摘要、优先级、推荐的应对措施之外，有时还会附带 **Sigma 格式的检测规则草案**。
规则草案经过校验后，会作为“提议”保存到 **Rules → LLM proposals**（检测规则 → LLM 提议）中，**不会自动启用**。
需要人工审查后再采用。

## 与安全事件的联动

如果告警引用了某个 CVE，且该 CVE 被收录在 KEV 中，则会提升安全事件的优先级。
**Dashboard**（仪表盘）上的 **KEV matches**（KEV 匹配）表示已知被利用漏洞与资产相匹配的数量。

## Web 调研（0day 定期调查）

- 默认每 12 小时（`intel.research_interval_hours`）调查一次 `intel.research_topics` 中的主题。
- 由于使用的是 Claude 的 **服务器端 Web 搜索**，**仅在设置了 Anthropic 的 API 密钥时** 才会实际进行搜索。
  使用模拟 LLM 时不会进行搜索，结果中会注明这一点。
- 由于使用高级模型，会产生 LLM 费用。如不需要，可以通过 `intel.research_enabled: false` 停用。
- 结果摘要是 LLM 的输出。在做出重要判断之前，请务必核实出处。

## 主要设置（`intel.*`）

| 键 | 默认 | 说明 |
|---|---|---|
| `enabled` | true | 整个情报功能 |
| `sync_interval_minutes` | 360 | 同步间隔 |
| `sources` | 全部 true | 各数据源的启用 / 禁用（`kev`, `epss`, `nvd`, `osv`, `jvn`, `ghsa`, `rss`） |
| `rss_feeds` | 5 个 | 要导入的 RSS URL |
| `research_enabled` / `research_interval_hours` | true / 12 | Web 调研 |
| `research_topics` | 0day、AI 驱动攻击 2 项 | 调查主题 |
| `epss_alert_threshold` | 0.1 | 视为 EPSS 急剧上升的阈值 |
| `nvd_lookback_days` | 3 | 回溯获取 NVD 数据的天数 |
