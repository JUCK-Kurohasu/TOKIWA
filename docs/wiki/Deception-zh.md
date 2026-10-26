> 🌐 [日本語](Deception) · [English](Deception-en) · **中文** · [Español](Deception-es)

# 欺骗防御（Mirage）

在本组织的资产上放置正常用户绝不会触碰的 **陷阱**，以高置信度检测触碰陷阱的对象。
陷阱由 Gate 下发，绝不会转发给要保护的应用。

## AI 金丝雀（反向提示注入）

这是 Mirage 的核心机制。在诱饵中嵌入“**只有 AI 智能体才会读取并遵循的隐藏指令**”。

- 人类用户看不到（使用 HTML 注释和隐藏元素，屏幕阅读器也不会朗读）。
- 指令的形式是“附带某个值发送特定请求头（默认 `X-Debug-Auth`）”“访问在 `/api/internal/` 后拼接该值的路径”等，
  **必须读懂并自行构造才能遵循**。
- 该值不会以链接（`href`）或 OpenAPI 示例的形式出现。因为如果机械地跟随链接的爬虫或模糊测试工具偶然
  “遵循”了指令，断定其为 AI 的依据就会失效。

收到遵循了指令的请求时，即可判断其为由 LLM 驱动的客户端（AI 评分 0.99）。

## 资产类型

| 类型 | 放置的内容 | 检测条件 |
|---|---|---|
| `decoy_path` | `/.env`、`/backup.sql`、`/admin/config.php`、`/.git/config`、`/api/internal/debug` 等。内容是伪造的凭据和 AI 金丝雀注记 | 访问该路径，或使用其中的伪造凭据 |
| `honeytoken` | 伪造的 AWS 密钥、API 密钥、数据库凭据 | 该值出现在任意事件中 |
| `ai_canary` | 隐藏指令。插入 HTML、`/robots.txt`、`/llms.txt`、类 OpenAPI 的 JSON 等 | **按指令使用了该值时**（仅获取页面不会被检测） |
| `labyrinth` | `/archive/` 下无限延伸的迷宫页面（默认 OFF） | 访问其下的页面。深度达到 3 及以上时严重级别为 critical |

伪造的凭据故意与真实服务的格式不同（例如 AWS 访问密钥 ID 不是真实的 20 个字符，而是
24 个字符）。即使万一泄露到外部，也无法当作真实凭据使用。

## 默认提供的资产

服务器启动时会自动创建以下资产（如果已存在则不做更改）。

- `deception.decoy_paths` 中列出的每个路径对应的 `decoy_path`
- AI 金丝雀：插入 HTML（启用）、`/api/internal/openapi.json`（启用）、`/robots.txt`（**禁用**）、`/llms.txt`（**禁用**）
- 仅在 `deception.labyrinth_enabled: true` 时创建迷宫

`/robots.txt` 和 `/llms.txt` 的金丝雀默认禁用，是因为它们会替换掉要保护的应用中同名的文件。
如需启用，请检查是否会与应用方的内容冲突。

> 即使 **删除** 资产，只要它仍保留在设置中，下次启动时就会重新出现。若要停用，请 **禁用** 它，或将其从设置中移除。

## 被检测到时

| 分类 | 严重级别 | 含义 |
|---|---|---|
| `ai_canary_followed` | critical | 遵循了 AI 金丝雀的指令（几乎可以断定为 AI 智能体。AI 评分 0.99） |
| `ai_canary_token` | critical | 金丝雀的值出现在其他地方（读取了隐藏文本的主体。也存在人类从源码中抄写的可能） |
| `honeytoken` | critical | 伪造的凭据被使用 |
| `decoy_path` | critical | 访问了诱饵路径 |
| `labyrinth` | high（深度 3 及以上为 critical） | 进入了迷宫 |

自动扫描器也会访问诱饵（`/.env` 等是常见的探测目标）。判断是否为 AI 智能体时，
请结合 `ai_canary_followed` 和 [AI sessions（AI 会话）](Web-UI-zh) 的行为评分一起判断。

## 界面操作

在 **Deception**（欺骗防御）页面中，可以查看资产列表、添加资产、启用 / 禁用、**预览下发内容**，以及查看 trip（触碰记录）列表。
也可以通过处置中的 `deploy_canary`，根据安全事件追加陷阱。

## 主要设置（`deception.*`）

| 键 | 默认 | 说明 |
|---|---|---|
| `enabled` | true | 整个欺骗防御功能 |
| `ai_canaries` | true | AI 金丝雀 |
| `decoy_paths` | 上述 5 个路径 | 默认创建的诱饵 |
| `html_injection` | true | 在要保护的应用的 HTML 响应中插入隐藏指令（`</body>` 之前） |
| `canary_header` | `X-Debug-Auth` | 隐藏指令要求发送的请求头名称。如果将其加入 `llm.redaction.sensitive_headers`，将无法检测 |
| `canary_language` | `both` | 隐藏指令的语言（`ja` / `en` / `both`） |
| `labyrinth_enabled` | false | 迷宫 |
| `labyrinth_prefix` / `labyrinth_max_depth` | `/archive/` / 8 | 迷宫的位置和深度 |

如果应用具有将页面 DOM 回传给服务器的机制（如会话回放等），请禁用 `html_injection`。

## 使用注意事项

- 陷阱 **只放置在本组织的资产上**。不对攻击来源进行反击，也不回传恶意软件类的载荷。
- 隐藏指令措辞的强度与语言、是否放置到 robots.txt / llms.txt，属于运营上的判断。引入时，
  请与组织的政策要求及法务负责人沟通确认。
