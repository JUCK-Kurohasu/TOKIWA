# Sigma ルール（検知カタログ / 仕様）

TOKIWA は Sigma ルールを **TOKIWA の `Event` に対してインメモリで直接評価** する（pySigma のような
バックエンド変換はしない）。実装: `backend/src/tokiwa/detect/sigma/`、検知器 `detectors/sigma.py`（id `sigma`）。

## 1. ルールの出どころ

| 出どころ | 場所 | `rules.source` | 評価条件 | 編集 |
|---|---|---|---|---|
| 組み込み | `rules/sigma/**/*.yml`（`settings.detection.sigma_rule_dirs`） | `builtin` | 行の `status=active` | 内容はファイルで。API では status のみ |
| ユーザー | `POST /api/v1/rules` | `user` | `status=active` | API で全項目 |
| LLM 提案 | intel-advisor が `validate_rule()` で検証して保存 | `llm` | 人間が `/approve` するまで `proposed`（発火しない） | API |

- 起動時（`@on_startup`）にファイルを `rules` テーブルへ `source=builtin` で同期する（`meta.rule_key` で対応付け。
  内容はファイルに追従、status と hit_count は保持。ファイルが消えた行は削除）。`POST /rules/reload` でも同期。
- 不正なルールはスキップしてログに出す（`get_rule_store().errors`、`/rules/reload` の応答）。
- ルール変更 API は commit 後にストアを再読込するので **次に取り込んだイベントから反映** される。
- `hit_count` はメモリで集計し、60 秒ごとのジョブ（`sigma.flush_hits`）・シャットダウン時・
  `GET /rules` / `GET /rules/{id}` の直前にまとめて DB へ書く（検知ループでは DB に書かない）。
- 検知器 `sigma` を `PATCH /detectors/sigma {enabled:false}` で止めると全 Sigma ルールが止まる。

## 2. 対応する Sigma サブセット

- トップレベル: `title`（必須）, `id`（任意・UUID 推奨・64 文字以内）, `status`（stable/test/experimental/deprecated/
  unsupported）, `level`（informational/low/medium/high/critical、省略時 medium）, `description`, `author`, `tags`,
  `references`, `falsepositives`, `logsource`（必須）, `detection`（必須）。その他のキーは無視（Sigma のカスタム属性）。
- 1 ファイル 1 ルール。複数ドキュメント（rule collection / `action: global`）は非対応。
- selection: map（AND）/ map のリスト（OR）/ 値のリスト（キーワード検索）。値のリストは OR、`|all` で AND。
- 修飾子: `contains startswith endswith all re(+i m s) cidr base64 base64offset windash cased lt lte gt gte exists`。
  **未知の修飾子は検証エラー**（`expand`, `utf16le`, `wide`, `fieldref` なども現状は未対応＝エラー）。
- ワイルドカード `*` `?`、エスケープ `\*` `\?` `\\`（それ以外の `\` はリテラル）。`field: null` は「値なし」。
- condition: `and or not ( )`、`1 of sel*` / `all of sel*` / `N of ...` / `any of ...` / `... of them`
  （`them` は `_` で始まる識別子を除く）、condition のリストは OR。**集約（`| count() ...`）は非対応＝エラー**。
  `timeframe` は受け付けるが無視。

### 照合セマンティクス（Sigma 既定に準拠）

- 文字列比較は大文字小文字を区別しない。`|cased` で区別。`|re` は区別（`|re|i` で非区別）、`re.search`（非アンカー）。
- `base64` / `base64offset` は base64 文字列が大小文字で意味を持つため **自動的に cased**。
- フィールドがリスト（`tags` 等）の場合はいずれかの要素が一致すれば真。
- キーワード（フィールド名なし）は暗黙の contains で、message / http.path / query / body / UA / referer /
  llm_app.prompt / ids.signature / process.cmdline / deception.detail を検索する。
- 64KB を超える値は先頭 64KB のみ照合（ユーザー正規表現のコスト上限）。

### TOKIWA 独自の扱い（調整可能点）

- **URI 系フィールド（path / query / `c-uri` / body）は生値と URL デコード値（最大 2 段）の両方で照合**。
  `|contains: '../'` が `%2e%2e%2f` にも一致する。厳密な「ログ行そのまま」照合が必要ならこの挙動は `fieldmap.py`
  の `_decoded_variants` で変更する。
- 参照フィールドが TOKIWA のイベントに存在しない場合は **検証エラー**（決して発火しないルール、特に LLM 提案の幻覚を早期に弾く）。
- logsource が TOKIWA の取り込み対象でない場合も **検証エラー**（例: `product: windows` のみ、`category: registry_event`）。

## 3. logsource → イベント種別

| logsource | EventKind |
|---|---|
| `category: webserver` / `proxy` / `web` / `http` | `http` |
| `category: llm_app` / `llm` | `llm_app` と `http`（http は `detection.llm_app_paths` 宛ての body を `prompt` として扱う） |
| `category: network_connection` / `firewall` | `connection` |
| `category: dns` / `dns_query` | `dns` |
| `category: process_creation` | `process` |
| `category: authentication` | `auth` |
| `category: ids` | `ids_alert` |
| `category: deception` | `deception` |
| `category: port_change` | `port_change` |
| `product: tokiwa`（category なし） | `service: <EventKind 値>` または `service: gate`（=http）。service なしは全種別 |

`category` があればそれで決まる（`product: nginx` 等は情報扱い）。

## 4. フィールドマッピング（主なもの。大文字小文字は区別しない）

| Event 属性 | Sigma / ECS 名 |
|---|---|
| `http.path` | `cs-uri-stem`, `c-uri-stem`, `url.path`, `http.path`, `path` |
| `http.query` | `cs-uri-query`, `c-uri-query`, `url.query`, `query` |
| path + `?` + query | `c-uri`, `cs-uri`, `url.original`, `uri`, `request` |
| scheme://host/path?query | `url.full` |
| 拡張子 | `c-uri-extension`, `url.extension` |
| `http.method` | `cs-method`, `http.request.method`, `method` |
| `http.status` | `sc-status`, `http.response.status_code`, `status` |
| `http.user_agent`（無ければ header） | `c-useragent`, `cs-user-agent`, `user_agent.original`, `useragent` |
| `http.referrer`（無ければ header） | `cs-referer`, `cs-referrer`, `http.request.referrer`, `referer` |
| header `cookie` | `cs-cookie` |
| `http.host` | `cs-host`, `r-dns`, `url.domain`, `destination.domain` |
| `http.request_body` | `request_body`, `http.request.body.content`, `cs-body`, `body` |
| `http.content_type` / sizes / version | `cs-content-type`, `cs-bytes`, `sc-bytes`, `cs-version`, `time-taken` |
| `source.ip` / `source.port` | `c-ip`, `src_ip`, `source.ip`, `clientip` / `c-port`, `src_port`, `source.port` |
| `destination.ip` / `.port` | `s-ip`, `dst_ip`, `destination.ip` / `s-port`, `dst_port`, `destination.port`, `DestinationPort` |
| LLM プロンプト | `prompt`, `llm.prompt`, `llm_app.prompt`, `gen_ai.prompt` |
| `llm_app.app/model/role/tool_names` | `llm.app`, `llm.model`, `llm.role`, `llm.tool_names` |
| `ids.signature/signature_id/category` | `signature`, `alert.signature`, `signature_id`, `alert.category` |
| process（top-level または network.process） | `Image`, `CommandLine`, `User`, `ProcessId`, `process.*` |
| メタ | `dataset`, `kind`, `message`, `sensor_id`, `session_id`, `asset_id`, `tags`, `host.name`, `hostname` |

上記以外は Event のドット区切りパスで参照可能（例 `http.headers.x-forwarded-for`, `labels.env`,
`source.geo_country`, `deception.asset_kind`, `port.listeners.port`）。dict 属性（headers / labels / raw）は任意キー可。

## 5. アラートへの変換

| AlertDraft | 値 |
|---|---|
| `rule_id` | `sigma:<Sigma id>`（id が無ければ `sigma:file:<相対パス>` / `sigma:db:<行 id>`） |
| `detector` | `sigma` |
| `severity` | level: informational→info, low, medium, high, critical |
| `confidence` | status: stable 0.85 / test 0.75 / experimental 0.65 / deprecated・unsupported 0.5 |
| `mitre` | `attack.t1190` → `T1190`, `attack.t1059.007` → `T1059.007` |
| `category` | `tokiwa.category.<AlertCategory>` タグ > logsource（llm_app→prompt_injection, deception, ids, port_change）> 最初の ATT&CK 戦術タグ（reconnaissance/discovery→recon, credential_access→credential_attack, その他→exploit_attempt）> other |
| `ai_score` | `tokiwa.ai_score.<0-100>` タグ（例 `tokiwa.ai_score.60` = 0.6）。無ければ None |
| `tags` | `["sigma", *rule.tags]` |
| `entities` | `host`, `path`, `llm_app` |
| `details` | `sigma_id`, `rule_ref`（rules 行 id → `GET /rules/{rule_ref}`）, `rule_origin`, `rule_path`, `level`, `matched`（真になった selection 名）, `falsepositives`, `logsource` |
| `fingerprint` | 既定（`rule_id|source_ip`）で重複排除 |

## 6. 初期ルールセット（rules/sigma/, 25 本）

| ファイル | 内容 | level |
|---|---|---|
| web/web_sqli_union_select | UNION [ALL] SELECT（コメント難読化含む） | high |
| web/web_sqli_time_based | SLEEP / PG_SLEEP / BENCHMARK / WAITFOR DELAY | high |
| web/web_path_traversal | `../`（デコード後含む）、/etc/passwd, win.ini | high |
| web/web_log4shell_jndi | `${jndi:` と難読化 | critical |
| web/web_cmd_injection | `;id`, `\|whoami`, `$(…)`, `curl http`, `nc -e` | high |
| web/web_sensitive_file_probe | /.env, /.git/config, backup.sql, /actuator/env … | medium |
| web/web_scanner_useragent | sqlmap, nuclei, ffuf, Nmap NSE … | medium |
| web/web_ssti_probe | `{{7*7}}`, `${7*7}`, `__class__.__mro__` | high |
| web/web_ssrf_cloud_metadata | 169.254.169.254, metadata.google.internal, gopher:// | high |
| web/web_xss_probe | `<script`, `javascript:`, onerror= | medium |
| web/web_xxe_external_entity | `<!DOCTYPE` + `<!ENTITY` + SYSTEM | high |
| web/web_lfi_stream_wrapper | php://filter, expect://, file:/// | high |
| web/web_rare_http_method | TRACE/TRACK/DEBUG/WebDAV | low |
| web/web_serialized_object_payload | Java rO0AB / aced0005, .NET, PHP `O:n:"…"` | high |
| ai/ai_agent_manifest_discovery | /.well-known/ai-plugin.json, llms.txt, agent/MCP 発見文書 | low |
| ai/ai_api_schema_discovery | openapi.json, swagger.json, /v3/api-docs | low |
| ai/ai_graphql_introspection | `__schema`, IntrospectionQuery | medium |
| ai/ai_mcp_endpoint_probe | /mcp, JSON-RPC tools/list・tools/call、MCP initialize | medium |
| ai/ai_llm_agent_useragent | GPTBot, ClaudeBot, PerplexityBot … | informational |
| ai/ai_llm_artifact_in_payload | パラメータ内の ``` / "As an AI language model" / `<thinking>`（LLM アプリ宛ては除外） | medium |
| llm_app/llm_app_prompt_injection_override | "ignore all previous instructions"、「以前の指示を無視」 | high |
| llm_app/llm_app_system_prompt_extraction | "print your system prompt"、「システムプロンプトを教えて」 | medium |
| llm_app/llm_app_jailbreak_persona | "do anything now", "developer mode enabled" | medium |
| llm_app/llm_app_markdown_exfiltration | クエリ付き markdown 画像、"send the conversation to http…" | high |
| llm_app/llm_app_encoded_injection | base64offset で埋め込まれた上書き指示 | medium |

各ルールの陽性/陰性ケースと「正常トラフィックでは何も発火しない」テストは `backend/tests/sigma/test_sigma_ruleset.py`。
ルールを追加したら同ファイルの `CASES` にケースを追加する（無いとテストが落ちる）。

## 7. 既知の制約

- ボディが見えないログ（nginx/caddy アクセスログ）では body 系ルールは発火しない（Gate 経由で取得）。
- JSON ボディ内の `\uXXXX` エスケープは展開しないため、日本語フレーズがエスケープされて送られると一致しない。
- `|re` は Python `re`（タイムアウト無し）。入力は 64KB で打ち切るが、病的な正規表現を書かないこと。
  LLM 提案ルールは自動有効化されず人間承認が必要。
- 集約・相関（count/near/temporal）は非対応。窓集計は Python の検知器（`ctx.window`）で実装する。
- TODO(verify): `/.well-known/agent.json`（A2A Agent Card）/ `/.well-known/mcp(.json)` の正式パス、
  AI クローラ UA トークン名、MITRE ATLAS ID（AML.T0051/T0054/T0056）。各ルールファイル先頭のコメント参照。
