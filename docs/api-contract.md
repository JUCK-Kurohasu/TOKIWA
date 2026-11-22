# API 契約（/api/v1）

> フロントエンドとバックエンドの約束。スキーマ名は `backend/src/tokiwa/schemas/*.py`、
> TS 型は `frontend/src/api/types.ts`。**エンドポイントを追加・変更したらここを更新**する。
> 「担当」は初期実装の担当モジュール（ルートファイル名）。

共通:
- 認証: ユーザーは `Authorization: Bearer <JWT>`（SSE は `?access_token=`）。JWT はクレーム `ver` に `users.token_version` を持ち、パスワード・ロール変更／ログアウト／`revoke-sessions` で版数が上がると 401 `token revoked`（`ver` の無い旧 JWT は版数 0 として扱う）。センサーは `X-Tokiwa-Token: tkw_...`。
- 一覧は `Page[T]` = `{items, total, limit, offset}`。クエリ `limit`（既定 50, 最大 500）, `offset`（最大 1,000,000。超過は 422）。
  バックエンドは共通ヘルパ `tokiwa.api.pagination`（`page: PageParams` 依存性 + `await paginate(session, stmt, page, Schema.model_validate)`）を使う。
  独自に `offset` Query を宣言しているルートにも、全ルーターに付く `offset_guard` が同じ上限を課す。
- 時刻は ISO8601 UTC。エラーは FastAPI 標準 `{detail}`。一意制約などの整合性違反（`IntegrityError`）は 409。
- 書き込みは応答の送信前にコミットされる（`DbSession` は `scope="function"`）。2xx を受け取った直後の再読込には反映済み。
- ロール: viewer=閲覧, analyst=アラート/インシデント/対処の操作, admin=ユーザー/トークン/設定。
  viewer にはイベントを **伏字済み射影** で返す（`tokiwa.api.visibility`、監査 #157）: `http.query`・`http.request_body`・
  ヘッダ値（user-agent/host/content-type/accept/content-length 以外）・referrer のクエリ・`raw`・Gate 以外の `message`・
  `process.cmdline`・`llm_app.prompt`・`deception.token` を `[redacted: analyst role required]` に置換（`raw` は null）。
  対象: `GET /events`・`/events/{id}`・`/sessions/{id}` の events・`/alerts/{id}` の evidence・`/deception/trips`。

## 認証・ユーザー（`routes/auth.py` 実装済, `routes/users.py`, `routes/tokens.py`）
| Method | Path | 権限 | 入出力 |
|---|---|---|---|
| GET | /auth/status | public | → `AuthStatus {setup_required, version, setup_code_required}` |
| POST | /auth/setup | public(初回のみ) | `SetupRequest`（`UserCreate` + `setup_code`。`schemas/auth.py`）→ `TokenResponse`。`auth.setup_code_required`（既定 true）のとき、起動ログと `data_dir/setup-code` に出る 1 回限りのコードが無い・違うと 403。一度セットアップしたら（ユーザーが 0 人になっても）再開しない（409）。同時実行でも作られる管理者は 1 人 |
| POST | /auth/login | public | `LoginRequest`（username ≤128 / password ≤1024 文字）→ `TokenResponse`。失敗は 401 `invalid credentials`（存在しないユーザーでも同じ時間）。同じユーザー名 × 送信元 IP で `auth.login_max_failures` 回、送信元 IP で `auth.login_max_failures_per_ip` 回失敗すると `auth.login_lockout_minutes` の窓の間 429 + `Retry-After`。成功・失敗を `auth.login.success` / `auth.login.failure` として監査に記録 |
| GET | /auth/me | user | → `User` |
| POST | /auth/logout | user | → 204。そのユーザーの **全端末の** JWT を失効（`users.token_version` を上げる）。監査 `auth.logout` |
| GET | /users | admin | → `User[]` |
| POST | /users | admin | `UserCreate` → `User`（201。重複 username は 409） |
| PATCH | /users/{id} | admin | `UserUpdate {role?, password?}`（`schemas/users.py`）→ `User`。最後の admin は降格不可（409。同時実行でも直列化）。待っている間に自分が降格・削除されていたら 403 |
| POST | /users/{id}/revoke-sessions | admin | → 204。対象ユーザーの JWT をすべて失効（404 = いない）。監査 `user.sessions_revoked` |
| DELETE | /users/{id} | admin | → 204。自分自身は削除不可（400）、最後の admin は削除不可（409。同時実行でも直列化）。待っている間に自分が降格・削除されていたら 403 |
| GET | /tokens | admin | → `ApiToken[]` |
| POST | /tokens | admin | `ApiTokenCreate {name, scopes, allowed_sensor_ids?, allowed_datasets?, expires_in_days?}` → `ApiTokenCreated`（201。平文は一度だけ。scopes 省略時は `[ingest]`（`gate` は明示が必要、監査 #33）、空は 422。`allowed_*` は省略/null=無制限、空配列は 422） |
| POST | /tokens/{id}/rotate | admin | `ApiTokenRotate {grace_hours=24 (0..720), expires_in_days?}` → `ApiTokenCreated`（201。同じ name/scopes/縛りの新トークン、`rotated_from`=旧 id。旧トークンは grace_hours 後に期限切れ、0 なら即失効。失効済み/期限切れは 409） |
| DELETE | /tokens/{id} | admin | revoke → 204（冪等。行は監査のため残す） |

users / tokens の変更はすべて `audit_log` に記録（パスワード・トークン平文は記録しない）。認証イベント: `auth.setup` / `auth.setup.failure`（セットアップコード誤り。送信元 IP 単位で `/auth/login` と同じ 429 制限）/ `auth.login.success` / `auth.login.failure`（details: `client_ip`, `known_user`, `locked`）。
`ApiToken` は `expires_at`（null=無期限。期限切れは token 認証で 401 `API token expired`）、`created_by`（作成者のユーザー名、CLI は `cli`）、
`rotated_from` を持つ。CLI `tokiwa token list|revoke|rotate` も同じ処理（`tokiwa.auth.api_tokens`）で監査に actor `cli` を残す。

## 取り込み（`routes/ingest.py` 実装済）
| POST | /ingest/events | token:ingest | `IngestBatch` → `IngestResult`。トークンに `allowed_datasets` があり範囲外の dataset を含むバッチは **丸ごと 403**（Gate の送信側は 403 を恒久エラーとしてバッチを破棄する） |

出所の記録（監査 #40）: サーバーは全イベントの `labels` に `ingest.token_id` / `ingest.token`（送ってきたトークンの id / 名前）を
付ける。クライアントが送った `ingest.*` ラベルは先に捨てる。トークンに `allowed_sensor_ids` があれば `sensor_id` をその中に強制し、
主張された値は `ingest.claimed_sensor_id` に残す（無制限トークンは従来どおり、未指定時のみ `token:<name>` で補完）。
`gate` スコープを持たないトークンが `gate.*` / `deception.*` dataset または kind=deception を送ると `ingest.trust=low` を付ける（受理はする）。

## イベント（`routes/events.py`）
| GET | /events | user | `?kind&dataset&source_ip&session_id&host&q&since&until&limit&offset` → `Page[Event]`（新しい順。`q` は HTTP path / UA の部分一致・大小無視） |
| GET | /events/{id} | user | → `Event` |
| GET | /events/stats/timeline | user | `?hours=24&bucket_minutes=60` → `EventTimeline {bucket_minutes, buckets:[{ts, total, by_kind:{}}]}`（hours ≤ 168、バケット ≤ 2000、ts はエポック整列のバケット開始） |

## アラート（`routes/alerts.py`）
| GET | /alerts | user | `?status&severity&category&source_ip&q&min_ai_score&incident_id&limit&offset` → `Page[Alert]` |
| GET | /alerts/{id} | user | → `AlertDetail`（evidence 付き） |
| PATCH | /alerts/{id} | analyst | `AlertUpdate` → `Alert` |
| POST | /alerts/{id}/triage | analyst | `?tier=fast|deep` → `Alert`（強制トリアージ） |

## インシデント（`routes/incidents.py`）
| GET | /incidents | user | `?status&severity&actor_type&limit&offset` → `Page[Incident]` |
| GET | /incidents/{id} | user | → `IncidentDetail` |
| PATCH | /incidents/{id} | analyst | `IncidentUpdate` → `Incident` |
| POST | /incidents/{id}/triage | analyst | → `Incident` |

## アクターセッション（`routes/sessions.py`）
| GET | /sessions | user | `?min_ai_score&classification&source_ip&limit&offset` → `Page[ActorSession]` |
| GET | /sessions/{id} | user | → `{session: ActorSession, events: Event[] (最大200), timeline:[{t, path, status, gap_ms, method, kind, event_id, error, band}]}`（`gap_ms` = 直前の HTTP 要求からの ms、`band` = burst/mid/think/long。`features.indicators/scores` は docs/detection/ai-attacks.md） |

## ダッシュボード（`routes/dashboard.py`）
| GET | /dashboard/summary | user | → `{alerts_24h:{total, by_severity:{}}, open_incidents, ai_sessions_24h, events_24h, llm_cost_today_usd, llm_budget_usd, pending_actions, kev_matches, top_sources:[{ip,count,ai_score}], top_rules:[{rule_id,title,count}], recent_incidents: Incident[]}` |
| GET | /dashboard/timeline | user | `?hours=24&bucket_minutes?` → `DashboardTimeline {bucket_minutes, buckets:[{ts, events, alerts, ai_alerts}]}`（bucket 省略時は ≤ 36 本になる幅を自動選択） |

スキーマは `schemas/dashboard.py`（`DashboardSummary` / `DashboardTimeline`）。定義: alerts_24h = last_seen が 24h 以内、
open_incidents = resolved / false_positive 以外、ai_sessions_24h = classification=ai_agent または ai_score ≥ `detection.ai_agent_threshold`、
ai_alerts = category=ai_agent または ai_score ≥ 同閾値、llm_cost_today_usd = ゲートウェイの予算判定と同じ直近 24h 合計、
top_* の count = アラートの重複排除カウント合計。テーブルが空でも 0 を返す。応答は 5 秒メモリキャッシュ。

## ホスト・資産（`routes/hosts.py`, `routes/assets.py`）
| GET | /hosts | user | → `HostSummary[]` = `[{host, ports_open, last_seen, deviations}]`（deviations = どのベースラインにも許可されない open listener 数） |
| GET | /hosts/ports | user | `?host&open` → `HostPort[]`（{id,host,protocol,bind_ip,port,pid,process_name,first_seen,last_seen,open,allowed}。closed も含む） |
| GET | /hosts/baselines | user | `?host`（指定時は host と `*` の両方）→ `PortBaseline[]`（{id,host,protocol,port,process_name,allow_public,note,created_at}） |
| POST | /hosts/baselines | analyst | `PortBaselineIn` = `{host?, protocol, port, process_name?, allow_public, note?}` → `PortBaseline`（host 省略は `*`、protocol は tcp/udp に正規化、同一キーは upsert） |
| DELETE | /hosts/baselines/{id} | analyst | → 204（無ければ 404） |
| POST | /hosts/baselines/learn | analyst | `{host}` 現在の open listener のうち未許可のものをベースライン化 → **作成した** `PortBaseline[]`（全 IF バインドは allow_public=true。未知ホストは 404） |
| GET | /assets | user | `?q&kind` → `Page[Asset]` |
| POST | /assets | analyst | `AssetIn` → `Asset`（201。作成後にバックグラウンドで脆弱性照合） |
| GET/PATCH/DELETE | /assets/{id} | user/analyst | PATCH は部分更新（software 変更で再照合）、DELETE は 204（一致も削除） |

## 検知・ルール（`routes/detectors.py`, `routes/rules.py`）
| GET | /detectors | user | → `DetectorInfo[]` |
| PATCH | /detectors/{id} | analyst | `{enabled}` → `DetectorInfo` |
| GET | /rules | user | `?status&source&q&limit&offset` → `Page[Rule]`（`meta`: sigma_id, level, tags, mitre, category, logsource, kinds, falsepositives; builtin は rule_key, path） |
| POST | /rules | analyst | `RuleIn` → `Rule`（Sigma 検証エラーは 422 `{detail: "invalid Sigma rule: ..."}`、Sigma id 重複は 409） |
| GET/PATCH/DELETE | /rules/{id} | user/analyst | PATCH `{content?, status?}` → `Rule`。builtin は content 変更・削除不可（409、status のみ可）。DELETE → 204 |
| POST | /rules/validate | analyst | `{content}` → `{valid, errors[], title?}` |
| POST | /rules/{id}/approve | analyst | proposed → active（再検証。proposed 以外は 409） |
| POST | /rules/reload | analyst | `rules/sigma` を再同期して再読込 → `{active_rules, errors: {source: [msg]}}` |

## インテル（`routes/intel.py`）
| GET | /intel/vulns | user | `?q&kev&min_epss&min_cvss&matched&source&severity&limit&offset` → `Page[VulnRecord]`（既定順: KEV→EPSS→CVSS→modified） |
| GET | /intel/vulns/{id} | user | → `{vuln: VulnRecord, matches: VulnMatch[], advisories: Advisory[]}`（id は CVE または GHSA/JVNDB エイリアス） |
| GET | /intel/matches | user | `?status&asset_id&vuln_id&kev&min_confidence` → `Page[VulnMatch]`（追加: `asset_name, asset_criticality, vuln_title, kev, epss, cvss_score`。KEV→EPSS→confidence 順） |
| PATCH | /intel/matches/{id} | analyst | `{status}` |
| POST | /intel/matches/rescan | analyst | 全資産×全脆弱性を再照合 → `{evaluated_vulns, matches, new, updated, closed}` |
| GET | /intel/advisories | user | `?priority&status&vuln_id&since` → `Page[Advisory]`（新しい順） |
| GET | /intel/advisories/{id} | user | → `Advisory` |
| POST | /intel/advisories/generate | analyst | `{vuln_id, force?}` → `Advisory`（7 日以内の同等アドバイザリがあればそれを返す。force で再生成） |
| PATCH | /intel/advisories/{id} | analyst | `{status}` |
| GET | /intel/news | user | `?source&q&vuln_id` → `Page[IntelItem]`（`source=rss` は `rss:<host>` 全件） |
| GET | /intel/research | user | → `Page[ResearchReport]` |
| GET | /intel/research/{id} | user | → `ResearchReport` |
| POST | /intel/research/run | analyst | `{topic?}` → `ResearchReport`（topic 省略時は設定の全トピックを 1 回で。LLM 失敗は 503） |
| GET | /intel/sources | user | → `[{id, name, enabled, last_sync, last_error, records, last_attempt, vulns_created, vulns_updated, items_created, duration_ms, running, attribution}]` |
| POST | /intel/sync | analyst | `{source?}` → `{started: true, sources: string[]}`（未知 source は 404、実行中/有効ソースなしは 409） |

## 対処（`routes/response.py`）・Gate ポリシー（`routes/gate.py`）
| GET | /response/actions | user | `?status&incident_id&limit&offset` → `Page[ResponseAction]` |
| GET | /response/actions/{id} | user | → `ResponseAction` |
| POST | /response/actions | analyst | `ActionProposal` → `ResponseAction`（status=proposed。重複は既存を返す。検証エラー 422） |
| POST | /response/actions/{id}/approve | analyst | → `ResponseAction` |
| POST | /response/actions/{id}/reject | analyst | `{reason?}` → `ResponseAction` |
| POST | /response/actions/{id}/revert | analyst | → `ResponseAction` |
| GET | /gate/policy | token:gate | → `GatePolicy`（`ETag: "<version>"`、`If-None-Match` 一致で 304）。200 / 304 とも取得を Gate（トークン + 送信元アドレス）ごとに記録（`gate_polls` テーブル） |
| GET | /gate/status | user | → `GateStatus`（`schemas/gate_status.py`）: `{generated_at, current_version, stale_after_seconds, gates:[{token_name, source_ip, first_seen, last_seen, last_version, last_status, fetch_count, current, stale}], actions:[{action_id, active_since, gates_applied, gates_applied_fresh, last_applied_at}]}`。`actions` は有効な Gate 系アクション（block_ip / rate_limit / tarpit / deceive）ごとに「有効化後にポリシーを取得した Gate 数」。`stale` は最終取得から `stale_after_seconds`（max(120, gate.policy_refresh_seconds×12)）超 |

## デセプション（`routes/deception.py`）
| GET | /deception/assets | user | `?kind&enabled` → `DeceptionAsset[]` |
| POST | /deception/assets | analyst | `DeceptionAssetIn` → `DeceptionAsset`（422 検証 / 409 重複） |
| GET | /deception/assets/{id} | user | → `DeceptionAsset` |
| PATCH | /deception/assets/{id} | analyst | `DeceptionAssetUpdate`（`schemas/deception.py`。`token: null` でローテーション） |
| DELETE | /deception/assets/{id} | analyst | 204 |
| GET | /deception/trips | user | `?asset_id&source_ip&limit&offset` → `Page[Event]`（トリップしたイベント。`deception` 情報付き） |
| GET | /deception/preview/{id} | analyst | `?path` → `DeceptionPreview`（`{asset_id, path, content_type, body, status_code, headers, served, extra_paths}`） |

## 通知（`routes/notify.py`）
| GET | /notify/channels | admin | → `NotificationChannel[]`（秘密はマスク） |
| POST | /notify/channels | admin | `NotificationChannelIn` → `NotificationChannel` |
| PATCH/DELETE | /notify/channels/{id} | admin | |
| POST | /notify/channels/{id}/test | admin | → `{ok, error?}` |

## LLM（`routes/llm.py`）
| Method | Path | 権限 | 入出力 |
|---|---|---|---|
| GET | /llm/config | user | → `LLMConfigOut` `{provider, active_provider, available, model_fast, model_deep, effort_fast, effort_deep, daily_budget_usd, spent_today_usd, output_language, enable_fallbacks, prompt_cache, max_output_tokens, max_input_tokens_per_call, request_timeout_seconds, anthropic_base_url, openai_base_url, anthropic_api_key_set, openai_api_key_set, overridden[], unpriced_models[]}` |
| PUT | /llm/config | admin | `LLMConfigUpdate`（部分更新。省略=変更なし、`null`=静的設定に戻す。未知フィールドは 422）→ `LLMConfigOut`。settings_kv `llm.config` に保存し gateway を再構築。`anthropic_api_key` / `openai_api_key` は書き込み専用（`""`/`null` で削除） |
| GET | /llm/models | user | → `{source: api\|builtin, models:[{id, display_name?, max_input_tokens?}], error?}`。設定画面の Anthropic モデル選択用。gateway が Anthropic のときは `GET /v1/models`（有効・構造化出力対応のモデルのみ、5 分キャッシュ）、それ以外・取得失敗時は内蔵一覧（`error` に理由）。LLM 呼び出しではないので予算・監査の対象外 |
| GET | /llm/usage | user | `?days=14`（1〜366, UTC 日単位, 古い順, 0 件の日も含む）→ `{days:[{date, cost_usd, calls, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, by_purpose:{purpose: cost_usd}, by_purpose_calls:{purpose: calls}, unpriced_calls}], unpriced_models[]}` |
| GET | /llm/calls | user | `?purpose&status&limit&offset` → `Page[LLMCall]`（新しい順） |
| GET | /llm/calls/{id} | admin | → `LLMCallDetail`（マスキング済み入力 `request_redacted` と `response_text`） |
| POST | /llm/test | admin | `?tier=fast\|deep`（既定 fast）→ `{ok, provider, model, latency_ms, status, error?}`（最小の構造化呼び出し。予算・監査が適用される） |

- `provider` は設定値（`auto|anthropic|openai_compat|mock`）、`active_provider` は実際に使われているプロバイダ（auto 解決後）。
  フォームの往復では `provider` を使う。`overridden` は実行時オーバーレイで上書き中のフィールド名。
- **API キーはどのレスポンスにも含まれない**（`*_api_key_set` の真偽のみ）。base URL は資格情報部分をマスクして返す。
- `spent_today_usd` は直近 24 時間のローリング合計（予算判定と同じ）。`/llm/usage` の日付は UTC 暦日。
- 費用は fail-closed（#35）: 単価表（`llm/pricing.py` + `llm.pricing`）にないモデルは最も高い既知単価で見積もる。
  `LLMCall.cost_basis` = `table`（表にある ID）/ `snapshot`（日付・版・Bedrock 接頭辞を除いた ID が表にある）/ `unpriced`（見積もり）/
  `null`（課金なし: mock・トークン 0・#35 以前の行）。`unpriced_calls` は `cost_basis=unpriced` の呼び出し数、
  `LLMConfigOut.unpriced_models` は設定中のモデルのうち単価が無いもの（mock では空）。
- `effort_*` は `low|medium|high|xhigh|max`。`output_language` は `ja|en`。

## コパイロット（`routes/copilot.py`）
会話の作成・メッセージ送信は `copilot.min_role`（既定 analyst）以上。送信はユーザーごとに `copilot.messages_per_minute`（既定 6/分、0=無制限）を超えると 429 + `Retry-After`（監査 #164）。

| GET | /copilot/conversations | user | `?all=true`(admin のみ全ユーザー分) → `[{id,title,owner,context,created_at,updated_at}]` |
| POST | /copilot/conversations | `copilot.min_role`（既定 analyst。未満は 403） | `{title?, context?:{incident_id?,alert_id?,session_id?,source_ip?,vuln_id?,asset_id?}}` → conversation (201) |
| GET | /copilot/conversations/{id} | owner/admin | → `{conversation, messages:[{id, role, content, created_at, tool_calls?, tool_results?, llm_call_id?}]}` |
| DELETE | /copilot/conversations/{id} | owner/admin | 204 |
| POST | /copilot/conversations/{id}/messages | owner | `{content}`(1–8000 字) → **SSE**: `data: {"type":"text"|"tool_call"|"tool_result"|"done"|"error", ...}`（403=ロール不足, 409=応答生成中, 429=送信レート超過, 503=copilot.enabled=false） |

コパイロット補足（実装: `tokiwa/copilot/`）:
- `role`: `user` / `assistant` / `tool`（ツール結果。`tool_results:[{tool_use_id,name,ok,summary}]`）/ `notice`（UI 表示専用。LLM 未設定・エラー・上限到達。LLM には再送しない）。他人の会話は 404。
- SSE ペイロード: `text {text, final, message_id}` / `tool_call {id, name, input}` / `tool_result {id, name, ok, summary}`（データ本体は流さず要約のみ）/
  `error {code: error|budget_exceeded|refused|max_tool_iterations|busy|internal, error, message_id?}` / `done {conversation_id, stop_reason: end_turn|llm_not_configured|refused|max_tool_iterations|error|busy, message_id, iterations, llm_call_ids}`。必ず `done` で終わる。
- LLM 未設定（mock）時は設定案内を `text` で返し `stop_reason=llm_not_configured`。
- ツール（参照専用のみ）: search_events, get_alert, list_alerts, get_incident, list_incidents, get_session, top_sources, lookup_vuln, list_vuln_matches, get_asset, list_actions。
- 設定 `copilot.*`: `enabled`, `max_tool_iterations`(chat 呼び出し上限), `max_history_messages`, `tier`(fast|deep, 既定 deep), `max_tool_result_chars`(既定 12000), `min_role`(既定 analyst), `messages_per_minute`(既定 6)。

## システム（`routes/system.py`）・ストリーム（`routes/stream.py`）
| GET | /system/info | user | → `SystemInfo` |
| GET | /system/jobs | user | → `JobInfo[]` |
| POST | /system/jobs/{name}/run | admin | → `JobInfo`（バックグラウンド起動して即返す。実行中なら二重起動しない。未知は 404） |
| GET | /audit | admin | `?action&actor&limit&offset` → `Page[AuditEntry]`（新しい順） |
| GET | /audit/access | admin | `?actor&route(完全一致 or 末尾*で前方一致)&target&since&limit&offset` → `Page[AccessLogEntry {id, created_at, last_at, actor, actor_id, role, route, target, filters, hits, items}]`（閲覧監査、監査 #167。`routes/access_log.py`） |

閲覧監査（`tokiwa.access_log`、テーブル `access_log`）: `events.list` / `events.get` / `sessions.list` / `sessions.get` /
`llm.calls.get` / `copilot.tool.<name>` を記録。同じ actor(id)・route・target・filter の閲覧は 5 分窓で 1 行にまとめ
（`hits` = 回数、`items` = 返した件数の合計）、窓の最初の 1 回だけ INSERT、以降はメモリ上で加算し窓の切替時と
`GET /audit/access` の直前に書き戻す（ポーリングで行が増えず、GET が毎回書き込みにならない）。
| GET | /stream | user(`?access_token`) | **SSE**: `data: {"topic": "...", "data": {...}}`（alert/incident/action/deception/llm.call） |

stream の詳細: 接続直後にコメント `: connected`、15 秒ごとに `: ping` コメント。中継トピックは `alert.*` / `incident.*` /
`action.*` / `deception.tripped` / `intel.advisory` / `llm.call`（`request_redacted`・`response_text` は除外）/
`event.ingested`（`{"count": n}` のみ）。`?access_token=` の値は uvicorn アクセスログでマスクされる。
| GET | /health | public | `{"status": "ok"}`。有効なユーザー JWT 付きのときだけ `version` も返す（DB 障害時も 200） |

未定義の `/api/*` は SPA の index.html ではなく JSON の 404（`{"detail": "Not Found"}`）。`/api/docs`・`/api/openapi.json` は
`server.expose_docs`（既定 true、本番は false 推奨）で無効化できる。ReDoc（旧 `/redoc`）は提供しない。
