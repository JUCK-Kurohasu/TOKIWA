# API 契約（/api/v1）

> フロントエンドとバックエンドの約束。スキーマ名は `backend/src/tokiwa/schemas/*.py`、
> TS 型は `frontend/src/api/types.ts`。**エンドポイントを追加・変更したらここを更新**する。
> 「担当」は初期実装の担当モジュール（ルートファイル名）。

共通:
- 認証: ユーザーは `Authorization: Bearer <JWT>`（SSE は `?access_token=`）。センサーは `X-Tokiwa-Token: tkw_...`。
- 一覧は `Page[T]` = `{items, total, limit, offset}`。クエリ `limit`（既定 50, 最大 500）, `offset`。
  バックエンドは共通ヘルパ `tokiwa.api.pagination`（`page: PageParams` 依存性 + `await paginate(session, stmt, page, Schema.model_validate)`）を使う。
- 時刻は ISO8601 UTC。エラーは FastAPI 標準 `{detail}`。
- ロール: viewer=閲覧, analyst=アラート/インシデント/対処の操作, admin=ユーザー/トークン/設定。

## 認証・ユーザー（`routes/auth.py` 実装済, `routes/users.py`, `routes/tokens.py`）
| Method | Path | 権限 | 入出力 |
|---|---|---|---|
| GET | /auth/status | public | → `AuthStatus` |
| POST | /auth/setup | public(初回のみ) | `UserCreate` → `TokenResponse` |
| POST | /auth/login | public | `LoginRequest` → `TokenResponse` |
| GET | /auth/me | user | → `User` |
| GET | /users | admin | → `User[]` |
| POST | /users | admin | `UserCreate` → `User`（201。重複 username は 409） |
| PATCH | /users/{id} | admin | `UserUpdate {role?, password?}`（`schemas/users.py`）→ `User`。最後の admin は降格不可（409） |
| DELETE | /users/{id} | admin | → 204。自分自身は削除不可（400）、最後の admin は削除不可（409） |
| GET | /tokens | admin | → `ApiToken[]` |
| POST | /tokens | admin | `ApiTokenCreate` → `ApiTokenCreated`（201。平文は一度だけ。scopes 空は 422） |
| DELETE | /tokens/{id} | admin | revoke → 204（冪等。行は監査のため残す） |

users / tokens の変更はすべて `audit_log` に記録（パスワード・トークン平文は記録しない）。

## 取り込み（`routes/ingest.py` 実装済）
| POST | /ingest/events | token:ingest | `IngestBatch` → `IngestResult` |

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
| GET | /sessions/{id} | user | → `{session: ActorSession, events: Event[] (最大200), timeline:[{t, path, status, gap_ms}]}` |

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
| POST | /assets | analyst | `AssetIn` → `Asset` |
| GET/PATCH/DELETE | /assets/{id} | user/analyst | |

## 検知・ルール（`routes/detectors.py`, `routes/rules.py`）
| GET | /detectors | user | → `DetectorInfo[]` |
| PATCH | /detectors/{id} | analyst | `{enabled}` → `DetectorInfo` |
| GET | /rules | user | `?status&source` → `Page[Rule]` |
| POST | /rules | analyst | `RuleIn` → `Rule`（Sigma 検証エラーは 422） |
| GET/PATCH/DELETE | /rules/{id} | user/analyst | |
| POST | /rules/validate | analyst | `{content}` → `{valid, errors[], title?}` |
| POST | /rules/{id}/approve | analyst | proposed → active |

## インテル（`routes/intel.py`）
| GET | /intel/vulns | user | `?q&kev&min_epss&min_cvss&matched&limit&offset` → `Page[VulnRecord]` |
| GET | /intel/vulns/{id} | user | → `{vuln: VulnRecord, matches: VulnMatch[], advisories: Advisory[]}` |
| GET | /intel/matches | user | `?status` → `Page[VulnMatch]`（asset 名付き: `asset_name`） |
| PATCH | /intel/matches/{id} | analyst | `{status}` |
| GET | /intel/advisories | user | `?priority&status` → `Page[Advisory]` |
| GET | /intel/advisories/{id} | user | → `Advisory` |
| POST | /intel/advisories/generate | analyst | `{vuln_id}` → `Advisory` |
| PATCH | /intel/advisories/{id} | analyst | `{status}` |
| GET | /intel/news | user | `?source&q` → `Page[IntelItem]` |
| GET | /intel/research | user | → `Page[ResearchReport]` |
| POST | /intel/research/run | analyst | `{topic?}` → `ResearchReport` |
| GET | /intel/sources | user | → `[{id, name, enabled, last_sync, last_error, records}]` |
| POST | /intel/sync | analyst | `{source?}` → `{started: true}` |

## 対処（`routes/response.py`）・Gate ポリシー（`routes/gate.py`）
| GET | /response/actions | user | `?status&incident_id&limit&offset` → `Page[ResponseAction]` |
| GET | /response/actions/{id} | user | → `ResponseAction` |
| POST | /response/actions | analyst | `ActionProposal` → `ResponseAction`（status=proposed。重複は既存を返す。検証エラー 422） |
| POST | /response/actions/{id}/approve | analyst | → `ResponseAction` |
| POST | /response/actions/{id}/reject | analyst | `{reason?}` → `ResponseAction` |
| POST | /response/actions/{id}/revert | analyst | → `ResponseAction` |
| GET | /gate/policy | token:gate | → `GatePolicy`（`ETag: "<version>"`、`If-None-Match` 一致で 304） |

## デセプション（`routes/deception.py`）
| GET | /deception/assets | user | → `DeceptionAsset[]` |
| POST | /deception/assets | analyst | `DeceptionAssetIn` → `DeceptionAsset` |
| PATCH/DELETE | /deception/assets/{id} | analyst | |
| GET | /deception/trips | user | → `Page[Event]`（kind=deception） |
| GET | /deception/preview/{id} | analyst | → `{path, content_type, body}`（レンダリング結果） |

## 通知（`routes/notify.py`）
| GET | /notify/channels | admin | → `NotificationChannel[]`（秘密はマスク） |
| POST | /notify/channels | admin | `NotificationChannelIn` → `NotificationChannel` |
| PATCH/DELETE | /notify/channels/{id} | admin | |
| POST | /notify/channels/{id}/test | admin | → `{ok, error?}` |

## LLM（`routes/llm.py`）
| Method | Path | 権限 | 入出力 |
|---|---|---|---|
| GET | /llm/config | user | → `LLMConfigOut` `{provider, active_provider, available, model_fast, model_deep, effort_fast, effort_deep, daily_budget_usd, spent_today_usd, output_language, enable_fallbacks, prompt_cache, max_output_tokens, max_input_tokens_per_call, request_timeout_seconds, anthropic_base_url, openai_base_url, anthropic_api_key_set, openai_api_key_set, overridden[]}` |
| PUT | /llm/config | admin | `LLMConfigUpdate`（部分更新。省略=変更なし、`null`=静的設定に戻す。未知フィールドは 422）→ `LLMConfigOut`。settings_kv `llm.config` に保存し gateway を再構築。`anthropic_api_key` / `openai_api_key` は書き込み専用（`""`/`null` で削除） |
| GET | /llm/usage | user | `?days=14`（1〜366, UTC 日単位, 古い順, 0 件の日も含む）→ `{days:[{date, cost_usd, calls, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, by_purpose:{purpose: cost_usd}, by_purpose_calls:{purpose: calls}}]}` |
| GET | /llm/calls | user | `?purpose&status&limit&offset` → `Page[LLMCall]`（新しい順） |
| GET | /llm/calls/{id} | admin | → `LLMCallDetail`（マスキング済み入力 `request_redacted` と `response_text`） |
| POST | /llm/test | admin | `?tier=fast\|deep`（既定 fast）→ `{ok, provider, model, latency_ms, status, error?}`（最小の構造化呼び出し。予算・監査が適用される） |

- `provider` は設定値（`auto|anthropic|openai_compat|mock`）、`active_provider` は実際に使われているプロバイダ（auto 解決後）。
  フォームの往復では `provider` を使う。`overridden` は実行時オーバーレイで上書き中のフィールド名。
- **API キーはどのレスポンスにも含まれない**（`*_api_key_set` の真偽のみ）。base URL は資格情報部分をマスクして返す。
- `spent_today_usd` は直近 24 時間のローリング合計（予算判定と同じ）。`/llm/usage` の日付は UTC 暦日。
- `effort_*` は `low|medium|high|xhigh|max`。`output_language` は `ja|en`。

## コパイロット（`routes/copilot.py`）
| GET | /copilot/conversations | user | `?all=true`(admin のみ全ユーザー分) → `[{id,title,owner,context,created_at,updated_at}]` |
| POST | /copilot/conversations | user | `{title?, context?:{incident_id?,alert_id?,session_id?,source_ip?,vuln_id?,asset_id?}}` → conversation (201) |
| GET | /copilot/conversations/{id} | owner/admin | → `{conversation, messages:[{id, role, content, created_at, tool_calls?, tool_results?, llm_call_id?}]}` |
| DELETE | /copilot/conversations/{id} | owner/admin | 204 |
| POST | /copilot/conversations/{id}/messages | owner | `{content}`(1–8000 字) → **SSE**: `data: {"type":"text"|"tool_call"|"tool_result"|"done"|"error", ...}`（409=応答生成中, 503=copilot.enabled=false） |

コパイロット補足（実装: `tokiwa/copilot/`）:
- `role`: `user` / `assistant` / `tool`（ツール結果。`tool_results:[{tool_use_id,name,ok,summary}]`）/ `notice`（UI 表示専用。LLM 未設定・エラー・上限到達。LLM には再送しない）。他人の会話は 404。
- SSE ペイロード: `text {text, final, message_id}` / `tool_call {id, name, input}` / `tool_result {id, name, ok, summary}`（データ本体は流さず要約のみ）/
  `error {code: error|budget_exceeded|refused|max_tool_iterations|busy|internal, error, message_id?}` / `done {conversation_id, stop_reason: end_turn|llm_not_configured|refused|max_tool_iterations|error|busy, message_id, iterations, llm_call_ids}`。必ず `done` で終わる。
- LLM 未設定（mock）時は設定案内を `text` で返し `stop_reason=llm_not_configured`。
- ツール（参照専用のみ）: search_events, get_alert, list_alerts, get_incident, list_incidents, get_session, top_sources, lookup_vuln, list_vuln_matches, get_asset, list_actions。
- 設定 `copilot.*`: `enabled`, `max_tool_iterations`(chat 呼び出し上限), `max_history_messages`, `tier`(fast|deep, 既定 deep), `max_tool_result_chars`(既定 12000)。

## システム（`routes/system.py`）・ストリーム（`routes/stream.py`）
| GET | /system/info | user | → `SystemInfo` |
| GET | /system/jobs | user | → `JobInfo[]` |
| POST | /system/jobs/{name}/run | admin | → `JobInfo`（バックグラウンド起動して即返す。実行中なら二重起動しない。未知は 404） |
| GET | /audit | admin | `?action&actor&limit&offset` → `Page[AuditEntry]`（新しい順） |
| GET | /stream | user(`?access_token`) | **SSE**: `data: {"topic": "...", "data": {...}}`（alert/incident/action/deception/llm.call） |

stream の詳細: 接続直後にコメント `: connected`、15 秒ごとに `: ping` コメント。中継トピックは `alert.*` / `incident.*` /
`action.*` / `deception.tripped` / `intel.advisory` / `llm.call`（`request_redacted`・`response_text` は除外）/
`event.ingested`（`{"count": n}` のみ）。`?access_token=` の値は uvicorn アクセスログでマスクされる。
| GET | /health | public | 実装済 |
