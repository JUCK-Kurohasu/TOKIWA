# API 契約（/api/v1）

> フロントエンドとバックエンドの約束。スキーマ名は `backend/src/tokiwa/schemas/*.py`、
> TS 型は `frontend/src/api/types.ts`。**エンドポイントを追加・変更したらここを更新**する。
> 「担当」は初期実装の担当モジュール（ルートファイル名）。

共通:
- 認証: ユーザーは `Authorization: Bearer <JWT>`（SSE は `?access_token=`）。センサーは `X-Tokiwa-Token: tkw_...`。
- 一覧は `Page[T]` = `{items, total, limit, offset}`。クエリ `limit`（既定 50, 最大 500）, `offset`。
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
| POST | /users | admin | `UserCreate` → `User` |
| DELETE | /users/{id} | admin | 自分自身は削除不可 |
| GET | /tokens | admin | → `ApiToken[]` |
| POST | /tokens | admin | `ApiTokenCreate` → `ApiTokenCreated`（平文は一度だけ） |
| DELETE | /tokens/{id} | admin | revoke |

## 取り込み（`routes/ingest.py` 実装済）
| POST | /ingest/events | token:ingest | `IngestBatch` → `IngestResult` |

## イベント（`routes/events.py`）
| GET | /events | user | `?kind&dataset&source_ip&session_id&host&q&since&until&limit&offset` → `Page[Event]`（新しい順） |
| GET | /events/{id} | user | → `Event` |
| GET | /events/stats/timeline | user | `?hours=24&bucket_minutes=60` → `{buckets:[{ts, total, by_kind:{}}]}` |

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
| GET | /dashboard/timeline | user | `?hours=24` → `{buckets:[{ts, events, alerts, ai_alerts}]}` |

## ホスト・資産（`routes/hosts.py`, `routes/assets.py`）
| GET | /hosts | user | → `[{host, ports_open, last_seen, deviations}]` |
| GET | /hosts/ports | user | `?host` → `HostPort[]`（{host,protocol,bind_ip,port,pid,process_name,first_seen,last_seen,open,allowed}） |
| GET | /hosts/baselines | user | → `PortBaseline[]` |
| POST | /hosts/baselines | analyst | `{host?, protocol, port, process_name?, allow_public, note?}` → `PortBaseline` |
| DELETE | /hosts/baselines/{id} | analyst | |
| POST | /hosts/baselines/learn | analyst | `{host}` 現在の listener をベースライン化 → `PortBaseline[]` |
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
| POST | /response/actions | analyst | `ActionProposal` → `ResponseAction`（status=proposed） |
| POST | /response/actions/{id}/approve | analyst | → `ResponseAction` |
| POST | /response/actions/{id}/reject | analyst | `{reason?}` → `ResponseAction` |
| POST | /response/actions/{id}/revert | analyst | → `ResponseAction` |
| GET | /gate/policy | token:gate | → `GatePolicy` |

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
| GET | /llm/config | user | → `{provider, available, model_fast, model_deep, effort_fast, effort_deep, daily_budget_usd, spent_today_usd, output_language, enable_fallbacks, prompt_cache}` |
| PUT | /llm/config | admin | 部分更新（settings_kv `llm.config` に保存し gateway を再構築）。API キーは書き込みのみ |
| GET | /llm/usage | user | `?days=14` → `{days:[{date, cost_usd, calls, input_tokens, output_tokens, by_purpose:{}}]}` |
| GET | /llm/calls | user | `?purpose&status&limit&offset` → `Page[LLMCall]` |
| GET | /llm/calls/{id} | admin | → `LLMCallDetail` |
| POST | /llm/test | admin | → `{ok, provider, model, latency_ms, error?}` |

## コパイロット（`routes/copilot.py`）
| GET | /copilot/conversations | user | → `[{id,title,created_at,updated_at}]` |
| POST | /copilot/conversations | user | `{title?, context?}` → conversation |
| GET | /copilot/conversations/{id} | user | → `{conversation, messages:[{id, role, content, created_at, tool_calls?}]}` |
| DELETE | /copilot/conversations/{id} | user | |
| POST | /copilot/conversations/{id}/messages | user | `{content}` → **SSE**: `data: {"type":"text"|"tool_call"|"tool_result"|"done"|"error", ...}` |

## システム（`routes/system.py`）・ストリーム（`routes/stream.py`）
| GET | /system/info | user | → `SystemInfo` |
| GET | /system/jobs | user | → `JobInfo[]` |
| POST | /system/jobs/{name}/run | admin | → `JobInfo` |
| GET | /audit | admin | `?limit&offset` → `Page[AuditEntry]` |
| GET | /stream | user(`?access_token`) | **SSE**: `data: {"topic": "...", "data": {...}}`（alert/incident/action/deception/llm.call） |
| GET | /health | public | 実装済 |
