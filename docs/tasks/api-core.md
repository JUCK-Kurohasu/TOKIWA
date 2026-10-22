# タスク: api-core — ユーザー/トークン/イベント/ダッシュボード/システム/ライブストリーム API

## 担当範囲
- `backend/src/tokiwa/api/routes/users.py`, `tokens.py`, `events.py`, `dashboard.py`, `system.py`, `stream.py`, `audit.py`
- `backend/src/tokiwa/api/pagination.py`（共通: limit/offset 依存性、`Page` 生成ヘルパ）
- `backend/tests/api/`

## 要件
1. users / tokens（admin）: docs/api-contract.md 参照。最後の admin は削除・降格不可。トークン平文は作成時のみ返す。
   すべて `record_audit`。
2. events: フィルタ（kind, dataset, source_ip, session_id, host, q = path/UA 部分一致, since/until）、新しい順、
   limit 上限 500。timeline 集計（SQLite と PostgreSQL の両方で動く書き方: Python 側バケット集計で良い。件数が
   多い場合に備え、期間上限 7 日）。
3. dashboard: summary / timeline（docs の形）。重いクエリは 5 秒程度のメモリキャッシュ可。
   `llm_cost_today_usd` は `llm_calls` 合計、`pending_actions` は proposed 件数、`kev_matches` は KEV × open match 件数。
   テーブルが空でも 0 を返す（他モジュール未実装でも動くこと）。
4. system: info（`SystemInfo`: provider 名と available は `get_gateway().provider`）、jobs（`runtime.jobs()`）、
   jobs/{name}/run（admin、バックグラウンド実行して即 JobInfo）。
5. audit: `GET /api/v1/audit`（admin）。
6. stream: `GET /api/v1/stream`（SSE）。`bus.listen()` で受けて `{"topic","data"}` を JSON 送信。
   対象トピック: alert.*, incident.*, action.*, deception.tripped, intel.advisory, llm.call。Pydantic は
   `model_dump(mode="json")`。event.ingested は件数のみ（`{"count": n}`）に間引く。15 秒ごとに keep-alive コメント。
   切断時に unlisten。

## 受け入れ基準
- 各 API の正常系・権限（viewer/analyst/admin）・ページングのテスト。stream は bus に publish したものが届くこと
  （SSE をテストクライアントで数件読み取って切断）。
