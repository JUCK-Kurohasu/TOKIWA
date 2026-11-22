# 2026-11-21 監査修正（系統 G / I / K）— 統合ログ

統合担当（親セッション）の記録。各レーンの詳細は同じ日付の `2026-11-21-audit-<レーン>.md`。

## 選定

#16 の系統図（`docs/audit/2026-11/tools/taxonomy.json`）の 11 系統のうち、工数 S の割合が高い 3 系統を先に着手した。

| 系統 | 件数 | 工数 S | 重大度 |
|---|---|---|---|
| I フロントエンド | 8 | 7 | medium 3 / low 5 |
| K 評価・文書 | 11 | 8 | medium 3 / low 8 |
| G API・認証 | 17 | 11 | high 1 / medium 7 / low 9 |

衝突を避けるため、系統ではなく**編集するファイルの所有**でレーンを分けた（http-hardening / auth / tokens-roles / frontend /
eval-docs / data-handling）。I の #66（セキュリティヘッダ）はバックエンドのミドルウェアなので http-hardening に入れた。
#101（vitest/tinypool）は dependabot の PR JUCK-Kurohasu/TOKIWA#17 が対応中のため対象外。

## 共通の土台（統合担当が先に入れたもの）

- `fad4626 feat(db)`: `tokiwa.db.schema_sync.sync_additive`。`create_all` の後に、既存テーブルへ不足している nullable /
  server_default 付きの列とインデックスを `ALTER TABLE ADD COLUMN` で足す（削除・型変更はしない。default 無しの NOT NULL は例外）。
  修正で既存テーブルに列が増えても、アップグレードした `tokiwa.db` が壊れないようにするため（移行機構 #162 の代わりではない）。
  `tests/core/test_schema_upgrade.py` が f993282 時点のスキーマ（`tests/fixtures/schema-f993282.sqlite.sql`）で現行モデルを起動する。

## data-handling レーン（#169）の副産物 — コード読解で見つかった未登録の問題

Issue 化はしていない（要判断: 監査 Issue として追加登録するか）。

- Zeek `http.log` の `username` が `sensors/normalize.py` の `_SENSITIVE_KEYS` に無く、`raw` に残る。
- 対処の承認依頼通知（`notify/render.py` の `render_action`）が LLM の書いた `reason`（最大 500 文字）を外部チャネルへ送る（#168 の要約とは別経路）。
- `POST /api/v1/ingest/events` はサーバー側でマスキングしない（ingest トークンがあれば未マスクのデータを保存できる）。
- `mock` 時・予算超過時もプロンプト全文が `llm_calls.request_redacted` に残る。Copilot の会話を消しても `llm_calls` の行は残る。
- `db/models/deception.py` の docstring と `deception/service.py` が存在しない「event retention」に言及。
- Gate の `--access-log` を有効にすると uvicorn のアクセスログ（リクエスト行）がマスクされずに出る。
- `GET /api/v1/llm/calls` の `error` に拒否時のモデル出力先頭 500 文字が入る（Data-Handling ページの権限表は「本文は含まない」と書いており、やや甘い）。
- 既存 #172（UI で保存した LLM 設定が環境変数より優先）と #111（DB ファイルの権限）とも重なる。

## 統合の記録

| 順 | レーン | マージ | 全チェック | 備考 |
|---|---|---|---|---|
| 1 | data-handling（#169） | cf788df（ff） | wiki OK | 権限表・保持・本人対応の節に `TODO(integrator)`。#157/#158/#164/#167 の統合後に更新する |
| 2 | 5 レーンのコミット済み分（途中） | a1548e9 まで | backend 1354 passed / frontend 緑 / CI 緑 | 利用枠の上限で全エージェントが 2 回中断したため、コミット済み分を先に統合。統合で `TokensTab.tsx` が旧 `formatDateTime` を参照（frontend × tokens の意味的衝突）→ `dateTimeTitle` に修正 |
| 3 | http-hardening / frontend / tokens-roles / eval-docs（完了） | bb12ce6 まで | backend 1432 passed / frontend 緑 | wiki `Configuration*.md` の表の行が衝突 → 両方残す。eval の `parse_mix` に新規 mypy エラー → 修正 |
| 4 | auth（完了） | 9b21ee4 | backend 1459 passed / ruff・format 緑 / mypy 既知 4 件のみ / frontend 緑 | `api/deps.py`（import）・`cli.py`（typing import と user reset-password / token 作成の並び）・`api-contract.md`・wiki `Configuration*.md` が衝突 → 両方の内容を残して解決 |
| 5 | Data-Handling ページの `TODO(integrator)` 解消 | 74efb7e | wiki OK | #157（viewer の伏字）・#164・#167（閲覧記録）・#158（data purge/export）・#56（ログイン監査）・#102（ファイル権限）を反映。4 言語 |

## 統合で気づいたこと

- 全体テストの所要時間が 70 秒台から約 2 分 40 秒に伸びた（1459 件。エージェント停止後の単独実行で 156 秒）。AGENTS.md の「1 分以内」を既に超えていたが、
  さらに伸びた。遅いテストの洗い出し（`pytest --durations=20`）が次の課題。
- auth レーンからの依頼: SSE の接続中に JWT を失効させても、開いているストリームは切れない（`token_version` の定期再確認が必要。未対応）。
  TOKIWA 自身への連続ログイン失敗を検知ルールにする件も未対応。
