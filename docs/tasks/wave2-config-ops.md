# Wave 2 / D: config-ops — 設定の整理・DB マイグレーション・保持期間・型チェック

## 担当範囲
`backend/src/tokiwa/config.py`（横断的変更はこの担当だけ）, `db/**`, `backend/alembic/**`（新規）, `api/app.py`,
`gate/cli.py`, `backend/src/tokiwa/retention.py`（新規）, `.github/workflows/ci.yml`, `backend/pyproject.toml`,
mypy の既存エラー箇所（`db/session.py`, `detect/context.py`, `llm/gateway.py` ほか）, `docs/deploy.md`

## 要件
1. **Gate 設定**: 現在 CLI フラグ専用の 5 項目（upstream timeout、キューサイズ、Host 扱い、接続上限、HTML 注入の最大サイズ）を
   `GateSettings` へ移し、env / yaml から設定可能に（CLI フラグは上書き用に残す）。
2. **センサー系のサーバー側設定**（初回スナップショットの扱い、スキャン閾値など）が `AgentSettings` に置かれている → `detection` 配下へ
   移す（後方互換: 旧キーも読めるようにして警告）。
3. **空文字の `TOKIWA_*` を未設定扱い**に（例: `TOKIWA_SERVER__SECRET_KEY=` が空の署名鍵になる問題）。テスト付き。
4. **Alembic 導入**（ADR-0002）: 現行スキーマを初版リビジョンに。起動時の `create_all` を「Alembic で upgrade head」に置換
   （テストは従来どおり高速に動くよう、テスト用は create_all を維持してよい）。SQLite と PostgreSQL の両方で確認。
   `docs/deploy.md` にアップグレード手順。
5. **データ保持とパージ**: `events` / `llm_calls` / `audit_log` などの保持日数を設定化し、`@periodic` のパージジョブ（バッチ削除）。
   既定値は保守的に（例: events 30 日、llm_calls 90 日、audit は削除しない）。
6. **mypy**: 既存エラーを解消し、CI で `uv run mypy src` を必須化。
7. 各モジュールに散らばった調整用定数のうち、運用で変えたいもの（NVD 待機時間、ページ上限、通知の重複抑制時間 など）を
   該当セクションに設定化（モジュールのコードは読み替えのみ最小修正）。

## 受け入れ基準
- 全テスト緑、mypy 緑（CI 必須）、`alembic upgrade head` → サーバー起動 → ingest が SQLite / PostgreSQL で動く。
