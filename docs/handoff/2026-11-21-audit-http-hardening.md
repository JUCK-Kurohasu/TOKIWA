# 2026-11 監査: http-hardening レーン（系統 G「API・認証」入力上限・例外 + 系統 I #66）

担当: #91 → #94 → #57 → #93 → #66。統合担当が本ブランチをマージする。push / GitHub への書き込みはしていない。

## 対応状況

| Issue | 状態 | 内容 | コミット |
|---|---|---|---|
| #91 コミットが応答送信後 | 完全 | `DbSession` を `Depends(get_session, scope="function")` に変更（コミットはルート関数の終了後・応答送信前）。`IntegrityError` → 409 の共通ハンドラ（app.py）。応答開始時点で別セッションから DB を見るテストを追加 | （本コミット） |
| #94 巨大 offset / IntegrityError 500 | 未着手 | | |
| #57 ボディ・フィールド長上限 | 未着手 | | |
| #93 docs / openapi / version 公開・/api/* の SPA 200 | 未着手 | | |
| #66 セキュリティヘッダ | 未着手 | | |

## #91 の詳細（事実）

- インストール済み FastAPI 0.159.1 / Starlette 1.9.0 の実装を確認した:
  `fastapi/routing.py` の `request_response()` は `request_stack`（外）と `function_stack`（内）の 2 つの
  `AsyncExitStack` を持ち、`function_stack` はルート関数（応答のシリアライズ込み）が返った直後、
  `await response(scope, receive, send)` の**前**に閉じる。`request_stack` は応答送信（BackgroundTasks 含む）の**後**に閉じる。
  yield 依存の既定スコープは `"request"`（`dependencies/models.py::_get_computed_scope`）。
- テストで挙動を確認: `tests/api/test_commit_timing.py` は ASGI の `send` を包み、`http.response.start` の時点で別セッションから
  DB を読む（httpx の ASGITransport は応答後の後始末まで待ってから返すので、普通の「失効→再利用」テストでは差が出ない）。
  - 修正前（`Depends(get_session)`）: 4 件とも失敗（応答開始時点で未コミット `[False]`、コミット時の UNIQUE 違反は
    例外が応答後に出る＝クライアントには成功に見える状態）。
  - 修正後: 4 件とも成功。全体テストも成功。
- 依存キャッシュのキーにはスコープが含まれる（`_get_cache_key`）。`get_session` を `Depends` しているのは `api/deps.py` の
  `DbSession` だけなので、`get_current_user` / `require_token_scope` とルートは同じセッションを共有する（grep で確認）。
- 副作用（改善）: `assets.py` の `BackgroundTasks(_rematch)` は従来コミット前に走り得たが、今はコミット後に走る。
  SSE（copilot / stream）は DB セッションを応答ストリーム中に保持しなくなった（`run_turn` と `_stream_user` は自前の
  `session_scope` を使うので影響なし）。
- `IntegrityError` ハンドラは `str(exc)` を出さない（SQL とバインド値＝パスワードハッシュ等を含むことをテストの失敗出力で確認）。
  ドライバメッセージの 1 行目のみ warning ログ。応答は固定文言の 409。

## 要判断

- （#91）なし。既定動作の変更だが外部仕様（エンドポイント・形式）は変わらない。409 は従来 500 だったケースのみ。

## 失敗した試み

- なし

## 担当外の変更

- `backend/src/tokiwa/api/deps.py`: `DbSession` の 1 行のみ（`scope="function"` とコメント）。tokens レーンへ: この行を戻さないこと。

## 他レーンへの依頼

- tokens レーン: `DbSession` の `scope="function"` を維持してください（戻すと #91 が再発し、`test_commit_timing.py` が落ちる）。

## 未検証事項

- PostgreSQL での IntegrityError → 409（SQLite のみで確認。asyncpg の例外も `sqlalchemy.exc.IntegrityError` に包まれる想定だが未実行）。
