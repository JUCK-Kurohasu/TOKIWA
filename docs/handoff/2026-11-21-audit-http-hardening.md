# 2026-11 監査: http-hardening レーン（系統 G「API・認証」入力上限・例外 + 系統 I #66）

担当: #91 → #94 → #57 → #93 → #66。統合担当が本ブランチをマージする。push / GitHub への書き込みはしていない。

## 対応状況

| Issue | 状態 | 内容 | コミット |
|---|---|---|---|
| #91 コミットが応答送信後 | 完全 | `DbSession` を `Depends(get_session, scope="function")` に変更（コミットはルート関数の終了後・応答送信前）。`IntegrityError` → 409 の共通ハンドラ（app.py）。応答開始時点で別セッションから DB を見るテストを追加 | c5d9741 |
| #94 巨大 offset / IntegrityError 500 | 完全 | `PageParams` の offset に `le=MAX_OFFSET`（1,000,000）。独自 `offset` Query を持つ 15 一覧ルートにも効くよう、全ルーターに `offset_guard`（router-level dependency, 422）を付与。IntegrityError → 409 は #91 のハンドラ。OpenAPI から offset を持つ全 GET ルートを列挙して 422 を確認するテスト | ee30db5 |
| #57 ボディ・フィールド長上限 | 部分（推奨 (1)(2) は完全、(3) トークン単位レート制限・(4) retention 既定有効は未対応） | (1) 純 ASGI の `BodySizeLimitMiddleware`（`api/middleware.py`）: `server.max_body_bytes`（既定 1 MiB）/ `server.max_ingest_body_bytes`（`/api/v1/ingest/`、既定 32 MiB）。Content-Length 申告と実受信バイト（chunked）の両方で 413。(2) `Event` の全文字列（ヘッダ値・ラベル値・リスト要素・ネストしたモデル含む）を 65,536 文字で**切り詰め**（拒否しない）、`raw` は JSON 64 KiB で adapters と同じ `{"_truncated","_bytes","text"}` 形に。切り詰め時はタグ `truncated` とラベル `tokiwa.truncated`（`field:元の長さ`）。wiki（Configuration / Sensors ×4 言語） | 9985076 |
| #93 docs / openapi / version 公開・/api/* の SPA 200 | 部分（本レーン分は完全。`/auth/status` の version と CORS `allow_credentials` は未対応＝auth レーン / 要判断） | SPA フォールバックが `api` / `api/...` を JSON 404 に。`server.expose_docs`（既定 true＝後方互換）で `/api/docs`・`/api/openapi.json` を無効化可能。ReDoc（未記載の `/redoc`）を廃止、OAuth2 redirect を `/api/docs/oauth2-redirect` へ。`/health` は認証不要のまま `{"status":"ok"}`、有効なユーザー JWT があるときだけ `version`。wiki（CLI / Configuration ×4）・api-contract | （本コミット） |
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

## #94 の詳細

- 独自に `offset: int = Query(0, ge=0)` を宣言しているルート（alerts, assets, deception, incidents, intel_advice×3, llm,
  response, rules, sessions）は他レーンのファイルなので書き換えず、`app._include_routers` で
  `include_router(router, dependencies=[Depends(offset_guard)])` とした。将来追加されるルートにも自動で効く。
  OpenAPI の各ルートの `offset` には `le` が表示されない（PageParams 利用ルートのみ表示）。各ルートを `PageParams` に
  寄せるのは各担当レーンの任意の後続作業。
- `offset_guard` は「数字だけの値で 1,000,000 超」だけを拒否（桁数で先に判定するので `int()` の桁数上限に当たらない）。
  負数・非数値はルート自身の検証（422）に任せる。`?offset=1&offset=<巨大>` のような重複指定も全値を検査。

## #57 の詳細

- フィールド上限 `EVENT_FIELD_MAX_CHARS = 65_536` の根拠: 系統 A #21（切り詰めによる検知回避）を悪化させないため、検知器の
  検査長のうち最大の Sigma `MAX_MATCH_CHARS`（65,536）に合わせた（detect-web `max_inspect_chars` 8192、aidetect `MAX_TEXT` 4096
  より長い）。`tests/core/test_event_limits.py::test_cap_is_not_narrower_than_any_detector_window` がこの関係を固定。
  `detection.web.max_inspect_chars` をこれより大きく設定すると起動時に warning（app.py）。
  監査の推奨（UA 1KB、message 16KB 等）より緩いが、検知入力を失わない方を優先した。
- 切り詰めは `Event` の `model_validator(mode="after")` で行うので、ingest・Gate の in-process 生成・DB 読み出しすべてに効く。
  冪等（保存済みの切り詰め済み `raw` を再読込で再切り詰めしない）。ラベル/タグは送信者が書けるので「印」は参考情報。
- 検証時間: 5000 イベントの `IngestBatch` 検証が約 75 ms → 約 140 ms（切り詰め走査 約 12 µs/イベント、うち `raw` の JSON 化
  約 3 µs）。パイプライン全体（検知・DB 書き込み）に比べれば小さいと判断。
- ボディ上限の既定値: Gate の最悪ケース（64 ヘッダ × 2 KiB + パス/クエリ/UA 各 2 KiB + ボディ 4 KiB）を `EventBuilder` と同じ
  形で JSON 化すると 1 イベント約 147 KB → Gate 既定 `batch_size` 100 で約 15 MB。監査推奨の 10 MB では Gate の正当なバッチが
  413 になり得て、**両 shipper とも 413 のバッチを破棄する**（`gate/shipper.py` は 4xx を drop、`sensors/shipper.py` は 400/413/422 を drop）
  ＝攻撃者がヘッダを水増ししてテレメトリを落とせる。そのため 32 MiB とした。
- ボディは FastAPI が依存（認証）より先に読むので、未認証でも ingest には 32 MiB まで送れる（読んで JSON パースしてから 401）。
  ミドルウェアでのトークン検証は tokens レーンの領域なので未対応。リバースプロキシ側の上限（`client_max_body_size` 等）を推奨。
- chunked ボディで上限を超えた場合は `receive` から `HTTPException(413)` 派生を送出（インストール済み FastAPI の
  `routing.py` はボディ読み取り中の `HTTPException` をそのまま再送出し、それ以外は 400 に包むことを確認済み）。

## #93 の詳細

- `/health` の利用者を確認した: Docker HEALTHCHECK（`deploy/healthcheck.py`）と `scripts/docker-smoke.sh` はステータスコードだけを見る。
  フロントの `AppShell.tsx` `SystemStatus` はログイン後に JWT 付きで呼び `v${data.version}` を表示する。→ 認証不要のまま、
  version だけをログイン済みに限定した（DB 参照は Authorization ヘッダがあるときだけ、例外は握って 200）。
- 正直な注記: `expose_docs` 既定 true の間は `/api/openapi.json` の `info.version` から未認証でも version が分かる。
  `/api/v1/auth/status` も version を返す（auth レーンの `routes/auth.py`、本レーンでは触っていない）。`/health` だけ隠しても
  効果は限定的で、`expose_docs: false` ＋ auth/status 側の対応と組み合わせて意味を持つ。
- POST など GET 以外の未定義 `/api/*` は従来どおり 405（SPA ルートが GET のみのため）。全メソッドの `/api/{rest}` キャッチオール
  を足すと実在ルートの 405 まで 404 になるので入れていない。
- パストラバーサルの防御（`resolve()` + `parents` 判定）は変更なし。テストを追加して維持を確認。

## 要判断

- （#93）`server.expose_docs` 既定は **true（後方互換）**。AGENTS.md・wiki（CLI / Sensors）が `/api/docs` を案内しているため。
  **本番では false を推奨**（wiki の CLI / Configuration に記載）。既定 false にする場合は lab/compose・docs の案内も同時に変える。
- （#93）ReDoc を廃止（`redoc_url=None`）。従来 `/redoc` で公開されていたが文書に記載なし。CSP に Google Fonts と blob ワーカーを
  足す必要があり、Swagger UI と重複するため。必要なら `/api/redoc` として復活させ、docs 用 CSP を広げる。
- （#93）CORS `allow_credentials=True` は監査推奨では false（JWT は Authorization ヘッダ運用）だが、本レーンでは変更していない。
  フロントは Cookie を使っていない（`client.ts` は Authorization ヘッダ）ので false で問題ない見込み。要確認のうえ別途。
- （#57）`server.max_ingest_body_bytes` 既定 32 MiB / `server.max_body_bytes` 既定 1 MiB。従来は無制限なので、32 MiB を超える
  バッチを送っていた利用者（`batch_size` を 5000 近くにして大きなイベントを送る構成）は 413 → バッチ破棄になる。現実的な構成
  （Gate 100 件、Agent 500 件）は最悪ケースでも収まる見込み。要件次第で下げる（メモリ/DoS 優先）か上げる（取りこぼし優先）か。
- （#57）フィールド上限 65,536 文字は定数（`schemas/events.py`）。設定化はしていない（スキーマが設定に依存しないように）。
- （#91）なし。既定動作の変更だが外部仕様（エンドポイント・形式）は変わらない。409 は従来 500 だったケースのみ。
- （#94）offset 上限 1,000,000（例示値どおり）。これより深いページングが必要な運用があればフィルタで絞る前提。

## 失敗した試み

- なし

## 担当外の変更

- `backend/src/tokiwa/api/deps.py`: `DbSession` の 1 行のみ（`scope="function"` とコメント）。tokens レーンへ: この行を戻さないこと。

## 他レーンへの依頼

- tokens レーン: `DbSession` の `scope="function"` を維持してください（戻すと #91 が再発し、`test_commit_timing.py` が落ちる）。
- tokens / ingest レーン（#57 の残り）: トークン単位の events/秒・bytes/秒レート制限と 429。可能なら ingest のトークン検証を
  ボディ読み取り前に（未認証の 32 MiB 送信を早期 401 に）。
- Gate / sensors レーン: 413 を受けたバッチを破棄せず二分割して再送する（現在はバッチごと破棄。#57 の既定上限との組み合わせで
  テレメトリ欠落＝検知回避になり得る）。
- auth レーン（#93 の残り）: `GET /api/v1/auth/status` が未認証で `version` を返す。不要なら削除（フロントが使っているか要確認）。
- frontend レーン: `/health` の `version` は未ログイン時に返らなくなった。`AppShell.tsx` の型を `version?: string` にし、
  無いときは `v` 表示を省くと堅い（ログイン後にしか表示されないので現状でも実害なし）。
- pipeline / retention 担当: 保存期間・容量ベースの retention を既定で有効化（#57 推奨 (4)）。L12-03（PostgreSQL の列長・NUL）は未対応。

## 未検証事項

- PostgreSQL での IntegrityError → 409（SQLite のみで確認。asyncpg の例外も `sqlalchemy.exc.IntegrityError` に包まれる想定だが未実行）。
