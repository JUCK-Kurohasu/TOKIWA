# タスク: gate — TOKIWA Gate（リバースプロキシ・センサー / エンフォーサ）

## 目的
アクセスログでは見えない **リクエストボディ** を含めて HTTP を捕捉し（要件 §8 の課題を解決）、
サーバーから取得したポリシーで block / rate-limit / tarpit / deceive（Mirage へ誘導）を即時適用する。
XDR の「R」を担う実働部。

## 担当範囲
- `backend/src/tokiwa/gate/`（app.py, proxy.py, capture.py, policy.py, shipper.py, ratelimit.py, cli.py）
- `backend/tests/gate/`
- `docs/gate.md`（運用手順・性能・制約）

## 要件
1. ASGI アプリ（Starlette）+ httpx.AsyncClient でアップストリームへストリーミング転送。
   Hop-by-hop ヘッダ除去、`X-Forwarded-For/Proto/Host` 付与、WebSocket は v1 では素通し不可でよい（501 + ログ）。
   アップストリーム障害時は 502。タイムアウト設定。
2. 捕捉: `Event(kind=HTTP, dataset="gate.http")`。メソッド・パス・クエリ・ヘッダ（順序も `header_order` に）・UA・
   ボディ先頭 `capture_body_bytes`（テキスト系のみ、バイナリは size のみ）・ステータス・応答サイズ・処理時間。
   **送信前に `tokiwa.llm.redact`**（ヘッダ・クエリ・ボディ）。送信元 IP は `trust_forwarded_for` 設定時のみ XFF を信頼。
3. シッパー: 非同期キュー（上限あり、溢れたら古いものを捨てて統計を記録）、`batch_size` / `flush_interval_seconds`、
   `X-Tokiwa-Token` で `/api/v1/ingest/events` へ。サーバー停止時もプロキシは止めない（fail-open、ただしログ）。
4. ポリシー: `/api/v1/gate/policy`（`GatePolicy`）を `policy_refresh_seconds` ごとに取得、`version` が変わったら差し替え。
   IP/CIDR マッチは `ipaddress` で前処理（多数エントリでも O(log n) 程度に）。
   - blocked → 403（簡素な本文）+ 捕捉イベントに `tags: ["gate:blocked"]`
   - rate_limited → トークンバケット（per IP）、超過は 429
   - tarpit → `asyncio.sleep(ms)` を応答前に挿入（上限 30s）
   - deceive / decoys → 一致する `DecoyRoute` があればアップストリームに転送せずデコイを返す。deceive 対象 IP は
     全リクエストをデコイ（一致がなければ汎用 404 デコイ）。デコイ応答はイベントに `kind` を DECEPTION として
     別途記録（`deception.asset_id` 付き）
   - html_injection → アップストリームの `text/html` 応答（非圧縮時のみ、圧縮時は解凍できる場合のみ）で `</body>` 直前に挿入し
     Content-Length を再計算
5. `tokiwa gate run --upstream ... --listen ... --server ... --token ...`（`GateSettings`）。`/__tokiwa/health`。
6. 性能目標（ラボ）: 単一プロセスで 300 RPS 程度。簡易ベンチスクリプト `backend/scripts/bench_gate.py`。

## 受け入れ基準
- テスト: アップストリームをテスト用 ASGI アプリにして、転送・捕捉内容（ボディ・redact 済み）・block・429・tarpit（時間をモック）・
  デコイ応答・html_injection・ポリシー更新・サーバー停止時の fail-open を検証。
