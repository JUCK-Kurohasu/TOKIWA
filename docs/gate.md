# TOKIWA Gate — リバースプロキシ・センサー / エンフォーサ

アクセスログでは見えない **リクエストボディ** まで含めて HTTP を捕捉し、サーバーの `GatePolicy` を即時適用する
別プロセス（`tokiwa gate run`）。実装: `backend/src/tokiwa/gate/`。

```
client ──▶ Gate (:8080) ──▶ upstream app
             │  POST /api/v1/ingest/events  (gate.http / gate.deception, X-Tokiwa-Token)
             │  GET  /api/v1/gate/policy    (policy_refresh_seconds ごと)
             ▼
        TOKIWA server
```

## 1. 起動

```bash
cd backend
uv run tokiwa token create gate-1 --scope ingest --scope gate   # 平文は一度だけ表示（既定は ingest のみ）
export TOKIWA_GATE__INGEST_TOKEN=tkw_...          # --token より安全（ps に出ない）。--token-file も可
uv run tokiwa gate run --upstream http://127.0.0.1:3000 --listen 0.0.0.0:8080 --server http://127.0.0.1:8788
```

設定の優先順位: CLI フラグ > `TOKIWA_GATE__*` / `tokiwa.yaml`（`GateSettings`）> 既定値。

| 設定 (`GateSettings`) | CLI | 既定 | 備考 |
|---|---|---|---|
| upstream | `--upstream` | http://127.0.0.1:3000 | パス接頭辞可（`http://app/base`） |
| listen_host / listen_port | `--listen host:port` | 0.0.0.0:8080 | `[::]:8080`, `:8080` 可 |
| server_url | `--server` | http://127.0.0.1:8788 | |
| token_file | `--token-file` | なし | 変更（mtime/サイズ/inode）時と 401 受信時に読み直す。空・読めないときは直前のトークンを維持 |
| ingest_token | `--token` / `--token-file` | なし | scope `ingest` と `gate` が必要（`token create` の既定は `ingest` のみなので `--scope gate` を明示） |
| sensor_id | `--sensor-id` | gate-1 | イベントの `sensor_id` |
| capture_body_bytes | `--capture-body-bytes` | 4096 | 0 で本文捕捉なし |
| batch_size / flush_interval_seconds | `--batch-size` / `--flush-interval` | 100 / 1.0 | |
| policy_refresh_seconds | `--policy-refresh` | 5.0 | ±10% ジッタ |
| trust_forwarded_for | `--trust-forwarded-for` | false | 信頼できる LB の背後でのみ |
| max_request_headers | — | 100 | ヘッダ行がこれを超える要求は上流へ転送せず **431**（`gate:too_many_headers`）。0 で無効。Apache の `LimitRequestFields` と同じ既定 |

`GateSettings` に無い運用ノブ（`GateOptions`、CLI のみ）: `--upstream-timeout`（30s, 接続 5s）、
`--max-queue`（10000 件）、`--preserve-host/--rewrite-host`（既定は Caddy 同様にクライアントの Host を転送）、
`--access-log`。HTML 注入上限 2 MiB、デコイ時の本文読み取りタイムアウト 5s はコード定数。

ヘルスチェック: `GET /__tokiwa/health` → `{"status":"ok"}`。ループバック/プライベート IP からは
ポリシー版・シッパー統計・処理件数も返す（インターネットには内部情報を出さない）。プロキシもイベント化もしない。

## 2. リクエスト処理順

1. `/__tokiwa/health` → ヘルス
2. `blocked` に一致 → **403**（本文を読まずに即応答。タグ `gate:blocked`, label `gate.rule`）
3. `rate_limited` に一致 → クライアント IP ごとのトークンバケット（容量 N、N/60 個/秒で補充）。空なら **429** + `Retry-After`
4. WebSocket（`Upgrade: websocket` / websocket scope）→ **501**（v1 は非対応。ログ + `gate:websocket_unsupported`）
5. `tarpit` に一致 → `sleep(ms)`（上限 30 s）してから続行（`gate:tarpit`）
6. パスが `DecoyRoute` に一致 → デコイを返す（**アップストリームへは一切転送しない**）。HTTP イベント（`gate:decoy`）+
   `kind=deception` イベント（`dataset=gate.deception`, `deception.asset_id/asset_kind`）を送る
7. `deceive` に一致する IP → 全リクエストをデコイで応答。ルール不一致なら汎用 404 デコイ（`gate:decoy_generic`。
   DECEPTION イベントは出さない＝ノイズ回避）
8. ヘッダ行が `max_request_headers` を超える → **431**（イベントに残せるのは 64 名までなので、見えない分を上流へ渡さない）
9. それ以外 → アップストリームへストリーミング転送。`html_injection` があれば HTML 応答の `html_injection_positions` の位置（既定 `<body>` 直後と最後の `</body>` 直前。位置の無い古いポリシーは `</body>` 直前のみ。docs/deception.md §6）に挿入

ゲート生成の応答（403/429/デコイ）には直近のアップストリームの `Server` ヘッダを付け、デコイが浮かないようにする。

## 3. 捕捉イベント（`gate.http`）

- `http.method/scheme/host/path/query/headers/header_order/user_agent/referrer/content_type`
- `headers` は最大 64 名（Web 検知器が見る上限と同じ）。**検知に使うヘッダは位置に関係なく必ず残す**（`gate.capture.PRIORITY_HEADERS`:
  UA・Referer・Host・Origin・Cookie・Content-*・Accept-*・`Sec-Fetch-*`・Client Hints・`X-Forwarded-*`・`Forwarded`・`X-Real-IP` 等の
  送信元 IP 系・`X-Original-URL` 等のルーティング上書き・Web 検知器が名前で見るヘッダ・デセプションのカナリアヘッダ）。残りの枠を
  到着順に使う（監査 #140: ダミーヘッダ 64 個を前に置くと UA 等が消えていた）。同名ヘッダは `, `（Cookie は `; `）で連結し、
  連結は 8192 文字で打ち切る。`header_order` は到着順で、同じ名前は 2 回まで
- `request_body`: 先頭 `capture_body_bytes` を UTF-8（置換）で。テキスト系 Content-Type のみ。不明・multipart は内容で判定、
  バイナリはサイズ（`request_body_size`）のみ。多バイト文字の途中で切れた末尾は捨てる
- `Content-Encoding: gzip` / `x-gzip` / `deflate`（zlib 形式・raw の両方、2 段まで、gzip の複数メンバーも）の要求ボディは、捕捉した
  先頭を **展開してから** `request_body` に入れる（監査 #141: Express の body-parser 等は展開して処理するのに、検知器は圧縮バイト列を
  見ていた）。展開後も `capture_body_bytes` で打ち切る（圧縮爆弾対策。展開するのは捕捉した先頭だけ）。`request_body_size` は
  転送路上の（圧縮された）サイズのまま。上流へは元の圧縮バイト列をそのまま送る
- `status / response_size / response_content_type / duration_ms`（tarpit 込みのクライアント体感）/ `http_version`
- `timestamp` = リクエスト到着時刻（AI リズム特徴量用）
- tags: `gate:blocked|rate_limited|tarpit|decoy|decoy_generic|deceive|html_injected|inject_skipped|upstream_error|client_disconnect|websocket_unsupported|body_timeout`、
  `gate:headers_truncated`（64 名を超えた・連結を打ち切った。label `gate.header_count`=受信したヘッダ行数, `gate.headers_dropped`, `gate.headers_clipped`）、
  `gate:duplicate_header`（Host・Content-Length・User-Agent・`Sec-Fetch-*` などリストでないヘッダが 2 回以上。label `gate.duplicate_headers`）、
  `gate:too_many_headers`（431）、
  `gate:req_encoded`（要求ボディを展開した。label `gate.request_encoding`, `gate.request_body_decoded_bytes`）、
  `gate:req_encoding_unknown`（br・zstd・3 段以上など展開できない符号化。本文は記録しない）、`gate:req_decode_failed`（gzip/deflate と
  宣言したが壊れている）
- labels: `gate.action`（proxy/blocked/rate_limited/decoy/deceive/upstream_error/websocket/too_many_headers）, `gate.rule`, `gate.policy`,
  `gate.tarpit_ms`, `gate.upstream_ms`, `gate.decoy_asset`, `gate.peer_ip`（XFF 採用時の実ピア）, `gate.error`

**送信前に `tokiwa.llm.redact`** を適用: ヘッダ（`sensitive_headers` は値を丸ごとマスク）、パス、クエリ、Referer、UA、本文。
本文だけは `max_field_chars` ではなく `capture_body_bytes` を上限にする。生の値はキューにも残らない（捕捉時点で redact）。

## 4. 送信（シッパー）と fail-open

- 401（失効・期限切れ・ローテーション後の旧トークン）は恒久エラーとして捨てない: トークンファイルを読み直し、変わっていれば
  その場で再送。変わっていなければイベントをキューに保持したままバックオフで再試行（キュー上限で古いものから捨てる）。
  無停止ローテーション: `tokiwa token rotate gate-1 --grace-hours 24` → 出力をトークンファイルへ書く → Gate が自動で切替。

- `submit()` は O(1) 同期。ネットワーク I/O はバックグラウンドタスク。応答送信後にイベントを作るのでレイテンシに乗らない。
- フルバッチ（`batch_size`）は即送信、端数は最長 `flush_interval_seconds` 待つ（小さな POST の乱発 = サーバー DB の
  トランザクション乱発を防ぐ）。
- キュー上限（既定 10000）を超えたら **古いものから捨て**、`dropped_overflow` に計上（1 回目と 1000 件ごとに WARN）。
- 一時障害（接続失敗・5xx・408・429）→ バッチをキュー先頭に戻し指数バックオフ（最大 30 s）。
  恒久エラー（401 以外の 4xx: スコープ不足 403・スキーマ不一致 422）→ バッチ破棄 + ERROR（`dropped_rejected`）。
- サーバー停止中もプロキシは止まらない。終了時は最大 5 s で残りを flush。

## 5. ポリシー

> **gate トークンの漏えい＝デセプション配置の漏えい。** `gate` スコープのトークンで `GET /api/v1/gate/policy` を読むと、
> 全デコイ経路（秘匿プレフィックス含む）・デコイ本文（ハニートークン値入り）・AI カナリアの注入文とカナリアヘッダ名・
> blocked/deceive/tarpit リストがそのまま得られる。攻撃者はデコイを一切踏まずに回避できるようになる。
> `gate` スコープは Gate 専用トークンにだけ付け（`tokiwa token create` の既定は `ingest` のみ）、トークンファイルは
> Gate ホストで権限 600 にする。漏えいが疑われたらトークンを失効し、`/deception` で資産のトークンをローテーションする。

- `version` が変わったときだけ差し替える（同じなら既存テーブル・レートリミッタ状態を維持）。差し替えは参照の一括置換。
- 初回取得前は何も強制しない（純粋なセンサー兼プロキシ）。取得失敗時は **最後のポリシーを維持**（fail-static）。
  ブロックはサーバー側で TTL 管理されるため、サーバーを DoS すれば解除される、という抜け道を作らない。
- ただし各エントリの期限（`GatePolicy.entry_expires_at`、監査 #64）は Gate 側でも守る: `受信時刻 + (expires_at - generated_at)`
  を単調時計で過ぎたエントリはその場で外す（Gate の壁時計のずれに依存しない）。期限のないエントリは従来どおり維持。
- IP/CIDR: プレフィックス長ごとのハッシュ表で最長一致（エントリ数に依存せず最大 33/129 回の dict 参照）。
  IPv4-mapped IPv6 は IPv4 に正規化。不正エントリはスキップして WARN。重複時は rate_limited=厳しい方、tarpit=長い方。
- デコイパス: 完全一致、または `*` 終端で接頭辞一致（最長一致）。照合前に `//` と `.`/`..` を正規化するので
  `/static/../.env` でも回避できない。`*` / `/*` のような全体デコイは拒否（サイト全体を乗っ取るため）。
- デコイヘッダ: hop-by-hop・Content-Length/Type/Encoding・Date・CR/LF を含むものは除外。

## 6. プロキシの挙動

- hop-by-hop ヘッダ（`Connection` に列挙されたものも）を双方向で除去。`Transfer-Encoding` 付きリクエストは
  `Content-Length` を落とす（スマグリング対策）。
- `X-Forwarded-For/Proto/Host`: `trust_forwarded_for=false` ならクライアント送信値を **破棄してゲートの観測値で置換**
  （ゲート経由で上流に IP を偽装させない）。`true` なら既存チェーンに実ピアを追記し、送信元 IP は **右端** の有効 IP
  （信頼 LB が付けた値。左端はクライアントが自由に書ける）。
- リクエストターゲットは生のまま転送（httpcore `target` 拡張。httpx の `..` 正規化を避け nginx の `proxy_pass` URI なしと同等）。
  イベントの `path` もクライアントが実際に送った値。
- 本文はストリーミング転送しつつ先頭だけ捕捉。上流障害 **502**、タイムアウト **504**、応答途中の障害は接続中断。
- `Set-Cookie` 等の重複ヘッダを保持。uvicorn は `server_header/date_header/proxy_headers` 無効で起動（上流の値を転送）。
- 上流クライアントはクッキーを一切保存・送信しない（全訪問者で 1 つの httpx クライアントを共有するため。保存すると上流の
  `Set-Cookie` が Cookie を送らない別の訪問者の要求に付いてしまう）。

### HTML カナリア注入
対象: `text/html`、HEAD 以外、204/206/304 以外、宣言サイズ ≤ 2 MiB。gzip/deflate は解凍して注入し非圧縮で返す
（`Content-Encoding`/`ETag`/`Content-MD5`/`Digest` を削除、`Content-Length` 再計算）。br/zstd・多重エンコード・破損・
展開後 2 MiB 超（圧縮爆弾対策）・`</body>` 無し → 無加工で通す（`gate:inject_skipped`）。注入が有効な間は
`Accept-Encoding` を gzip/deflate/identity に絞り、br を使うクライアントでも注入できるようにする。
スニペットは `Content-Type` の charset でエンコード（表せない文字は数値文字参照）。

## 7. 性能（ラボ, `backend/scripts/bench_gate.py`）

2026-10-22 のサンドボックス（4 vCPU）。負荷生成・上流・ゲートが同一マシンで CPU を取り合うので **下限値**。
小さな HTML（約 1 KB）、32 並列、ブロックリスト 2000 件。

| 条件 | req/s | p50 / p99 (ms) | イベント欠落 |
|---|---|---|---|
| 上流直結（ゲートなし） | 592 | 37 / 258 | — |
| ゲート経由 GET | 530–554 | 40 / 250–265 | 0（約 5000 件 / 50 バッチ） |
| ゲート経由 POST 2 KB + HTML 注入 | 435 | 57 / 267 | 0 |

目標（単一プロセス 300 RPS）は満たす。直結との差が小さいのは、負荷生成側（Python/httpx）も律速になっているため。

```bash
uv run python scripts/bench_gate.py [--duration 10 --concurrency 32 --inject --post-bytes 2048 --direct --gate-url URL]
```

## 8. 制約・既知の限界

- WebSocket・HTTP/2 上流・gRPC は v1 非対応（WebSocket は 501）。
- 単一プロセス（uvicorn workers=1）前提。レートリミット状態はプロセス内メモリ（LRU 10 万キー。溢れたキーは満タンから
  再開＝fail-open 側）。複数ワーカー/複数ゲートでは IP ごとの上限が台数倍になる。
- 捕捉は**リクエスト**本文のみ。応答本文は保存しない（サイズと型のみ）。
- 上流が **要求ボディを展開するか**（例: Express の body-parser、ASP.NET Core の RequestDecompression。対応する符号化は製品・版による。
  TODO(verify): 版ごとの br 対応）を
  確認すること。Gate は br・zstd を展開できない（`gate:req_encoding_unknown` だけ残る）ので、上流がそれらを展開する構成では
  圧縮ボディ内の攻撃は検知されない。
- 本文の redact は正規表現ベース。未知形式の秘密は残りうる。`capture_body_bytes=0` で本文捕捉を止められる。
- `trust_forwarded_for` は信頼 LB が 1 段の構成を想定（右端 1 個を採用）。多段構成は未対応。
- `/__tokiwa/health` の詳細は RFC1918 等の「プライベート」判定（Python `ipaddress.is_private`）に依存。
  ドキュメント用アドレス帯（TEST-NET）もプライベート扱いになる。
- ポリシー取得 API（`GET /api/v1/gate/policy`）は respond モジュールの実装に依存。未実装の間は 404 → WARN を 1 回出し、
  ポリシー無しで動作する。
