> 🌐 **日本語** · [English](Sensors-en) · [中文](Sensors-zh) · [Español](Sensors-es)

# センサーの接続

TOKIWA サーバーはデータを自分で集めに行かず、**センサーが送ってくるイベント** を分析します。
センサーは 3 種類あり、組み合わせて使えます。

| センサー | 見えるもの | 向いている用途 |
|---|---|---|
| **TOKIWA Gate** | HTTP リクエストの全体（**ボディを含む**）とレスポンスの状態 | Web アプリ・API の保護。遮断・デコイも Gate が実行する |
| **TOKIWA Agent** | ホストの待ち受けポート・接続、nginx / Caddy の JSON ログ、Suricata、Zeek | サーバーの監視、既存ログの取り込み |
| **取り込み API（直接）** | 自分で送ったもの（LLM アプリのプロンプトなど） | 独自の連携 |

## API トークン

センサーはユーザーのログインではなく **API トークン** で認証します。

```bash
cd backend
uv run tokiwa token create gate-1 --scope ingest --scope gate   # Gate 用: gate スコープを明示
uv run tokiwa token create agent-web01            # 既定のスコープ: ingest のみ
```

| スコープ | 許可されること |
|---|---|
| `ingest` | イベントの送信（`POST /api/v1/ingest/events`） |
| `gate` | Gate のポリシー取得（`GET /api/v1/gate/policy`） |
| `read` | 予約済み（v0.1 では、このスコープで使える API はまだありません） |

- トークン（`tkw_...`）は **作成時に一度だけ** 表示されます。DB にはハッシュだけが保存されます。
- Web UI の **設定 → API トークン**（管理者のみ）でも作成・失効できます。
- コマンドライン引数で渡すと `ps` で他のユーザーに見えるので、**環境変数またはファイル** で渡してください。
- `--sensor-id` / `--dataset` でトークンを特定のセンサー ID・dataset に **縛れます**（省略時は無制限）。縛ったトークンが
  範囲外の dataset を送るとバッチごと 403、別のセンサー ID を名乗ると許可された ID に置き換えられます。Gate 以外のセンサーの
  トークンは縛っておくのがおすすめです（例: `--sensor-id web01 --dataset nginx.access --dataset 'host.*'`）。
- サーバーはすべてのイベントに、送ってきたトークンを `ingest.token` / `ingest.token_id` ラベルとして記録します。
  `gate` スコープの無いトークンから来た Gate 由来のデータ（`gate.*` / `deception.*`）には `ingest.trust=low` が付きます。
  偽造イベントで無実の IP を遮断させられないよう、取引先・CDN・自社の出口 IP は `response.protected_cidrs` に入れておいてください。

## TOKIWA Gate（リバースプロキシ型センサー）

守りたい Web アプリの前に置くリバースプロキシです。アクセスログでは見えないリクエストボディまで捕捉し、
サーバーが配布するポリシー（遮断・レート制限・tarpit・デコイ）を即座に適用します。

```
クライアント ──▶ Gate (:8080) ──▶ 守りたいアプリ
                   │ イベント送信 / ポリシー取得（既定 5 秒ごと）
                   ▼
              TOKIWA Server (:8788)
```

### 起動

```bash
cd backend
export TOKIWA_GATE__INGEST_TOKEN=tkw_...          # または --token-file <path>
uv run tokiwa gate run --upstream http://127.0.0.1:3000 --listen 0.0.0.0:8080 --server http://127.0.0.1:8788
```

利用者は今後 Gate（:8080）にアクセスするように、DNS やロードバランサの向き先を変えます。

### 主な設定

設定の優先順位は「CLI フラグ > 環境変数 `TOKIWA_GATE__*` > `tokiwa.yaml` > 既定値」です。

| 設定 | CLI | 既定 | 説明 |
|---|---|---|---|
| upstream | `--upstream` | `http://127.0.0.1:3000` | 転送先。パス接頭辞も可（`http://app/base`） |
| listen | `--listen host:port` | `0.0.0.0:8080` | 待ち受けアドレス |
| server_url | `--server` | `http://127.0.0.1:8788` | TOKIWA サーバー |
| ingest_token | `--token-file`（`--token` は `ps` で見えるので使わない） | なし | スコープ `ingest` と `gate` が必要。環境変数 `TOKIWA_GATE__INGEST_TOKEN` でも可 |
| capture_body_bytes | `--capture-body-bytes` | 4096 | 捕捉するリクエストボディの先頭バイト数（0 で捕捉しない） |
| policy_refresh_seconds | `--policy-refresh` | 5.0 | ポリシーを取りに行く間隔 |
| trust_forwarded_for | `--trust-forwarded-for` | false | `X-Forwarded-For` の **右端** を送信元 IP とする |
| max_request_headers | —（`TOKIWA_GATE__MAX_REQUEST_HEADERS`） | 100 | ヘッダ行がこれを超える要求は上流へ転送せず 431（0 で無効） |
| forward_client_headers | —（`TOKIWA_GATE__FORWARD_CLIENT_HEADERS`） | `[]` | 既定では除去するヘッダ（下記）のうち、そのまま上流へ渡すもの |
| tarpit_max_concurrent / tarpit_max_per_client | — | 256 / 8 | tarpit で同時に保持する要求の上限（全体 / 同じ IP）。超えた要求は 429（0 で無制限） |
| trusted_proxies | —（`TOKIWA_GATE__TRUSTED_PROXIES`） | `[]` | `trust_forwarded_for` 時、`X-Forwarded-For` を読むのは接続元がここに含まれる場合だけ（IP / CIDR。例 `["10.0.0.0/8"]`）。空は従来動作（どの接続元も信頼）で起動時に警告、`TOKIWA_STRICT_CONFIG=1` なら起動拒否 |
| body_idle_timeout_seconds / body_total_timeout_seconds | — | 15 / 120 | リクエストボディが途切れた時間 / 全体の上限。超えると 408 を返し上流接続を解放（タグ `gate:slow_body`。0 で無制限） |
| max_requests_per_client | — | 64 | 同じ送信元 IP の処理中リクエスト数の上限。超えると即 429（タグ `gate:conn_limit`。0 で無制限） |
| persist_policy / policy_cache_file / policy_cache_max_age_hours | — | true / `<server.data_dir>/gate-policy-<sensor_id>.json` / 168 | 取得したポリシーを保存し、起動時にサーバーへ繋がらなくても強制する（古すぎる保存は使わない。0 で無制限） |

CLI だけにある運用ノブ: `--upstream-timeout`（30 秒）、`--max-queue`（送信待ちイベントの上限 10,000 件）、
`--preserve-host / --rewrite-host`、`--access-log`、`--limit-concurrency`（同時接続の上限。超えると 503。既定は無制限）。

### 知っておくべき挙動

- **`--trust-forwarded-for` は信頼できるロードバランサの背後でのみ** 使ってください。付けないと、クライアントが送った
  `X-Forwarded-*` は捨てられ、Gate が観測した値に置き換えられます（送信元 IP の偽装を防ぐため）。
- `X-Real-IP`・`Forwarded`・`True-Client-IP`・`CF-Connecting-IP` など、送信元 IP・スキームを名乗るほかのヘッダと、`X-Original-URL` /
  `X-Rewrite-URL` は **上流へ渡しません**。代わりに Gate が `X-Real-IP` と `Forwarded` に自分が判定した送信元 IP を付けます。
  Cloudflare などの前段が付けるヘッダを上流が読む場合は、`forward_client_headers` に列挙してください（例: `["cf-connecting-ip"]`）。
  クライアントが送っていない `User-Agent` などを Gate が補うこともありません。
- デコイの照合は大文字小文字・末尾の `/` や `.`・`;` 以降・`%5c`（`\`）・二重エンコードの違いを同じパスとみなします
  （`/.ENV` や `/.env;x` も `/.env` のデコイに当たります）。こうした変形を含むパスにはタグ `gate:path_anomaly` が付きます。
- Gate 自身が返す応答（遮断の 403、デコイ、上流障害の 502/504 など）には `Cache-Control: no-store` を付けます。Gate の前に CDN を
  置く場合は、CDN が 404 などを強制的にキャッシュする設定になっていないか確認してください。
- `Content-Encoding: gzip` / `deflate` の要求ボディは展開してから記録します（タグ `gate:req_encoded`。上流には圧縮したまま送ります）。
  br・zstd は展開できず、タグ `gate:req_encoding_unknown` だけが残ります。
- 捕捉したデータは **送信前に Gate 側でマスク** されます（`Authorization` や `Cookie` などのヘッダ値、
  `password=` などのパラメータ値、トークン・鍵・メールアドレスなど）。
- イベントに残すリクエストヘッダは 64 種類までです。User-Agent・Referer・`Sec-Fetch-*`・`X-Forwarded-*` など検知に使うヘッダは
  位置に関係なく必ず残し、超えた分はタグ `gate:headers_truncated` とヘッダ数（label `gate.header_count`）で分かるようにします。
- **fail-open**: TOKIWA サーバーが止まっても、Gate のプロキシは止まりません（イベントは一時的に溜めて再送します）。
- **送信元 IP**: `trust_forwarded_for` を有効にしたら `trusted_proxies` に前段の LB / CDN のアドレスを列挙してください。列挙した接続元からの
  `X-Forwarded-For` だけを右から読み、信頼するプロキシの分を飛ばした最初のアドレスを送信元にします。IP でない要素（`unknown` など）が
  あればそこで止めます。列挙外の接続元が `X-Forwarded-For` を送ってきた場合は無視し、タグ `gate:untrusted_forwarded_for` を付けます。
- **低速攻撃**: ボディを少しずつ送る要求は 408、同じ IP からの同時要求が多すぎる場合は 429 で切ります。**ヘッダを少しずつ送る攻撃
  （slowloris）は Gate より手前の uvicorn の段階で起きるため Gate では防げません**。インターネットに直接出す場合は、ヘッダの読み取り
  タイムアウトを持つ nginx やロードバランサを前に置いてください。
- **再起動時のポリシー**: 最後に取得したポリシー（遮断・デコイ・カナリア）をファイルに保存し、起動直後にサーバーへ繋がらなくても
  それを強制します。期限の過ぎた項目は外します。Docker では `/data` にボリュームが要ります（`deploy/compose.yaml` の `gate-state`）。
- **イベントの破棄**: サーバー停止中に送信待ちがあふれると、まず普通のページ閲覧（GET/HEAD・2xx/3xx・クエリなし・タグなし）から捨てます。
  捨てた件数は次にサーバーへ届く送信で `gate.health` イベントとして報告し、検知 `sensor.events_dropped` が出ます。
- **fail-static**: ポリシーが取れないときは最後のポリシーを維持します（サーバーを落として遮断を外させる、という抜け道を作らないため）。ただし各遮断の期限（TTL）は Gate 側でも守り、期限を過ぎたものは外します。
- ヘルスチェック: `GET /__tokiwa/health` → `{"status":"ok"}`。ローカル／プライベート IP からは送信統計なども返します。
- 未対応: WebSocket（501 を返します）、HTTP/2 の上流、gRPC。Gate は単一プロセス前提です。

## TOKIWA Agent（ホストセンサー・ログ転送）

```bash
cd backend
export TOKIWA_AGENT__INGEST_TOKEN=tkw_...
uv run tokiwa agent run --server-url http://tokiwa.example.internal:8788 \
  --nginx /var/log/nginx/tokiwa.json.log \
  --suricata /var/log/suricata/eve.json
```

| 収集対象 | オプション | 内容 |
|---|---|---|
| ホスト | `--host-sensor`（既定 ON）、`--connections`（既定 ON）、`--interval` | 待ち受けポートの一覧と変化、新しい TCP 接続 |
| nginx | `--nginx <path>`（複数可） | JSON 形式のアクセスログ（形式はリポジトリの `lab/nginx/tokiwa-json.conf`） |
| Caddy | `--caddy <path>` | JSON アクセスログ |
| Suricata | `--suricata <path>` | `eve.json` |
| Zeek | `--zeek-dir <path>` | ログディレクトリまたは単一ファイル |

- ログは既定で **末尾から** 読み始めます（`--from-beginning` で先頭から）。
- 動作確認には `tokiwa agent once --print`（1 回だけ収集し、送信せずに JSON を表示）が便利です。
- 他ユーザーのプロセス情報を読むには root 相当の権限が必要になる場合があります。
- ポートの初回スナップショットで見つかった待ち受けは、既定（`agent.ports_first_snapshot: info`）では重大度「情報」として
  記録されます（`learn` にすると記録せずに基準として覚えるだけ）。以後、新しい待ち受けが現れると検知されます。
- **コマンドライン**: 待ち受け・接続のプロセスのコマンドラインは、送信前にエージェント側で秘密を伏字にします
  （`--password X`・`--api-key X` など名前で分かる引数、`mysql -pX`・`redis-cli -a X`・`sshpass -p X`・`curl -u user:X`・
  `smbclient -U user%X` など代表的なツールのオプション、`*_KEY=X` などの環境変数代入、URL 中の資格情報）。プログラム名・
  オプション名・パスは残します。位置引数で渡したパスワードなどは伏字にならないことがあるため、引数に秘密を置くホストでは
  `TOKIWA_AGENT__SEND_CMDLINE=false`（名前・実行ファイル・ユーザーだけを送る）を推奨します。引数で渡したハニートークンも伏字になり、
  デセプションの照合には掛かりません。
- **新しい接続の上限**: 1 周期の新しい接続が `agent.max_connections_per_cycle`（既定 1000）を超えると、確立済み・外向き・
  プロセスの分かる接続から先に送り、残りは捨てずに次の周期へ回します。超過はポートのスナップショットのラベル
  `connections_truncated` と検知 `sensor.connections_truncated`（中）で分かります（大量のダミー接続で C2 を隠す手口への対策）。
- **nginx のログ書式**: `log_format ... escape=json` を使ってください（`lab/nginx/tokiwa-json.conf`）。`escape=json` が無いと
  `"` が `\x22` と書かれて JSON として不正になります。エージェントは復号して取り込みますが、警告を出します。
- **ログの時刻**: オフセット付き（ISO 8601 の `+09:00` / `Z`、`$time_local` など）が確実です。オフセットの無い時刻（独自書式、
  Caddy の `wall` など）は `agent.log_timezone`（例 `Asia/Tokyo`・`+09:00`・`UTC`）で解釈します。未設定だと UTC とみなし、
  その件数を警告します（JST のログなら 9 時間ずれます）。不正な値は起動時にエラーになります。
- **読めなかった行**: JSON として読めない行・解釈できない時刻は数えられ、最初はすぐ、以後は最短 `agent.health_report_seconds`
  （既定 300 秒）ごとに警告ログと `agent.health` イベントを送ります。読めない行があると検知 `sensor.log_parse_failures` が出ます。
  `agent.health` は dataset を縛ったトークンでも受け付けられます。
- **Suricata のアラートの向き**: EVE のアラートの `src_ip` は一致したパケットの向きです。応答方向（`direction: to_client`、
  例: ATTACK_RESPONSE）のアラートでは、接続を始めた側を攻撃者（送信元）にします。ルールの `target` があればそれを優先し、
  ET の `metadata.attack_target` が `Client_Endpoint` なら入れ替えません。判断はラベル `suricata.direction` /
  `suricata.attribution` / `suricata.swapped` に、元の向きは `raw` に残ります。

## 取り込み API（直接送信・LLM アプリ連携）

独自のシステムからイベントを送るときは、取り込み API を直接呼びます。たとえば社内の LLM アプリで、
ユーザーのプロンプトを TOKIWA に送ってプロンプトインジェクションを監視できます。

```bash
curl -X POST http://127.0.0.1:8788/api/v1/ingest/events \
  -H "X-Tokiwa-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "events": [{
      "kind": "llm_app",
      "dataset": "support-bot.prompts",
      "source": {"ip": "203.0.113.10"},
      "llm_app": {"app": "support-bot", "role": "user", "prompt": "Ignore all previous instructions and ..."}
    }]
  }'
```

- 認証ヘッダは `X-Tokiwa-Token: tkw_...` または `Authorization: Bearer tkw_...`。スコープ `ingest` が必要です。
- 1 リクエストあたり最大 **5,000 イベント**。`timestamp` を省略すると受信時刻になります。
- リクエストボディは既定で最大 32 MiB（`server.max_ingest_body_bytes`、超えると 413）。1 つの文字列フィールドが 65,536 文字を
  超えると先頭だけを残して切り詰め、イベントにタグ `truncated` とラベル `tokiwa.truncated`（`フィールド:元の長さ`）を付けます
  （拒否はしません。検知は切り詰め後の値で行われます）。
- `kind` には `http` / `port_snapshot` / `connection` / `ids_alert` / `dns` / `process` / `auth` / `deception` /
  `llm_app` / `custom` などがあります。スキーマの詳細は、サーバーの API ドキュメント（`http://<server>:8788/api/docs`）を参照してください。
- ⚠️ **取り込み API ではサーバー側のマスキングは行われません**（Gate と Agent は送信前にマスクします）。
  直接送る場合は、パスワードやトークンなどの秘密を含めないでください。なお、LLM に渡す直前には必ずマスクされます。

HTTP の JSON チャット（既定で `/api/chat`、`/v1/chat/completions`、`/chat` 宛て）は、Gate 経由であれば
自動的にプロンプトインジェクション検知の対象になります（`detection.llm_app_paths` で変更可）。
