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
uv run tokiwa token create gate-1                    # 既定のスコープ: ingest + gate
uv run tokiwa token create agent-web01 --scope ingest
```

| スコープ | 許可されること |
|---|---|
| `ingest` | イベントの送信（`POST /api/v1/ingest/events`） |
| `gate` | Gate のポリシー取得（`GET /api/v1/gate/policy`） |
| `read` | 予約済み（v0.1 では、このスコープで使える API はまだありません） |

- トークン（`tkw_...`）は **作成時に一度だけ** 表示されます。DB にはハッシュだけが保存されます。
- Web UI の **設定 → API トークン**（管理者のみ）でも作成・失効できます。
- コマンドライン引数で渡すと `ps` で他のユーザーに見えるので、**環境変数またはファイル** で渡してください。

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

設定の優先順位は「CLI フラグ > 環境変数 `TOKIWA_GATE__*` / `tokiwa.yaml` > 既定値」です。

| 設定 | CLI | 既定 | 説明 |
|---|---|---|---|
| upstream | `--upstream` | `http://127.0.0.1:3000` | 転送先。パス接頭辞も可（`http://app/base`） |
| listen | `--listen host:port` | `0.0.0.0:8080` | 待ち受けアドレス |
| server_url | `--server` | `http://127.0.0.1:8788` | TOKIWA サーバー |
| ingest_token | `--token` / `--token-file` | なし | スコープ `ingest` と `gate` が必要 |
| capture_body_bytes | `--capture-body-bytes` | 4096 | 捕捉するリクエストボディの先頭バイト数（0 で捕捉しない） |
| policy_refresh_seconds | `--policy-refresh` | 5.0 | ポリシーを取りに行く間隔 |
| trust_forwarded_for | `--trust-forwarded-for` | false | `X-Forwarded-For` の **右端** を送信元 IP とする |

CLI だけにある運用ノブ: `--upstream-timeout`（30 秒）、`--max-queue`（送信待ちイベントの上限 10,000 件）、
`--preserve-host / --rewrite-host`、`--access-log`。

### 知っておくべき挙動

- **`--trust-forwarded-for` は信頼できるロードバランサの背後でのみ** 使ってください。付けないと、クライアントが送った
  `X-Forwarded-*` は捨てられ、Gate が観測した値に置き換えられます（送信元 IP の偽装を防ぐため）。
- 捕捉したデータは **送信前に Gate 側でマスク** されます（`Authorization` や `Cookie` などのヘッダ値、
  `password=` などのパラメータ値、トークン・鍵・メールアドレスなど）。
- **fail-open**: TOKIWA サーバーが止まっても、Gate のプロキシは止まりません（イベントは一時的に溜めて再送します）。
- **fail-static**: ポリシーが取れないときは最後のポリシーを維持します（サーバーを落として遮断を外させる、という抜け道を作らないため）。
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
- `kind` には `http` / `port_snapshot` / `connection` / `ids_alert` / `dns` / `process` / `auth` / `deception` /
  `llm_app` / `custom` などがあります。スキーマの詳細は、サーバーの API ドキュメント（`http://<server>:8788/api/docs`）を参照してください。
- ⚠️ **取り込み API ではサーバー側のマスキングは行われません**（Gate と Agent は送信前にマスクします）。
  直接送る場合は、パスワードやトークンなどの秘密を含めないでください。なお、LLM に渡す直前には必ずマスクされます。

HTTP の JSON チャット（既定で `/api/chat`、`/v1/chat/completions`、`/chat` 宛て）は、Gate 経由であれば
自動的にプロンプトインジェクション検知の対象になります（`detection.llm_app_paths` で変更可）。
