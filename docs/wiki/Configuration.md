> 🌐 **日本語** · [English](Configuration-en) · [中文](Configuration-zh) · [Español](Configuration-es)

# 設定リファレンス

## 設定の渡し方と優先順位

上にあるものほど優先されます。

1. **環境変数** `TOKIWA_*`（ネストは `__` でつなぐ。例: `TOKIWA_LLM__DAILY_BUDGET_USD=10` → `llm.daily_budget_usd`）
2. **YAML ファイル**: `TOKIWA_CONFIG` で指定したパス（既定はカレントディレクトリの `tokiwa.yaml`。無ければ無視）
3. **既定値**（`backend/src/tokiwa/config.py`）

さらに、次の 2 つは **Web UI から実行時に上書き** でき、その値は DB に保存されます。

- LLM の設定（**LLM → 設定**）: プロバイダ・モデル・予算・出力言語・API キーなど
- 検知器の有効 / 無効（**検知ルール → 検知器**）

**画面で保存した値は、その項目について環境変数・YAML より優先されます**（DB の値が勝つ）。再起動しても、DB を復元しても残ります。
起動時に、静的な設定と異なる LLM の項目名がログに WARNING で出ます（値は出しません）。LLM → 設定の「画面での上書き」で
どの項目が DB から来ているかを確認でき、**上書きをすべてリセット**（`DELETE /api/v1/llm/config`、管理者のみ・監査記録あり）で
静的な設定に戻せます。環境変数・YAML で LLM の設定を固定したいとき（例: 外部の LLM に一切送らないよう `TOKIWA_LLM__PROVIDER=mock` を
強制する）は `TOKIWA_LLM__ALLOW_UI_OVERRIDE=false`（`llm.allow_ui_override`、既定 true）を設定してください。DB の上書きは無視され、
画面からの変更（`PUT /api/v1/llm/config`）は 409 になります。この設定自体は画面からは変えられません。

Docker Compose では `.env` が環境変数としてコンテナに渡されます。ローカルで `tokiwa serve` を直接動かす場合、
`.env` は自動では読み込まれません。

### 書き方の注意

- **リストや辞書は JSON で** 書きます: `TOKIWA_DETECTION__DISABLED_DETECTORS='["web.scanner_ua"]'`
- **空の値で設定しないでください**（空文字は項目によって意味が変わります）。`TOKIWA_SERVER__SECRET_KEY=`（空）は未設定として扱われ、`data_dir/secret.key` の自動生成の鍵が使われます。設定する場合は 32 文字以上が必要で、短いとサーバーが起動しません。
- 秘密（API キー・パスワード）は YAML ではなく環境変数で渡すことを勧めます。

### YAML の例

```yaml
# tokiwa.yaml
server:
  base_url: https://tokiwa.example.internal
llm:
  daily_budget_usd: 10
  output_language: ja
triage:
  min_severity_for_llm: high
response:
  protected_cidrs: ["127.0.0.0/8", "::1/128", "10.0.0.0/24"]
  default_ttl_minutes: 30
deception:
  labyrinth_enabled: true
```

## 主な設定項目

### 全体・サーバー・DB

| キー | 既定 | 説明 |
|---|---|---|
| `env` | `dev` | `dev` / `prod` / `test` |
| `log_level` | `INFO` | ログレベル |
| `server.host` / `server.port` | `0.0.0.0` / `8788` | 待ち受け |
| `server.base_url` | `http://localhost:8788` | 利用者が開く URL（通知のリンクなど） |
| `server.cors_origins` | `["http://localhost:5173"]` | UI を別オリジンから配信する場合のみ |
| `server.static_dir` | なし | ビルド済み UI（`frontend/dist`）。指定すると `/` で配信 |
| `server.data_dir` | `./data` | データの保存先（署名鍵など） |
| `server.secret_key` | 自動生成 | ログイン（JWT）の署名鍵（32 文字以上）。未設定・空なら `data_dir/secret.key`（権限 0600）に生成・保存 |
| `server.token_ttl_minutes` | 720 | ログインの有効時間 |
| `auth.setup_code_required` | `true` | 初回セットアップ（最初の管理者作成）に、起動ログと `data_dir/setup-code` に出る 1 回限りのコードを要求する |
| `server.max_body_bytes` | 1048576（1 MiB） | リクエストボディの上限。超えると 413。インジェスト以外の全 API に適用 |
| `server.security_headers` | `true` | 全応答に CSP・`X-Frame-Options: DENY`・`nosniff`・`Referrer-Policy: no-referrer` を付ける。プロキシで独自ポリシーを付ける場合やカスタム UI で CSP が合わない場合のみ `false` |
| `server.expose_docs` | `true` | API ドキュメント（`/api/docs`・`/api/openapi.json`）を認証なしで公開する。本番では `false` を推奨 |
| `server.max_ingest_body_bytes` | 33554432（32 MiB） | `/api/v1/ingest/` のボディ上限。超えたバッチは 413 になり、Gate / エージェントはそのバッチを**破棄**する。`batch_size` を大きくする場合は合わせて上げる |
| `auth.login_max_failures` | 5 | 同じユーザー名 × 送信元 IP のログイン失敗がこの回数に達すると、一時的に拒否（429）。0 で無効 |
| `auth.login_max_failures_per_ip` | 30 | 1 つの送信元 IP からの失敗（ユーザー名を問わない。パスワードスプレー対策）の上限。0 で無効 |
| `auth.login_lockout_minutes` | 15 | 上の 2 つを数える時間窓（分）。古い失敗が窓から外れると解除 |
| `auth.password_hash_concurrency` | 4 | 同時に計算するパスワードハッシュ（scrypt）の数 |
| `database.url` | `sqlite+aiosqlite:///./data/tokiwa.db` | PostgreSQL は `postgresql+asyncpg://user:pass@host/db` |

### LLM（`llm.*`）

[LLM の設定とコスト](LLM) を参照してください。主なもの: `provider`、`anthropic_api_key`（または環境変数 `ANTHROPIC_API_KEY`）、
`openai_base_url` / `openai_api_key`、`model_fast` / `model_deep`、`daily_budget_usd`、`output_language`、`redaction.*`。

### 検知（`detection.*`）

| キー | 既定 | 説明 |
|---|---|---|
| `disabled_detectors` | `[]` | 無効にする検知器の ID |
| `sigma_rule_dirs` | パッケージ位置から解決（ソースでは `<リポジトリ>/rules/sigma`、Docker イメージでは `/app/rules/sigma`） | Sigma ルールの置き場所。起動時の作業ディレクトリには依存しない。見つからないディレクトリは起動時に ERROR ログ。相対パスを指定した場合は作業ディレクトリ → `backend/` の順に探す |
| `dedup_window_seconds` | 300 | 同じアラートをまとめる時間幅 |
| `llm_app_paths` | `/api/chat`, `/v1/chat/completions`, `/chat` | プロンプトインジェクションの監視対象とする HTTP パス |
| `session_idle_timeout_seconds` | 1800 | この時間アクセスがなければ別セッションとみなす |
| `ai_agent_threshold` | 0.7 | AI エージェントと判定する AI スコアのしきい値 |
| `web.*` | — | Web 系のレート検知のしきい値（エラーの連発、ログイン失敗、フラッドなど） |

### トリアージ・相関（`triage.*`）

| キー | 既定 | 説明 |
|---|---|---|
| `auto_triage` | true | アラートを自動で LLM トリアージする |
| `min_severity_for_llm` | `medium` | LLM に回す最低重大度 |
| `escalate_confidence_below` | 0.6 | 軽量モデルの信頼度がこれ未満なら上位モデルへ |
| `escalate_severity` | `high` | この重大度以上は上位モデルへ |
| `max_concurrent` | 4 | 同時トリアージ数 |
| `incident_window_minutes` | 60 | アラートを同じインシデントに束ねる時間幅 |
| `max_evidence_events` | 25 | LLM に渡す証拠イベントの最大数 |

### 対処（`response.*`）

| キー | 既定 | 説明 |
|---|---|---|
| `auto_approve_enabled` / `auto_approve_actions` | false / `[]` | 自動承認（両方の設定が必要） |
| `default_ttl_minutes` / `max_ttl_minutes` | 60 / 10080 | TTL の既定と上限 |
| `protected_cidrs` | `127.0.0.0/8`, `::1/128` | 絶対に対象にしない範囲 |
| `protect_server_addresses` | true | サーバー自身の IP を保護 |
| `block_private_targets` | false | プライベートアドレスを対象にすることを禁止（管理網の保護） |
| `default_rate_limit_rpm` / `default_tarpit_delay_ms` | 60 / 2000 | レート制限・tarpit の既定値 |
| `nftables_enabled` | false | nftables による遮断 |
| `webhook_urls` / `webhook_allowed_hosts` / `webhook_block_private` | `{}` / `[]` / true | 対処としての Webhook の送信先と SSRF 対策 |

### デセプション（`deception.*`）・インテリジェンス（`intel.*`）

[デセプション（Mirage）](Deception) と [脆弱性インテリジェンス](Threat-Intel) を参照してください。

### Gate（`gate.*`）・Agent（`agent.*`）

| キー | 既定 | 説明 |
|---|---|---|
| `gate.upstream` | `http://127.0.0.1:3000` | 転送先 |
| `gate.listen_host` / `gate.listen_port` | `0.0.0.0` / 8080 | 待ち受け |
| `gate.server_url` | `http://127.0.0.1:8788` | TOKIWA サーバー |
| `gate.ingest_token` | なし | API トークン（scope: ingest + gate） |
| `gate.token_file` | なし | API トークンのファイル。変更時と 401 受信時に読み直す（ローテーション時に再起動不要）。読めれば `ingest_token` より優先 |
| `gate.capture_body_bytes` | 4096 | 捕捉するボディの先頭バイト数 |
| `gate.trust_forwarded_for` | false | `X-Forwarded-For` を信頼する |
| `agent.server_url` | `http://127.0.0.1:8788` | TOKIWA サーバー |
| `agent.ingest_token` | なし | API トークン（scope: ingest） |
| `agent.interval_seconds` | 10 | ホストセンサーの収集間隔 |
| `agent.nginx_json_logs` / `caddy_json_logs` / `suricata_eve_logs` / `zeek_log_dirs` | `[]` | 取り込むログ |
| `agent.verify_tls` | true | サーバーの TLS 証明書を検証する |

### 通知（`notify.*`）・コパイロット（`copilot.*`）

| キー | 既定 | 説明 |
|---|---|---|
| `notify.default_webhook_url` | なし | 画面で登録しなくても使える既定の Webhook |
| `notify.default_min_severity` | `high` | 既定 Webhook の最低重大度 |
| `notify.public_ui_url` | なし | 通知に入れる UI のリンク先 |
| `notify.language` | `both` | 通知の言語 |
| `notify.dedup_minutes` | 10 | 同じ通知を抑制する時間 |
| `notify.allowed_hosts` / `notify.block_private_destinations` | `[]` / true | 送信先の制限（SSRF 対策） |
| `copilot.enabled` | true | コパイロット |
| `copilot.tier` | `deep` | 使うモデルのティア |
| `copilot.max_tool_iterations` | 8 | 1 回の質問でツールを使う最大回数 |
| `copilot.min_role` | `analyst` | 会話の作成・送信に必要な最低ロール（`viewer` / `analyst` / `admin`）。1 回の質問で deep ティアを最大 8 回呼び、日次予算は全体共通のため既定で viewer は不可 |
| `copilot.messages_per_minute` | 6 | ユーザーごとの 1 分あたり送信数の上限（0 で無制限）。超えると 429 |

すべての項目は `backend/src/tokiwa/config.py` にあります。Docker 用の例は、リポジトリ直下の `.env.example` を参照してください。
