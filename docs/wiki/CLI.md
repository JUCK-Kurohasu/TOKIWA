> 🌐 **日本語** · [English](CLI-en) · [中文](CLI-zh) · [Español](CLI-es)

# CLI リファレンス

すべての操作は `tokiwa` コマンドで行います。ソースから使う場合は `backend/` ディレクトリで `uv run tokiwa ...`、
Docker イメージでは `tokiwa ...`（またはコンテナの引数としてサブコマンド名）です。
各コマンドの最新のオプションは `--help` で確認できます。

| コマンド | 内容 |
|---|---|
| `tokiwa version` | バージョンの表示 |
| `tokiwa serve` | サーバー（API・UI・取り込み・バックグラウンドジョブ） |
| `tokiwa user` | ユーザー管理 |
| `tokiwa token` | センサー用 API トークン |
| `tokiwa gate` | リバースプロキシ型センサー |
| `tokiwa agent` | ホストセンサー・ログ転送 |
| `tokiwa intel` | 脆弱性フィード |
| `tokiwa sim` | ラボ用トラフィックシミュレータ |
| `tokiwa eval` | 評価ハーネス |

> ⚠️ DB に直接アクセスするコマンド（`user`、`token`、`intel` など）は、サーバーと **同じ設定**（同じカレントディレクトリ、
> または同じ `TOKIWA_DATABASE__URL`）で実行してください。既定の DB パス `./data/tokiwa.db` は相対パスです。

## tokiwa serve

```bash
tokiwa serve [--host HOST] [--port 8788] [--reload] [--no-jobs]
```

| オプション | 説明 |
|---|---|
| `--host` / `--port` | 待ち受け（既定は設定値、ポート 8788） |
| `--reload` | コード変更で自動再起動（開発用） |
| `--no-jobs` | 定期ジョブ（インテル同期・期限切れ処理など）を起動しない |

API のドキュメントは `http://<server>:8788/api/docs`、ヘルスチェックは `/api/v1/health` です。

## tokiwa user create

```bash
tokiwa user create <username> [--role admin|analyst|viewer]
```

パスワードは対話的に（入力を隠して 2 回）尋ねられます。ロールの既定は `analyst` です。

## tokiwa token create

```bash
tokiwa token create <name> [--scope ingest] [--scope gate]
```

既定のスコープは `ingest` と `gate`。トークン（`tkw_...`）は **一度だけ** 表示されます。

## tokiwa gate run

```bash
tokiwa gate run --upstream http://127.0.0.1:3000 [--listen 0.0.0.0:8080] [--server http://127.0.0.1:8788] \
  [--token-file PATH] [--trust-forwarded-for] ...
```

| オプション | 既定 | 説明 |
|---|---|---|
| `--upstream` | 設定値 | 転送先の URL |
| `--listen` | `0.0.0.0:8080` | 待ち受け `host:port` |
| `--server` | 設定値 | TOKIWA サーバーの URL |
| `--token` / `--token-file` | — | API トークン（環境変数 `TOKIWA_GATE__INGEST_TOKEN` か、ファイルを推奨） |
| `--sensor-id` | `gate-1` | イベントに記録するセンサー ID |
| `--capture-body-bytes` | 4096 | 捕捉するボディの先頭バイト数 |
| `--trust-forwarded-for` | off | `X-Forwarded-For` の右端を送信元とする（信頼できる LB の背後のみ） |
| `--policy-refresh` | 5 | ポリシー取得間隔（秒） |
| `--batch-size` / `--flush-interval` | 100 / 1.0 | 送信のバッチ |
| `--upstream-timeout` | 30 | 上流の読み書きタイムアウト（秒） |
| `--max-queue` | 10000 | 送信待ちの上限（超えたら古いものから捨てる） |
| `--preserve-host` / `--rewrite-host` | preserve | Host ヘッダをそのまま送るか、上流のものに書き換えるか |
| `--access-log` | off | uvicorn のアクセスログ |
| `--log-level` | 設定値 | ログレベル |

## tokiwa agent

```bash
tokiwa agent run  [--server-url URL] [--nginx PATH ...] [--caddy PATH ...] [--suricata PATH ...] [--zeek-dir PATH ...]
tokiwa agent once [--print] [--max-events 1000] ...
```

| オプション | 説明 |
|---|---|
| `--server-url` | TOKIWA サーバーの URL |
| `--token` | API トークン（環境変数 `TOKIWA_AGENT__INGEST_TOKEN` を推奨） |
| `--sensor-id` | センサー ID（既定はホスト名） |
| `--interval` | ホストセンサーの間隔（秒） |
| `--host-sensor / --no-host-sensor` | 待ち受けポート・接続の収集 |
| `--connections / --no-connections` | 新しい TCP 接続の報告 |
| `--nginx` / `--caddy` / `--suricata` / `--zeek-dir` | 取り込むログ（複数指定可） |
| `--from-beginning / --from-end` | ログをどこから読むか（既定: 末尾） |
| `once --print` | 1 回だけ収集し、送信せずに JSON を表示（動作確認用） |

## tokiwa intel

```bash
tokiwa intel sync [-s kev] [-s nvd]   # 同期を 1 回実行（既定: 有効なソースすべて）
tokiwa intel status                   # ソースごとの同期状態
tokiwa intel show CVE-2021-44228 [--json]   # 統合済みの 1 件を表示（CVE / GHSA / JVNDB の ID）
```

## tokiwa sim

```bash
tokiwa sim profiles
tokiwa sim run      [--profile mixed] [--target http://localhost:8080] [--sessions N] [--seed 1] \
                    [--time-scale 1.0] [--spread 60] [--max-requests 2000] [--max-rps 50] \
                    [--spoof-xff] [--record FILE.jsonl] [--loop] [--i-own-this-target]
tokiwa sim generate --out FILE.jsonl [--profile mixed] [--sessions N] [--seed 1] [--start ISO8601] [--spread 1800] [--no-canary]
tokiwa sim ingest   [--server http://localhost:8788] [--token-file PATH] [--profile mixed] [--batch-size 200]
```

| サブコマンド | 内容 |
|---|---|
| `profiles` | プロファイルの一覧 |
| `run` | ラボのターゲット（Gate）に実際にトラフィックを送る |
| `generate` | ネットワークを使わずにラベル付きデータセットを生成（同じ seed なら同一ファイル） |
| `ingest` | 合成イベントを取り込み API に直接送る（Gate 不要） |

`--profile` は `ai_agent`、`ai_agent,scanner`、`ai_agent=2,benign_browser=5`、`mixed` のように指定します。
`--time-scale` を 1 未満にすると速く終わりますが、リクエストのリズムが変わり、AI 判定の特徴量にも影響します。

## tokiwa eval

```bash
tokiwa eval run --dataset FILE.jsonl [--llm mock|live] [--budget-usd N] [--out DIR] \
                [--compare PREV] [--fail-on-regression] [--speed 0] [--json]
tokiwa eval compare <current> <previous> [--fail-on-regression]
tokiwa eval import-artex <source> --out FILE.jsonl [--host HOST] [--session LABEL] [--source-ip IP]
tokiwa eval info FILE.jsonl
```

| オプション | 説明 |
|---|---|
| `--llm` | `mock`（無料・オフライン、既定）または `live`（設定済みのプロバイダ。**費用が発生**） |
| `--budget-usd` | `--llm live` のときに **必須**。この実行の費用の上限 |
| `--out` | 出力先（既定 `eval/runs/<UTC 時刻>`） |
| `--compare` / `--fail-on-regression` | 前回との比較 / 悪化していたら終了コード 1 |
| `--speed` | 0 = 最速、1 = 実時間、10 = 10 倍速 |
| `--enable-detector` / `--disable-detector` | 検知器を強制的に有効 / 無効にする |
| `--keep-work` | 評価用の一時 DB を残す |
