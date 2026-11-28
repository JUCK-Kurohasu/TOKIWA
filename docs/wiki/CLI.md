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
| `tokiwa data` | 特定の IP・セッションのデータの削除・書き出し |

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
API ドキュメント（`/api/docs`・`/api/openapi.json`）は認証なしで公開されるため、本番では `server.expose_docs: false`
（環境変数 `TOKIWA_SERVER__EXPOSE_DOCS=false`）で無効にすることを推奨します。ヘルスチェックは認証不要ですが、
バージョンはログイン済みのときだけ返します。

## tokiwa user create

```bash
tokiwa user create <username> [--role admin|analyst|viewer]
```

パスワードは対話的に（入力を隠して 2 回）尋ねられます。ロールの既定は `analyst` です。
既に同じ名前のユーザーがいる場合は、エラーメッセージを表示して終了します（終了コード 1）。作成は監査ログに `user.create`（操作者 `cli`）として残ります。
管理者が 1 人もいなくなったときの復旧にも使えます（`--role admin`）。

## tokiwa user reset-password

```bash
tokiwa user reset-password <username>
```

新しいパスワードを対話的に（入力を隠して 2 回）尋ね、設定します。そのユーザーの既存のログインはすべて無効になり、監査ログに `user.password_reset`（操作者 `cli`。パスワードは記録しません）が残ります。管理者のパスワードを忘れたときに使います。

## tokiwa token create

```bash
tokiwa token create <name> [--scope ingest] [--scope gate] [--sensor-id ID ...] [--dataset PATTERN ...]
```

既定のスコープは `ingest` **のみ**。Gate 用のトークンは `--scope ingest --scope gate` を明示します（`gate` スコープはデコイ経路・カナリア値・ブロックリストを含む Gate ポリシーを読めるため、Gate 以外に付けない）。トークン（`tkw_...`）は **一度だけ** 表示されます。
`--sensor-id` / `--dataset`（繰り返し可）はトークンをセンサー ID・dataset に縛ります（[センサーの接続](Sensors)）。
`--expires-in-days N` で有効期限を付けられます（既定は無期限）。期限切れのトークンは 401 になります。

## tokiwa token list / revoke / rotate

```bash
tokiwa token list [--all]                                  # 一覧（秘密は表示しない。--all で失効済みも）
tokiwa token revoke <id|name>                              # 即時失効
tokiwa token rotate <id|name> [--grace-hours 24] [--expires-in-days N]   # 新トークンを発行（標準出力に一度だけ）
```

管理者ログインが無くても（パスワード紛失・インシデント対応中でも）サーバーのホストでトークンを止められます。
操作は監査ログに actor `cli` で記録されます。`rotate` は同じ名前・スコープ・縛りの新トークンを発行し、旧トークンを
`--grace-hours`（既定 24 時間、0 で即時失効）だけ有効のまま残します。Gate はトークンファイルの変更を自動で読み直すので、
新しいトークンをファイルに書けば再起動なしで切り替わります。名前が複数の有効なトークンに当たるときは id を指定します。

## tokiwa config show

```bash
tokiwa config show [--changed] [-s SECTION] [--db] [--json] [--check]
```

効いている設定を出所つきで表示します（秘密は `<set>`）。詳しくは [設定リファレンス](Configuration)。

## tokiwa data purge / export

```bash
tokiwa data purge  [--ip IP] [--session ID] [--before 2026-11-01] [--yes]   # 既定は件数だけ表示（dry run）
tokiwa data export [--ip IP] [--session ID] [--before ...] [--out subject.jsonl]
```

特定の送信元 IP・アクターセッション・期間について、保存されたデータをまとめて削除・書き出しします（本人からの開示・削除の依頼、
誤って取り込んだ顧客データの除去など）。条件は AND で組み合わせます。対象: `events`・`actor_sessions`・`deception_trips` は行を削除、
`alerts` は `details` を消去（インシデントとの紐付けのため行は残す）、`llm_calls` はプロンプト・応答本文だけを消去（費用の記録は残す）。
LLM の記録は IP / セッション ID を語の境界つきで照合します（`10.0.0.1` は `10.0.0.15` に一致しない）。`export` は JSONL
（1 行 1 レコード `{"table": ..., "row": {...}}`）で、`--out` のファイルは権限 600。どちらも監査ログに actor `cli` で残ります。
インシデントの概要文・コパイロットの会話・バックアップは対象外です。

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
| `--token` / `--token-file` | — | API トークン（環境変数 `TOKIWA_GATE__INGEST_TOKEN` か、ファイルを推奨。ファイルは変更時と 401 受信時に読み直す） |
| `--sensor-id` | `gate-1` | イベントに記録するセンサー ID |
| `--capture-body-bytes` | 4096 | 捕捉するボディの先頭バイト数 |
| `--trust-forwarded-for` | off | `X-Forwarded-For` から送信元を決める（信頼できる LB の背後のみ。LB のアドレスは `gate.trusted_proxies` に列挙） |
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
                [--compare PREV] [--fail-on-regression] [--allow-mismatch] [--speed 0] [--json]
tokiwa eval compare <current> <previous> [--fail-on-regression] [--allow-mismatch]
tokiwa eval import-artex <source> --out FILE.jsonl [--host HOST] [--session LABEL] [--source-ip IP] \
                         [--since T] [--until T] [--split-gap-minutes N]
tokiwa eval info FILE.jsonl
```

| オプション | 説明 |
|---|---|
| `--llm` | `mock`（無料・オフライン、既定）または `live`（設定済みのプロバイダ。**費用が発生**） |
| `--budget-usd` | `--llm live` のときに **必須**。この実行の費用の上限 |
| `--out` | 出力先（既定 `eval/runs/<UTC 時刻>`） |
| `--compare` / `--fail-on-regression` | 前回との比較 / 悪化していたら終了コード 1。2 つの実行の条件（データセットの sha256・LLM プロバイダ・有効な検知器・読み込んだ Sigma ルール数・しきい値・バッチ設定）が違うときは「比較不能」として終了コード 3 |
| `--allow-mismatch` | 条件が違っても比較して悪化の判定を出す（差分は警告として表示） |
| `--speed` | 0 = 最速、1 = 実時間、10 = 10 倍速 |
| `--enable-detector` / `--disable-detector` | 検知器を強制的に有効 / 無効にする |
| `--keep-work` | 評価用の一時 DB を残す |
| `import-artex --since` / `--until` | ARTEX の記録をこの時間帯だけ取り込む（unix 秒または ISO 8601。オフセットなしは UTC） |
| `import-artex --split-gap-minutes` | ホストごとに、記録が N 分以上途切れたところで別セッション（別の送信元 IP）にする。既定は分割しない |
