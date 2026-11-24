# デプロイ・運用ガイド

> 対象: `deploy/Dockerfile`（オールインワンイメージ）と `deploy/compose.yaml`（本番寄りスタック）。
> ラボ（被監視アプリ + シミュレータ）は `lab/compose.yaml` / `lab/README.md` を参照。
> ⚠️ v0.1 は開発中。自分が管理する環境でのみ使うこと。

## 1. 構成

| 要素 | 内容 |
|---|---|
| イメージ | 1 つのイメージで全ロールを実行。既定は `tokiwa serve`（API + Web UI + バックグラウンドジョブ、:8788） |
| ビルド | ① node 22 で `frontend/dist` をビルド → ② python 3.12-slim + uv で `uv sync --frozen --no-dev --no-editable`（`postgres` extra = asyncpg 同梱）→ ③ ランタイムに venv と UI だけコピー |
| 実行ユーザー | uid/gid `10001`（`tokiwa`）。root では動かない |
| 状態 | すべて `/data`（ボリューム）: SQLite `tokiwa.db`（+ `-wal`/`-shm`）、JWT 署名鍵 `secret.key`、デセプションの鍵リング `deception.key` |
| 設定 | 環境変数 `TOKIWA_*`（ネストは `__`、`backend/src/tokiwa/config.py`）。任意で `/etc/tokiwa/tokiwa.yaml` |
| ヘルスチェック | `GET /api/v1/health`（`tokiwa-healthcheck`、30 秒間隔・起動中は 2 秒間隔） |
| Sigma ルール | ビルド時に `rules/` があれば `/app/rules` にコピー（`TOKIWA_DETECTION__SIGMA_RULE_DIRS=["/app/rules/sigma"]`） |

イメージに焼き込まれている既定値:

```
TOKIWA_ENV=prod
TOKIWA_CONFIG=/etc/tokiwa/tokiwa.yaml          # イメージには中身が空（コメントのみ）のファイルを同梱。自分の YAML をマウントして置き換える
TOKIWA_SERVER__STATIC_DIR=/app/frontend/dist
TOKIWA_SERVER__DATA_DIR=/data
TOKIWA_DATABASE__URL=sqlite+aiosqlite:////data/tokiwa.db
TOKIWA_DETECTION__SIGMA_RULE_DIRS=["/app/rules/sigma"]
```

## 2. 要件

- Docker Engine **25 以上**（BuildKit、`HEALTHCHECK --start-interval`）、Docker Compose **v2.24 以上**
  （`env_file.required` / `depends_on.required`）。
- x86_64 / arm64（依存はすべて両アーキのホイールあり。arm64 ビルドは未検証）。
- メモリ目安: 512 MB〜（ラボ規模）。

## 3. インストール（Compose）

```bash
git clone <this repo> tokiwa && cd tokiwa
cp .env.example .env            # 必要な行だけコメントを外す（空値で有効化しないこと）
make up                         # = docker compose -f deploy/compose.yaml --env-file .env up -d --build --wait
```

1. `http://localhost:8788/setup` で最初の管理者を作成（または CLI:
   `docker compose -f deploy/compose.yaml exec tokiwa tokiwa user create admin --role admin`）。
2. LLM を使う場合は `.env` に `ANTHROPIC_API_KEY=...`（未設定なら mock で動作し、ルールベースにフォールバック）。
3. デモデータ（任意）: `make seed SEED_URL=http://127.0.0.1:8788`
   — `TOKIWA_INGEST_TOKEN` 未設定なら backend の CLI でトークンを作るので、コンテナに対しては
   先に `docker compose -f deploy/compose.yaml exec tokiwa tokiwa token create seed-demo --scope ingest`
   で作ったトークンを `TOKIWA_INGEST_TOKEN=tkw_... make seed` で渡す。送信先は localhost のみ許可。

既定でポートは `127.0.0.1:8788` にだけ公開される。LAN に直接出す場合は `TOKIWA_BIND=0.0.0.0`
（TLS なしで公開しないこと。§8 のリバースプロキシ推奨）。

`docker` 単体で動かす場合:

```bash
make docker                                   # docker build -f deploy/Dockerfile -t tokiwa:local .
docker run -d --name tokiwa --init -p 127.0.0.1:8788:8788 -v tokiwa-data:/data tokiwa:local
```

### コンテナのハードニング（compose 既定）

`read_only: true`（書き込みは `/data` と tmpfs `/tmp` のみ）、`cap_drop: [ALL]`、`no-new-privileges`、
`pids_limit: 512`（スレッドも数える。サーバー・Gate の通常の使用量より十分大きい）、`init: true`、ログローテーション（json-file 10 MB × 5）。

- postgres（監査 #109）: `cap_drop: [ALL]` のうえで公式 entrypoint が root で行う処理に要るものだけ `cap_add`（CHOWN・DAC_OVERRIDE・
  FOWNER = データ / ソケットのディレクトリ作成・chmod・chown、SETUID・SETGID = gosu で postgres ユーザーへ切替）と `no-new-privileges`。
  一覧は `docker-entrypoint.sh`（docker-library/postgres の 18/trixie）を読んで決めた。TODO(verify): この構成での起動は未確認
  （CI のスモークテストは postgres プロファイルを動かさない）。起動しない場合は `cap_drop` / `cap_add` を外して報告してほしい。
  `read_only` はソケット用の tmpfs などイメージの書き込み先を確かめていないので付けていない。
- メモリ上限（`mem_limit`）は付けていない: 低すぎると攻撃を受けている最中に SIEM 自身が OOM で落ち、検知が黙って止まる。
  ホストの規模に合わせて運用側で設定する（目安は §2 のメモリ）。
- ラボ（`lab/compose.yaml`、監査 #105）も同じ: TOKIWA の各サービスと victim は `read_only`・tmpfs `/tmp`・`cap_drop: [ALL]`・
  `no-new-privileges`・`pids_limit`。nginx は `no-new-privileges` と `pids_limit` のみ（公式イメージの書き込み先・必要な権限を未確認）。

## 4. センサー・他ロールを同じイメージで動かす

エントリポイントは第 1 引数が tokiwa のサブコマンド（`serve gate agent sim eval intel user token version`）なら
`tokiwa` を前置する。`tokiwa ...` / `sh` / `python ...` はそのまま実行。

```bash
# API トークン（一度だけ表示される）。Gate 用は gate スコープを明示（既定は ingest のみ）
docker compose -f deploy/compose.yaml exec tokiwa tokiwa token create gate-1 --scope ingest --scope gate

# Gate（リバースプロキシ型センサー）: compose の gate プロファイル
#   .env に TOKIWA_GATE__INGEST_TOKEN / TOKIWA_GATE__UPSTREAM を設定して
docker compose -f deploy/compose.yaml --env-file .env --profile gate up -d

# 単体 docker run の例。トークンはファイルで渡す（`token create` の出力をエディタで貼り付け、コンテナの uid 10001 が読めるように）。
# ディレクトリごとマウントするのは、ローテーションでファイルを置き換えても Gate が新しいトークンを読めるようにするため
sudo install -d -m 700 /etc/tokiwa/gate && sudoedit /etc/tokiwa/gate/token
sudo chown 10001:10001 /etc/tokiwa/gate/token && sudo chmod 400 /etc/tokiwa/gate/token
docker run -d --name tokiwa-gate -p 8080:8080 \
  -e TOKIWA_HEALTHCHECK_URL=http://127.0.0.1:8080/__tokiwa/health \
  -v /etc/tokiwa/gate:/run/secrets/tokiwa-gate:ro \
  tokiwa:local gate run --upstream http://app:3000 --server http://tokiwa:8788 \
  --token-file /run/secrets/tokiwa-gate/token

# ホストセンサー（ホストのポート/プロセスを見るには host の PID/ネットワーク名前空間が必要）。
# agent に --token-file は無いので env ファイル（中身は TOKIWA_AGENT__INGEST_TOKEN=tkw_... の 1 行）で渡す。
# --env-file は docker コマンド側が読むので、docker を実行するユーザーだけが読める権限 600 にする
sudo install -m 600 -o "$USER" /dev/null /etc/tokiwa/agent.env && "${EDITOR:-vi}" /etc/tokiwa/agent.env
docker run -d --name tokiwa-agent --pid host --network host -e TOKIWA_HEALTHCHECK_URL=none \
  --env-file /etc/tokiwa/agent.env -v /var/log/nginx:/var/log/nginx:ro tokiwa:local agent run

# ラボ用シミュレータ（送信先はラボ内に制限される）
docker run --rm --network <lab-net> -e TOKIWA_HEALTHCHECK_URL=none tokiwa:local sim run --profile ai_agent --target http://gate:8080
```

- HEALTHCHECK は既定で `:8788/api/v1/health` を見る。HTTP を持たないロールは `TOKIWA_HEALTHCHECK_URL=none`、
  Gate は上記の URL に向ける（compose の gate プロファイルは設定済み）。
- **API トークンをコマンドライン引数（`--token tkw_...`）で渡さない**（監査 #143）。引数は同じホストの全ユーザーに `ps` /
  `/proc/<pid>/cmdline` で、Docker の管理者には `docker inspect`（`Args`）で見える。Gate と Agent は待ち受け・常駐プロセスなので、
  TOKIWA 自身のホストセンサーが待ち受けプロセスのコマンドラインを集めると、`ingest` + `gate` スコープのトークンがイベント・UI・
  コパイロット（LLM）に流れ得る。`--token-file`（Gate のみ。変更時に読み直す）か環境変数 `TOKIWA_GATE__INGEST_TOKEN` /
  `TOKIWA_AGENT__INGEST_TOKEN`（compose は `.env`、単体は `--env-file`）を使う。環境変数も `docker inspect` には見えるが、
  そこが見える人は Docker の管理者（実質 root）に限られる。`tokiwa gate run --token` は警告を出す。
- `gate` / `agent` / `sim` サブコマンドは各モジュール（gate / sensors / lab-eval）が提供する。オプション名・
  Gate の `/__tokiwa/health` はタスク仕様に基づく記述。TODO(verify): 各モジュールのマージ後に実機確認。
- agent は他ユーザーのプロセス情報を読むのに root 相当の権限が要る場合がある（イメージは非 root）。
  本番ではホストに直接 `uv tool install` / venv で入れる方が素直。

## 5. 設定

優先順位: 環境変数 `TOKIWA_*` > `tokiwa.yaml`（`TOKIWA_CONFIG`）> 既定値。主な項目は `.env.example` を参照。

- **空文字で有効化しない**: `TOKIWA_SERVER__SECRET_KEY=`（空）は空文字の JWT 鍵として使われてしまう。
  未設定なら初回起動時に `/data/secret.key` が生成・永続化される。
- `tokiwa.yaml` を使う場合は compose の `volumes:` にある `tokiwa.yaml` のマウント（long syntax・`create_host_path: false`）の
  コメントを外す（`deploy/` からの相対パス）。short syntax（`./tokiwa.yaml:/etc/tokiwa/tokiwa.yaml:ro`）は、ホスト側のファイルが
  無いと Docker がディレクトリを作ってしまう。秘密は YAML ではなく環境変数で渡す方がよい。
- **設定ミスは警告される**（監査 #161）: YAML の未知のキー、設定項目に当たらない `TOKIWA_*` 環境変数（`TOKIWA_LLM__PROVIDR`、
  `TOKIWA_LLM_PROVIDER` のような `_` 1 つ）、`TOKIWA_CONFIG` のファイルが無い・ディレクトリ — を起動時に `config:` で始まる
  WARNING で出す（名前とパスのみ。値は出さない）。`TOKIWA_STRICT_CONFIG=1` で起動拒否にできる（既定は警告のみ）。
  `TOKIWA_CONFIG=`（空）は「YAML を読まない」の明示。起動ログには読み込んだ設定ファイル・`data_dir`・DB（パスワード伏字）・
  LLM プロバイダが INFO で 1 行出る。
- 効いている値と出所は `docker compose -f deploy/compose.yaml exec tokiwa tokiwa config show`（`--changed` で既定から変わった項目、
  `--db` で画面からの LLM 上書き、`--check` で問題があれば終了コード 1）。秘密は `<set>` と表示する。
- `.env` は compose の変数展開（`--env-file .env`）と、**tokiwa サーバーのコンテナ**への環境変数（`env_file: ../.env`）に使う。
  `.env` 内で `${POSTGRES_PASSWORD}` のような参照が使える。**Gate のコンテナには `.env` 全体を渡さない**（監査 #71。攻撃トラフィックを
  直接受けるので、JWT 署名鍵・LLM / インテルの API キー・DB パスワードを持たせない）。Gate に渡るのは `deploy/compose.yaml` の
  `gate.environment` に列挙した変数（`TOKIWA_GATE__*`、`TOKIWA_LLM__REDACTION__*`、`TOKIWA_DECEPTION__CANARY_HEADER`、
  `TOKIWA_ENV`、`TOKIWA_LOG_LEVEL`）のうち `.env` で設定したものだけ。

### 秘密をファイルで渡す（任意。監査 #108 / #110）

環境変数は `docker inspect`・`docker compose config`・`/proc/<pid>/environ` で見える。`TOKIWA_<設定>_FILE=<パス>` で
文字列の設定（API キー・トークン・DB URL など）をファイルから読める（例 `TOKIWA_LLM__ANTHROPIC_API_KEY_FILE`、
`TOKIWA_DATABASE__URL_FILE`、`TOKIWA_SERVER__SECRET_KEY_FILE`。`ANTHROPIC_API_KEY_FILE` も可）。同じ設定を環境変数と `_FILE` の
両方で指定すると起動を拒否する（環境変数が空なら `_FILE` が使われる）。末尾の改行は除く。数値・リストの設定は対象外（WARNING）。
`gate.token_file` のように名前が `_file` で終わる本来の設定はそのまま設定として扱う。

Compose secrets と組み合わせる例が `deploy/compose.secrets.example.yaml`（LLM キー・DB URL・postgres のパスワード・Gate のトークン）:

```bash
cp deploy/compose.secrets.example.yaml deploy/compose.secrets.yaml      # 使うブロックだけ残す
install -d -m 700 secrets && (umask 077 && "${EDITOR:-vi}" secrets/anthropic_api_key)
sudo chown 10001:10001 secrets/anthropic_api_key                         # コンテナの uid が読めるように
docker compose -f deploy/compose.yaml -f deploy/compose.secrets.yaml --env-file .env up -d
```

- Compose はファイルの secret を `/run/secrets/<名前>` に読み取り専用で bind mount し、所有者・モードを変えられない
  （Compose 仕様: file ソースでは `uid` / `gid` / `mode` は未実装）。ホスト側でコンテナのユーザーが読めるようにする
  （TOKIWA は uid 10001。postgres の公式イメージは root で起動して `POSTGRES_PASSWORD_FILE` を読み、`postgres`（uid 999）に切り替える）。
- `.env` から同じ値（`ANTHROPIC_API_KEY`・`TOKIWA_DATABASE__URL`・`POSTGRES_PASSWORD`・`TOKIWA_GATE__INGEST_TOKEN`）を消す。
  postgres サービスの `POSTGRES_PASSWORD` は空になり、公式イメージは空の変数を未設定とみなして `POSTGRES_PASSWORD_FILE` を使う。
- アプリ用の DB ロールを PostgreSQL の管理ユーザー（`POSTGRES_USER`）と分けるのが望ましい（未対応。手順は運用側で）。

## 6. アップグレード

```bash
git pull
make up                    # 再ビルドして入れ替え（/data ボリュームは保持）
docker image prune -f      # 古いイメージの掃除（任意）
```

- ⚠️ **スキーマ移行は未整備**（Alembic は v1.0 前に導入予定 — ADR-0002）。起動時の `create_all` は
  「無いテーブルを作る」だけで、既存テーブルの列追加・変更は行わない。アップグレード前に必ず §7 のバックアップを取り、
  リリースノート/HANDOFF にスキーマ変更がある場合は手動移行が必要。
- ロールバック: 旧コミットでビルドし直し、必要ならバックアップから戻す。

## 7. バックアップとリストア

`secret.key` を失うと発行済みのログインセッション（JWT）が無効になる（API トークンは DB 内のハッシュなので影響なし）。
`deception.key`（デセプションの鍵リング、監査 #68）を失うと、デコイ内の派生値（偽 AWS シークレット・DB パスワード・
デコイ内のカナリア値）が変わり、**既に攻撃者の手に渡った値が検知されなくなる**（警告は出ない）。どちらも DB と一緒に保存すること。

**鍵のローテーション**:
- `secret.key`（JWT）は単独で入れ替えてよい（全員ログアウトされる）。#68 以降、デセプションの派生値は `deception.key` に
  依存し、JWT 鍵には依存しない（初回起動時に、それまで JWT 鍵から導出していた鍵をそのまま `deception.key` に書き出すので、
  既存のデコイの値は変わらない）。**#68 より前の版で JWT 鍵を入れ替えると派生値が変わる** — 版を上げてから入れ替えること。
- `deception.key` は 1 行 1 鍵（16 進）で、**先頭が現用**（新しい値の描画に使う）、**全行が照合対象**。入れ替えるときは
  新しい鍵（`python -c "import secrets; print(secrets.token_hex(32))"`）を先頭に足し、古い行は残す。古い鍵をいつ消すか
  （配布済みの値をいつまで検知したいか）は運用判断。

### SQLite（既定）

WAL モードなので稼働中にファイルを直接コピーしない。SQLite のオンラインバックアップ API を使う:

```bash
C="docker compose -f deploy/compose.yaml"
$C exec -T tokiwa python -c "import sqlite3; s=sqlite3.connect('/data/tokiwa.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d); d.close(); s.close()"
mkdir -p backups
$C cp tokiwa:/data/backup.db  "backups/tokiwa-$(date +%F).db"
$C cp tokiwa:/data/secret.key "backups/secret-$(date +%F).key"
$C cp tokiwa:/data/deception.key "backups/deception-$(date +%F).key"
$C exec -T tokiwa rm /data/backup.db
```

リストア（停止中に置き換える）:

```bash
$C stop tokiwa
$C cp backups/tokiwa-YYYY-MM-DD.db  tokiwa:/data/tokiwa.db
$C cp backups/secret-YYYY-MM-DD.key tokiwa:/data/secret.key
$C cp backups/deception-YYYY-MM-DD.key tokiwa:/data/deception.key
$C run --rm --entrypoint sh tokiwa -c 'rm -f /data/tokiwa.db-wal /data/tokiwa.db-shm'
$C start tokiwa
```

（`docker compose cp` でコピーしたファイルの所有者が root になる場合は
`$C run --rm --user 0 --entrypoint chown tokiwa -R 10001:10001 /data`。）

### PostgreSQL

```bash
C="docker compose -f deploy/compose.yaml --env-file .env"
$C exec -T postgres pg_dump -U tokiwa -Fc tokiwa > "backups/tokiwa-$(date +%F).dump"
# リストア
$C stop tokiwa
$C exec -T postgres pg_restore -U tokiwa -d tokiwa --clean --if-exists < backups/tokiwa-YYYY-MM-DD.dump
$C start tokiwa
```

`secret.key` と `deception.key` は PostgreSQL 構成でも `/data`（tokiwa-data ボリューム）にあるので別途保存する。

## 8. PostgreSQL への切替

SQLite はラボ〜小規模向け。イベント量が多い・複数プロセスから書く場合は PostgreSQL を使う。
イメージには asyncpg（`postgres` extra）が入っている。

```bash
# .env
COMPOSE_PROFILES=postgres
POSTGRES_USER=tokiwa
POSTGRES_PASSWORD=<openssl rand -hex 24 の出力（URL に入るので記号なしが無難）>
TOKIWA_DATABASE__URL=postgresql+asyncpg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/tokiwa
```

`make up` で postgres（18.x）が起動し、healthy になってから tokiwa が起動、テーブルは起動時に自動作成される。
PostgreSQL はホストに公開しない（compose ネットワーク内のみ）。外部の PostgreSQL を使う場合はプロファイルを有効にせず
`TOKIWA_DATABASE__URL` だけ設定する。

- SQLite → PostgreSQL の **データ移行ツールは無い**（新規 DB から開始）。TODO: Alembic 導入時に移行手順を整備。
- 検証済み: PostgreSQL 18.6 で起動・テーブル作成（23 テーブル）・ingest。全モジュールのクエリが PostgreSQL で
  動くことは各モジュールのマージ後に要確認（TODO(verify)）。

## 9. リバースプロキシ配下での運用

- TOKIWA は **ドメイン（またはサブドメイン）のルート**で公開する（UI が `/assets` と `/api` を絶対パスで参照するため、
  `/tokiwa/` のようなサブパス配信は未対応）。
- `TOKIWA_SERVER__BASE_URL=https://tokiwa.example.internal` を設定（通知リンク等）。UI と API が同一オリジンなら
  CORS 設定は不要。
- SSE（`/api/v1/stream`）はバッファリングを切り、タイムアウトを長くする。
- SSE の URL には 1 回限り・60 秒の券（`?ticket=`）が載る（監査 #100。以前は 12 時間有効な JWT が `?access_token=` で載り、
  プロキシのアクセスログに残った）。券は使用済みなら無価値だが、念のため stream の location はアクセスログを切る（下の nginx 例）か
  クエリを記録しない書式にする。旧形式 `?access_token=` を使うクライアントが残っていると、TOKIWA が WARNING を出す。
- プロキシが別ホスト/別コンテナの場合、uvicorn に `X-Forwarded-*` を信頼させる: `FORWARDED_ALLOW_IPS=<proxy の IP/CIDR>`。
- TOKIWA 自体は `127.0.0.1:8788`（compose 既定）に置き、TLS はプロキシで終端する。
- セキュリティヘッダ（CSP・`X-Frame-Options: DENY`・`X-Content-Type-Options: nosniff`・`Referrer-Policy: no-referrer`、
  index.html の `Cache-Control: no-store`）は **TOKIWA 自身が付ける**（`server.security_headers`、既定 true）。プロキシで
  CSP を重ねると両方が適用される（厳しい方が勝つ）ので、通常は足さない。HSTS は TLS を終端するプロキシで付ける。
- ボディ上限はアプリ側にもある（`server.max_body_bytes` 1 MiB / ingest は `server.max_ingest_body_bytes` 32 MiB、超過は 413）。
  プロキシの上限はこれ以上にする（小さいと ingest バッチがプロキシで 413 になり、センサーがそのバッチを破棄する）。
- 本番では `TOKIWA_SERVER__EXPOSE_DOCS=false`（`/api/docs`・`/api/openapi.json` を無効化）を推奨。

nginx:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name tokiwa.example.internal;
    # ssl_certificate / ssl_certificate_key ...
    client_max_body_size 32m;                 # ingest バッチ用（server.max_ingest_body_bytes と揃える）
    add_header Strict-Transport-Security "max-age=31536000" always;   # CSP 等は TOKIWA が付ける

    location /api/v1/stream {
        access_log off;                       # URL に単回使用の券（?ticket=）が載る。残すなら $uri だけの log_format に
        proxy_pass http://127.0.0.1:8788;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1h;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location / {
        proxy_pass http://127.0.0.1:8788;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Caddy:

```caddyfile
tokiwa.example.internal {
    header Strict-Transport-Security "max-age=31536000"   # CSP 等は TOKIWA が付ける
    request_body {
        max_size 32MB            # server.max_ingest_body_bytes と揃える
    }
    reverse_proxy 127.0.0.1:8788 {
        flush_interval -1        # SSE をそのまま流す
    }
}
```

認証の追加（SSO / mTLS / IP 制限）はプロキシ側で重ねてよい。センサー（Gate/Agent）からの
`/api/v1/ingest/events` と `/api/v1/gate/policy` は API トークン認証なので、プロキシで SSO を掛ける場合は
これらのパスを除外するか、センサーを内部ネットワーク経由で直接 :8788 に向ける。

## 10. ビルドのカスタマイズ

| build-arg | 既定 | 用途 |
|---|---|---|
| `NODE_IMAGE` | `node:22.23.4-trixie-slim@sha256:…` | フロントのビルド用 |
| `PYTHON_IMAGE` | `python:3.12.15-slim-trixie@sha256:…` | backend ビルド + ランタイム |
| `UV_IMAGE` | `ghcr.io/astral-sh/uv:0.11.32@sha256:…` | uv バイナリ |
| `TOKIWA_EXTRAS` | `postgres` | backend の optional extras（空にすると SQLite 専用、約 4 MB 小さい） |
| `TOKIWA_UID` / `TOKIWA_GID` | `10001` | 実行ユーザー |

- ベースイメージはタグと digest の両方で固定している（監査 #104。digest が優先されるので、同じタグが差し替えられても
  ビルド内容は変わらない）。digest はマルチアーキのインデックス（manifest list）のもの。postgres（`deploy/compose.yaml`）・
  ラボの nginx / victim・CI のツールイメージ（actionlint / hadolint / shellcheck）も同様。
- レジストリミラー: `--build-arg PYTHON_IMAGE=mirror.gcr.io/library/python:3.12.15-slim-trixie` など（digest を外すか、
  ミラーから取得して確かめた digest を付ける）。
- TLS インスペクションのあるプロキシ配下: 自社 CA を信頼させたベースイメージを用意し（`update-ca-certificates` +
  `UV_SYSTEM_CERTS=1`、node は `NODE_EXTRA_CA_CERTS`）、`NODE_IMAGE` / `PYTHON_IMAGE` で差し替える。
- ビルドコンテキストはリポジトリ直下。除外は `deploy/Dockerfile.dockerignore`（`.env`・`data/`・`node_modules`・`.venv` 等）。
- ベースイメージ・uv の更新: タグと digest を一緒に上げて `make docker docker-smoke`。digest は `docker pull <イメージ>:<タグ>`
  の出力の `Digest: sha256:…`（インデックスの digest）を使う。uv は `backend/uv.lock` を作った版と揃える
  （CI の `astral-sh/setup-uv` の `version` も同じ値に）。Dependabot（`.github/dependabot.yml`）が docker / docker-compose /
  github-actions / uv / npm の更新 PR を週次で出す。TODO(verify): Dockerfile の `ARG` 既定値にあるイメージを Dependabot が
  更新するか（しなければ手動で上げる）。

## 11. 開発補助・CI

| コマンド | 内容 |
|---|---|
| `make dev` / `scripts/dev.sh` | API（:8788, --reload）と UI（:5173）を同時起動。Ctrl-C で両方停止 |
| `make test` / `make lint` / `make build` | pytest + vitest / ruff + tsc + biome / UI ビルド |
| `make ci` | CI の backend・frontend ジョブ相当 + `seed_demo.py --validate` |
| `make docker` / `make docker-smoke` | イメージビルド / スモークテスト（`scripts/docker-smoke.sh`） |
| `make up` / `make down` / `make logs` | `deploy/compose.yaml` |
| `make seed` | デモイベント投入（`scripts/seed_demo.py`、localhost のみ） |
| `uvx pre-commit install` | ruff / ruff-format / biome（`frontend/node_modules` の biome）などのフック |

CI（`.github/workflows/ci.yml`）: すべてのブランチ push と PR で backend（uv sync --locked → ruff → pytest →
seed 検証、mypy は情報表示のみ）、frontend（npm ci → typecheck → lint → build → vitest）、docker（buildx + GHA
キャッシュでビルド → スモークテスト）、infra-lint（actionlint / hadolint / shellcheck）。LLM は mock 固定で秘密は不要。
Actions はコミット SHA で固定（更新時はタグと SHA を併記）。
依存の脆弱性（監査 #104）は `.github/workflows/dependency-audit.yml`: `backend/uv.lock` の実行時依存（全 extras）を
`pip-audit --strict`、`frontend/package-lock.json` の本番依存を `npm audit --omit=dev --audit-level=high` で検査し、既知の脆弱性が
あれば失敗する（開発・テスト専用の依存は警告の注釈だけ）。ロックファイルの変更時と毎週月曜に実行。手元では:
`cd backend && uv export --frozen --no-dev --all-extras --no-emit-project -o /tmp/req.txt && uvx pip-audit --strict --disable-pip --require-hashes -r /tmp/req.txt`、
`cd frontend && npm audit --omit=dev --audit-level=high`（どちらも PyPI / npm レジストリへの通信が要る）。

## 12. トラブルシューティング

| 症状 | 対処 |
|---|---|
| `PermissionError: /data/...` / 起動時に「/data is not writable」 | bind mount のホスト側ディレクトリを `sudo chown -R 10001:10001 <dir>`。名前付きボリュームなら自動で正しい所有者になる |
| UI が 404 / API だけ見える | `TOKIWA_SERVER__STATIC_DIR` を上書きしていないか確認（イメージ既定 `/app/frontend/dist`） |
| `unhealthy` | `docker inspect --format '{{json .State.Health}}' <container>`。gate/agent/sim では `TOKIWA_HEALTHCHECK_URL` を設定 |
| tokiwa が postgres を待ち続ける | `POSTGRES_PASSWORD` 未設定だと postgres が起動しない（`docker compose logs postgres`） |
| ログイン後すぐ 401 | `secret.key`/`TOKIWA_SERVER__SECRET_KEY` が変わった。バックアップから戻すか再ログイン |
| SSE が途切れる/遅れる | リバースプロキシのバッファリング・タイムアウト（§9） |
| 設定が効かない（既定値のまま） | 起動ログの `config:` WARNING と `tokiwa config show --changed`（§5） |
