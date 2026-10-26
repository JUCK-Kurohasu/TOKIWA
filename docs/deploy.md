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
| 状態 | すべて `/data`（ボリューム）: SQLite `tokiwa.db`（+ `-wal`/`-shm`）、JWT 署名鍵 `secret.key` |
| 設定 | 環境変数 `TOKIWA_*`（ネストは `__`、`backend/src/tokiwa/config.py`）。任意で `/etc/tokiwa/tokiwa.yaml` |
| ヘルスチェック | `GET /api/v1/health`（`tokiwa-healthcheck`、30 秒間隔・起動中は 2 秒間隔） |
| Sigma ルール | ビルド時に `rules/` があれば `/app/rules` にコピー（`TOKIWA_DETECTION__SIGMA_RULE_DIRS=["/app/rules/sigma"]`） |

イメージに焼き込まれている既定値:

```
TOKIWA_ENV=prod
TOKIWA_CONFIG=/etc/tokiwa/tokiwa.yaml          # 無ければ無視
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
`init: true`、ログローテーション（json-file 10 MB × 5）。

## 4. センサー・他ロールを同じイメージで動かす

エントリポイントは第 1 引数が tokiwa のサブコマンド（`serve gate agent sim eval intel user token version`）なら
`tokiwa` を前置する。`tokiwa ...` / `sh` / `python ...` はそのまま実行。

```bash
# API トークン（一度だけ表示される）
docker compose -f deploy/compose.yaml exec tokiwa tokiwa token create gate-1

# Gate（リバースプロキシ型センサー）: compose の gate プロファイル
#   .env に TOKIWA_GATE__INGEST_TOKEN / TOKIWA_GATE__UPSTREAM を設定して
docker compose -f deploy/compose.yaml --env-file .env --profile gate up -d

# 単体 docker run の例
docker run -d --name tokiwa-gate -p 8080:8080 \
  -e TOKIWA_HEALTHCHECK_URL=http://127.0.0.1:8080/__tokiwa/health \
  tokiwa:local gate run --upstream http://app:3000 --server http://tokiwa:8788 --token tkw_...

# ホストセンサー（ホストのポート/プロセスを見るには host の PID/ネットワーク名前空間が必要）
docker run -d --name tokiwa-agent --pid host --network host -e TOKIWA_HEALTHCHECK_URL=none \
  -v /var/log/nginx:/var/log/nginx:ro tokiwa:local agent run --token tkw_...

# ラボ用シミュレータ（送信先はラボ内に制限される）
docker run --rm --network <lab-net> -e TOKIWA_HEALTHCHECK_URL=none tokiwa:local sim run --profile ai_agent --target http://gate:8080
```

- HEALTHCHECK は既定で `:8788/api/v1/health` を見る。HTTP を持たないロールは `TOKIWA_HEALTHCHECK_URL=none`、
  Gate は上記の URL に向ける（compose の gate プロファイルは設定済み）。
- `gate` / `agent` / `sim` サブコマンドは各モジュール（gate / sensors / lab-eval）が提供する。オプション名・
  Gate の `/__tokiwa/health` はタスク仕様に基づく記述。TODO(verify): 各モジュールのマージ後に実機確認。
- agent は他ユーザーのプロセス情報を読むのに root 相当の権限が要る場合がある（イメージは非 root）。
  本番ではホストに直接 `uv tool install` / venv で入れる方が素直。

## 5. 設定

優先順位: 環境変数 `TOKIWA_*` > `tokiwa.yaml`（`TOKIWA_CONFIG`）> 既定値。主な項目は `.env.example` を参照。

- **空文字で有効化しない**: `TOKIWA_SERVER__SECRET_KEY=`（空）は空文字の JWT 鍵として使われてしまう。
  未設定なら初回起動時に `/data/secret.key` が生成・永続化される。
- `tokiwa.yaml` を使う場合は compose の `./tokiwa.yaml:/etc/tokiwa/tokiwa.yaml:ro` のコメントを外す
  （`deploy/` からの相対パス）。秘密は YAML ではなく環境変数で渡す方がよい。
- `.env` は compose の変数展開（`--env-file .env`）とコンテナへの環境変数（`env_file: ../.env`）の両方に使う。
  `.env` 内で `${POSTGRES_PASSWORD}` のような参照が使える。

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
DB と一緒に保存すること。

### SQLite（既定）

WAL モードなので稼働中にファイルを直接コピーしない。SQLite のオンラインバックアップ API を使う:

```bash
C="docker compose -f deploy/compose.yaml"
$C exec -T tokiwa python -c "import sqlite3; s=sqlite3.connect('/data/tokiwa.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d); d.close(); s.close()"
mkdir -p backups
$C cp tokiwa:/data/backup.db  "backups/tokiwa-$(date +%F).db"
$C cp tokiwa:/data/secret.key "backups/secret-$(date +%F).key"
$C exec -T tokiwa rm /data/backup.db
```

リストア（停止中に置き換える）:

```bash
$C stop tokiwa
$C cp backups/tokiwa-YYYY-MM-DD.db  tokiwa:/data/tokiwa.db
$C cp backups/secret-YYYY-MM-DD.key tokiwa:/data/secret.key
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

`secret.key` は PostgreSQL 構成でも `/data`（tokiwa-data ボリューム）にあるので別途保存する。

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
- プロキシが別ホスト/別コンテナの場合、uvicorn に `X-Forwarded-*` を信頼させる: `FORWARDED_ALLOW_IPS=<proxy の IP/CIDR>`。
- TOKIWA 自体は `127.0.0.1:8788`（compose 既定）に置き、TLS はプロキシで終端する。

nginx:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name tokiwa.example.internal;
    # ssl_certificate / ssl_certificate_key ...
    client_max_body_size 20m;                 # ingest バッチ（最大 5000 イベント）用

    location /api/v1/stream {
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
| `NODE_IMAGE` | `node:22.23.4-trixie-slim` | フロントのビルド用 |
| `PYTHON_IMAGE` | `python:3.12.15-slim-trixie` | backend ビルド + ランタイム |
| `UV_IMAGE` | `ghcr.io/astral-sh/uv:0.11.32` | uv バイナリ |
| `TOKIWA_EXTRAS` | `postgres` | backend の optional extras（空にすると SQLite 専用、約 4 MB 小さい） |
| `TOKIWA_UID` / `TOKIWA_GID` | `10001` | 実行ユーザー |

- レジストリミラー: `--build-arg PYTHON_IMAGE=mirror.gcr.io/library/python:3.12.15-slim-trixie` など。
- TLS インスペクションのあるプロキシ配下: 自社 CA を信頼させたベースイメージを用意し（`update-ca-certificates` +
  `UV_SYSTEM_CERTS=1`、node は `NODE_EXTRA_CA_CERTS`）、`NODE_IMAGE` / `PYTHON_IMAGE` で差し替える。
- ビルドコンテキストはリポジトリ直下。除外は `deploy/Dockerfile.dockerignore`（`.env`・`data/`・`node_modules`・`.venv` 等）。
- ベースイメージ・uv の更新: タグを上げて `make docker docker-smoke`。uv は `backend/uv.lock` を作った版と揃える
  （CI の `astral-sh/setup-uv` の `version` も同じ値に）。

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

## 12. トラブルシューティング

| 症状 | 対処 |
|---|---|
| `PermissionError: /data/...` / 起動時に「/data is not writable」 | bind mount のホスト側ディレクトリを `sudo chown -R 10001:10001 <dir>`。名前付きボリュームなら自動で正しい所有者になる |
| UI が 404 / API だけ見える | `TOKIWA_SERVER__STATIC_DIR` を上書きしていないか確認（イメージ既定 `/app/frontend/dist`） |
| `unhealthy` | `docker inspect --format '{{json .State.Health}}' <container>`。gate/agent/sim では `TOKIWA_HEALTHCHECK_URL` を設定 |
| tokiwa が postgres を待ち続ける | `POSTGRES_PASSWORD` 未設定だと postgres が起動しない（`docker compose logs postgres`） |
| ログイン後すぐ 401 | `secret.key`/`TOKIWA_SERVER__SECRET_KEY` が変わった。バックアップから戻すか再ログイン |
| SSE が途切れる/遅れる | リバースプロキシのバッファリング・タイムアウト（§9） |
