> 🌐 **日本語** · [English](Installation-en) · [中文](Installation-zh) · [Español](Installation-es)

# インストールと運用（Docker Compose）

常用・本番寄りの構成です。1 つの Docker イメージに、サーバー（API + Web UI + バックグラウンドジョブ）と
Gate・Agent・シミュレータの全ロールが入っています。手元で試すだけなら [クイックスタート](Quick-Start) の方が簡単です。

## 要件

- Docker Engine **25 以上**、Docker Compose **v2.24 以上**
- x86_64 または arm64（arm64 でのビルドは未検証）
- メモリ: ラボ規模で 512 MB 程度から

## インストール

```bash
git clone https://github.com/JUCK-Kurohasu/TOKIWA.git tokiwa && cd tokiwa
cp .env.example .env     # 必要な行だけコメントを外す
make up                  # = docker compose -f deploy/compose.yaml --env-file .env up -d --build --wait
```

1. <http://localhost:8788/setup> で最初の管理者を作成します（CLI の場合:
   `docker compose -f deploy/compose.yaml exec tokiwa tokiwa user create admin --role admin`。パスワードは対話入力）。
2. LLM を使う場合は `.env` に `ANTHROPIC_API_KEY=...` を書きます（未設定ならモック LLM で動作）。
3. 既定では `127.0.0.1:8788` にだけ公開されます。LAN に出す場合は `.env` の `TOKIWA_BIND=0.0.0.0` ですが、
   **TLS なしで公開せず**、後述のリバースプロキシを前に置いてください。

> ⚠️ **空の値で有効化しないでください**。たとえば `TOKIWA_SERVER__SECRET_KEY=`（空）は「空文字の署名鍵」として
> 使われてしまいます。使わない項目はコメントアウトのままにします。未設定なら署名鍵は初回起動時に自動生成されます。

### docker 単体で動かす

```bash
make docker              # docker build -f deploy/Dockerfile -t tokiwa:local .
docker run -d --name tokiwa --init -p 127.0.0.1:8788:8788 -v tokiwa-data:/data tokiwa:local
```

### 既定のハードニング（compose）

読み取り専用ルートファイルシステム（書き込みは `/data` と `/tmp` のみ）、全ケーパビリティの削除、
`no-new-privileges`、非 root ユーザー（uid/gid 10001）、ログローテーション（10 MB × 5）。

## 同じイメージで他のロールを動かす

コンテナの第 1 引数が `serve gate agent sim eval intel user token version` のいずれかなら `tokiwa` コマンドとして実行されます。

```bash
# センサー用 API トークン（一度だけ表示）
docker compose -f deploy/compose.yaml exec tokiwa tokiwa token create gate-1

# Gate（compose の gate プロファイル。.env に TOKIWA_GATE__INGEST_TOKEN と TOKIWA_GATE__UPSTREAM を設定）
docker compose -f deploy/compose.yaml --env-file .env --profile gate up -d

# ホストセンサー（ホストのポート・プロセスを見るため host の PID / ネットワーク名前空間を使う）
docker run -d --name tokiwa-agent --pid host --network host -e TOKIWA_HEALTHCHECK_URL=none \
  -e TOKIWA_AGENT__INGEST_TOKEN=tkw_... -v /var/log/nginx:/var/log/nginx:ro tokiwa:local agent run
```

- HTTP を持たないロール（agent / sim）は `TOKIWA_HEALTHCHECK_URL=none` を付けます。Gate のヘルスチェックは
  `http://127.0.0.1:8080/__tokiwa/health` です。
- Agent は他ユーザーのプロセス情報を読むのに root 相当の権限が要る場合があります（イメージは非 root）。
  ホスト監視が目的なら、ホストに直接インストールする方が素直です。詳しくは [センサーの接続](Sensors)。

## PostgreSQL に切り替える

SQLite はラボ〜小規模向けです。イベント量が多い場合は PostgreSQL を使います。`.env` に次を設定して `make up` します。

```bash
COMPOSE_PROFILES=postgres
POSTGRES_USER=tokiwa
POSTGRES_PASSWORD=<openssl rand -hex 24 の出力>
TOKIWA_DATABASE__URL=postgresql+asyncpg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/tokiwa
```

- テーブルは起動時に自動作成されます。PostgreSQL はホストに公開されません（compose ネットワーク内のみ）。
- SQLite から PostgreSQL への **データ移行ツールはまだありません**（新しい DB から始めます）。

## リバースプロキシの背後に置く

- **ドメイン（またはサブドメイン）のルートで公開** してください。`/tokiwa/` のようなサブパスでの配信は未対応です。
- `TOKIWA_SERVER__BASE_URL=https://tokiwa.example.internal` を設定します（通知のリンクなどに使われます）。
- リアルタイム更新（SSE: `/api/v1/stream`）は **バッファリングを切り、タイムアウトを長く** します。
- プロキシが別ホスト／別コンテナなら `FORWARDED_ALLOW_IPS=<プロキシの IP/CIDR>` を設定します。

nginx の例:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name tokiwa.example.internal;
    client_max_body_size 20m;                  # センサーからの取り込みバッチ用

    location /api/v1/stream {
        proxy_pass http://127.0.0.1:8788;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
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

Caddy の例:

```caddyfile
tokiwa.example.internal {
    reverse_proxy 127.0.0.1:8788 {
        flush_interval -1
    }
}
```

プロキシで SSO などの認証を重ねる場合、センサーが使う `/api/v1/ingest/events` と `/api/v1/gate/policy` は
API トークンで認証されるので、これらのパスは除外するか、センサーを内部ネットワーク経由で直接 :8788 に向けてください。

## バックアップとリストア

保存すべきものは **DB** と **署名鍵 `secret.key`** の 2 つです（どちらも `/data`）。`secret.key` を失うと
ログイン中のセッションが無効になります（API トークンは DB 内のハッシュなので影響しません）。

SQLite は WAL モードなので、稼働中にファイルを直接コピーせず、オンラインバックアップ API を使います。

```bash
C="docker compose -f deploy/compose.yaml"
$C exec -T tokiwa python -c "import sqlite3; s=sqlite3.connect('/data/tokiwa.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d); d.close(); s.close()"
mkdir -p backups
$C cp tokiwa:/data/backup.db  "backups/tokiwa-$(date +%F).db"
$C cp tokiwa:/data/secret.key "backups/secret-$(date +%F).key"
$C exec -T tokiwa rm /data/backup.db
```

リストアは停止中に置き換えます。

```bash
$C stop tokiwa
$C cp backups/tokiwa-YYYY-MM-DD.db  tokiwa:/data/tokiwa.db
$C cp backups/secret-YYYY-MM-DD.key tokiwa:/data/secret.key
$C run --rm --entrypoint sh tokiwa -c 'rm -f /data/tokiwa.db-wal /data/tokiwa.db-shm'
$C start tokiwa
```

PostgreSQL の場合は `pg_dump -Fc` / `pg_restore` を使い、`secret.key` は別途保存します。

## アップグレード

```bash
git pull
make up                  # 再ビルドして入れ替え（/data ボリュームは保持）
```

> ⚠️ **スキーマの自動移行（マイグレーション）はまだありません**。起動時には「無いテーブルを作る」だけで、
> 既存テーブルの列の追加・変更は行いません。アップグレード前に必ずバックアップを取ってください。
> 移行ツール（Alembic）は次の開発フェーズで導入予定です。

## 開発・運用の補助コマンド（make）

| コマンド | 内容 |
|---|---|
| `make dev` | API（:8788、自動リロード）と UI（:5173）を同時起動 |
| `make test` / `make lint` / `make build` | テスト / リント / UI ビルド |
| `make up` / `make down` / `make logs` | `deploy/compose.yaml` の起動・停止・ログ |
| `make lab` | ラボ（`lab/compose.yaml`）の起動 |
| `make seed` | ローカルのサーバーにデモ用の合成イベントを投入（送信先は localhost のみ） |
| `make docker` / `make docker-smoke` | イメージのビルド / スモークテスト |
