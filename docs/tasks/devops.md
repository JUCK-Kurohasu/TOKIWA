# タスク: devops — Docker・CI・開発補助

## 担当範囲
- `deploy/Dockerfile`（マルチステージ: node でフロントビルド → python:3.12-slim + uv で backend、`frontend/dist` を
  `TOKIWA_SERVER__STATIC_DIR` で配信、非 root ユーザー、`/data` ボリューム、HEALTHCHECK `/api/v1/health`）
- `deploy/compose.yaml`（本番寄り: tokiwa + 任意の postgres プロファイル）, `.env.example`
- `.github/workflows/ci.yml`（backend: uv sync → ruff → pytest、frontend: npm ci → typecheck → lint → build。
  キャッシュ有効。PR とブランチ push で実行）
- `.pre-commit-config.yaml`（ruff, ruff-format, biome（ローカル hook））
- `scripts/dev.sh`（backend と frontend を同時起動）、`scripts/seed_demo.py`（デモデータ投入: シミュレータが無くても
  ダッシュボードが埋まる程度の合成イベントを ingest API に送る。送信先は localhost 限定）
- `Makefile`（dev / test / lint / build / docker / lab のショートカット）
- `docs/deploy.md`（インストール・アップグレード・バックアップ・PostgreSQL 切替・リバースプロキシ配下での運用）

## 要件
- Docker ビルドが通ること（サンドボックスで Docker デーモンが使えない場合は `docker build` の代わりに
  Dockerfile の静的チェック（hadolint があれば）と、各ステップのコマンドをローカルで再現して確認。結果を作業ログに明記）。
- CI は秘密を必要としない（LLM は mock）。
- `scripts/seed_demo.py` は既存 API（/api/v1/ingest/events）のみ使う。

## 受け入れ基準
- CI YAML が妥当（actionlint があれば実行）。Makefile ターゲットがローカルで動く（docker 系を除く）。
