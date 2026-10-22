# ADR-0002: ストア — SQLite（既定）/ PostgreSQL（任意）、マイグレーションは v1.0 前に Alembic

- 状態: 採用（2026-10-22）
- 決定: SQLAlchemy async で SQLite(WAL) を既定、`TOKIWA_DATABASE__URL` で PostgreSQL に切替可能。
  イベントはホット列 + JSON 文書（`events.data`）。起動時 `create_all`（開発フェーズ）。
- 理由: ラボ規模では SQLite で十分、運用が軽い。要件 v0.1 の DuckDB+SQLite 案は二重管理になるため一本化。
  分析需要が増えたら DuckDB を読み取り専用で `events` に向ける / ClickHouse・OpenSearch へ移行（要件 未決 #5）。
- 課題: スキーマ変更時の移行が手動。**v1.0 前に Alembic を導入**（HANDOFF の TODO）。
