# ADR-0001: 技術スタック — Python(FastAPI) + React(Vite)

- 状態: 採用（2026-10-22）
- 文脈: 要件 v0.1 は Python 3 + Pydantic + uv を採用案としていた。ARTEX（対になる攻撃側）は Go + Next.js。
  ユーザーはフレームワーク選定を一任。多数の AI エージェントが並列に開発・引継ぎする。

## 決定
- バックエンド: Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2.0 async, uv。単一プロセス（API + パイプライン + ジョブ）。
- センサー（Gate / Agent）も同じ Python パッケージの別エントリポイント（`tokiwa gate` / `tokiwa agent`）。
- フロント: React 19 + Vite + TypeScript + Tailwind v4 + TanStack Query + react-router 7 + recharts。
  静的ビルドを FastAPI が配信（ARTEX の「単一バイナリにフロント埋め込み」と同じ配布体験を狙う）。

## 理由
- Anthropic Python SDK・Pydantic による構造化出力の検証・psutil・セキュリティ系ライブラリの充実。
- ユーザー（セキュリティ実践者）が読み書きしやすい。要件 v0.1 の採用案と一致。
- Next.js ではなく Vite: SSR 不要の管理画面で、静的エクスポート時の動的ルート制約を避けるため。

## 却下・保留
- Go 化（ARTEX と同一言語）: 高負荷センサー部のみ将来検討（要件 未決 #6）。Gate の性能計測後に判断。
- Next.js: 上記理由で不採用。UI の見た目は ARTEX と同系統（shadcn 風）に寄せる。
