# CLAUDE.md

@AGENTS.md

## Claude Code 向け補足

- セッション開始時は `HANDOFF.md` を読み、「次の一手」から再開する。終わる前に必ず更新する。
- Python は `backend/` で `uv run ...`、フロントは `frontend/` で `npm run ...`。リポジトリ直下では実行しない。
- 並列サブエージェントで作業する場合は git worktree を使い、モジュール単位（docs/tasks/*.md）で分担する。
  共有ファイル（config.py の他セクション、schemas の既存モデル、app.py、routes.ts）は触らない。
- LLM まわりのコードを書く前に `claude-api` スキル（利用可能なら）で最新の API 形状を確認する。
  既定モデル: deep tier = `claude-opus-5-5`、fast tier = `claude-haiku-5-5`（ユーザー要件「軽量モデルで一次」）。
  構造化出力は `client.messages.parse(..., output_format=PydanticModel)`、拒否は `stop_reason == "refusal"`。
- サンドボックスでは外部の脆弱性 API（NVD/KEV/EPSS/JVN/OSV）に出られないことが多い。テストは fixture で行う。
- ユーザー（JUCK）はセキュリティ実践者。推測と事実を分け、不確実なことは不確実と書く。成果物には
  「どこを調整できるか」を添える。
