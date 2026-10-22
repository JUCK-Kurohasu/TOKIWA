# AGENTS.md — TOKIWA 開発規約（AI エージェント / 人間 共通）

TOKIWA は「生成AI（LLM エージェント）によるサイバー攻撃を検知・防御する LLM 駆動 SIEM/XDR」。
攻撃側の ARTEX（AI 自律ペネトレーションテスト）と対をなす防御側プロダクト。

最初に読む順番: **HANDOFF.md（現在地）→ この文書 → docs/architecture.md → docs/api-contract.md**。
担当タスクがあれば docs/tasks/<name>.md。

## 1. コマンド

```bash
# backend（Python 3.12+ / uv）
cd backend
uv sync                                   # 依存インストール
uv run pytest                             # テスト（全部 1 分以内を維持）
uv run ruff check src tests && uv run ruff format --check src tests
uv run mypy src                           # 型（警告は徐々に潰す。新規コードは通すこと）
uv run tokiwa serve --reload              # http://localhost:8788  （API docs: /api/docs）
uv run tokiwa token create gate-1         # センサー/ゲート用 API トークン

# frontend（Node 22 / npm）
cd frontend
npm install
npm run dev                               # http://localhost:5173 （/api は 8788 にプロキシ）
npm run typecheck && npm run lint && npm run build

# ラボ（Docker Compose）
docker compose -f lab/compose.yaml up --build
```

## 2. 絶対に守ること（安全・正確性）

1. **LLM に渡すテレメトリは常に非信頼データ**。`tokiwa.llm.prompting.untrusted_block()` で包み、
   システムプロンプトに `UNTRUSTED_DATA_POLICY` を入れる。生の文字列連結でプロンプトを作らない。
2. **LLM 出力を実行系に直結しない**。コマンド・SQL・設定変更・HTTP リクエストの文字列を LLM に作らせない。
   対処は `ActionType` 許可リスト + 検証済みパラメータ（IP/CIDR/TTL）だけを executor に渡す。
3. 対処は **人間承認が既定**。承認なしで実行されないことをテストで保証する（FR-12）。
4. **LLM 呼び出しは必ず `tokiwa.llm.gateway.get_gateway()` 経由**（予算・監査・マスキング・モデル選択）。
   SDK を他モジュールから直接 import しない。
5. 秘密情報（API キー・トークン・パスワード）をログ・DB・LLM・コミット・引継ぎ文書に書かない。
6. 能動的防御は自組織資産上のみ。反撃（hack-back）・第三者への攻撃的通信を実装しない。
7. 攻撃シミュレータ（`tokiwa.eval.sim`）はラボ内ターゲット（既定 localhost / lab ネットワーク）にのみ送信し、
   実害のあるエクスプロイトは含めない（検知用の文字列パターンのみ）。
8. 仕様・CVE・API の事実関係は推測で断定しない。不明点はコード内 `TODO(verify): ...` と HANDOFF.md に残す。

## 3. 並列開発のルール（衝突を避ける）

- **拡張ポイントを使い、共有ファイルを編集しない**（docs/architecture.md §5 の表）。
  検知器・ルート・テーブル・ジョブ・UI ページはすべて「ファイルを追加するだけ」で自動登録される。
- `config.py` は **自モジュールのセクションのみ** 編集可。
- `schemas/` の既存モデルを変更する場合は互換を保つ（フィールド追加は default 付き）。
  新しいスキーマは新ファイル（例 `schemas/hosts.py`）に置く。変更したら `frontend/src/api/types.ts` も更新。
- 依存追加は `backend/pyproject.toml` / `frontend/package.json` に最小限。理由をコミットメッセージに書く。
- 担当外のモジュールを直したくなったら、最小修正にとどめ HANDOFF.md の「他モジュールへの依頼」に記録。

## 4. コーディング規約

### Python
- 型ヒント必須。`from __future__ import annotations`。Pydantic v2。SQLAlchemy 2.0 async。
- I/O は async。ブロッキング処理（psutil 等）は `asyncio.to_thread`。
- ORM 行 ↔ スキーマはフィールド名を一致させ `Schema.model_validate(row)`。
- 時刻は常に UTC aware（`tokiwa.util.utcnow()`）。ID は `tokiwa.util.new_id()`（UUIDv7 hex）。
- ログは `logging.getLogger(__name__)`。例外を握りつぶすときは `log.exception`。
- テストは `backend/tests/<module>/test_*.py`。外部ネットワークに出ない（`respx` / `httpx.MockTransport` / fixture）。
  `conftest.py` のフィクスチャ（`client`, `admin_headers`, `ingest_headers`, `mock_llm`, `make_http_event`, `db`）を使う。
- 日本語コメント可。docstring は「なぜ」を書く。

### TypeScript / React
- ページは `src/pages/<name>/route.tsx` に `export const route: AppRoute`（自動でルーティング・サイドバー登録）。
- データ取得は TanStack Query + `api` クライアント（`src/api/client.ts`）。型は `src/api/types.ts`。
- UI は `src/components/ui`（基本）と `src/components/common`（ドメイン共通）を使う。色はセマンティックトークン
  （`bg-surface`, `text-muted`, `border-line`, `text-accent`, `text-ai`, `bg-sev-*`）。
- 文言は `useLocal({ja, en})` で日英併記（既定 ja）。
- Biome でフォーマット/リント。

## 5. コミット・ブランチ

- Conventional Commits（`feat(detect): ...`, `fix(gate): ...`, `docs: ...`）。区切りごとに小さくコミット。
- アカウント間で同時編集しない。作業ブランチを分け、HANDOFF.md を更新してから切り替える。
- テスト・lint が通らない状態で push しない。

## 6. 引継ぎ（重要）

トークン切れ・アカウント切替に備え、**作業の区切りごとに HANDOFF.md を更新**する:
「やったこと / 現在の状態（動く・動かない）/ 失敗した試み / 次の一手 / 要判断事項」。
詳細な作業ログは `docs/handoff/YYYY-MM-DD-<topic>.md` に追記してよい。
