# HANDOFF.md — 現在地と次の一手

> 新しいセッション/アカウントはまずここを読む。作業の区切りごとに **必ず更新** する。
> 秘密情報・社内情報は書かない。

最終更新: 2026-10-22 08:15 UTC（セッション 1 / 統合担当）
作業ブランチ: `claude/affectionate-knuth-1inglo`

## 1. 現在の状態（サマリ）

- **M0 基盤: 完了**。骨格（契約・拡張ポイント）・ドキュメント・フロントシェルが動く。
  - `cd backend && uv run pytest` → 緑（スモークテスト）
  - `uv run tokiwa serve` → API（/api/docs）と UI（frontend/dist があれば）を配信
- **M1/M2: 並列エージェント（第 1 波, 18 タスク）で実装中**。各タスクの仕様は `docs/tasks/*.md`。
  各エージェントの作業ログは `docs/handoff/` に追加される。

## 2. 実装済み（骨格）

| 領域 | ファイル | 備考 |
|---|---|---|
| 設定 | backend/src/tokiwa/config.py | env `TOKIWA_*`（ネストは `__`）+ `tokiwa.yaml`。モジュール別セクション |
| スキーマ | backend/src/tokiwa/schemas/ | events / alerts / triage / intel / response / system |
| DB | backend/src/tokiwa/db/ | SQLAlchemy async。全テーブル定義済（models/ は自動 import） |
| パイプライン | pipeline/service.py | enrich → detect → store → alerts（重複排除）→ bus |
| 検知エンジン | detect/base.py, engine.py, context.py | `@register_detector`、窓/状態ストア |
| LLM | llm/base.py, gateway.py, mock.py, redact.py, prompting.py, pricing.py | ゲートウェイ（予算/監査/検証）、Mock、マスキング、非信頼データ封入 |
| 実行時 | runtime.py, bus.py, plugins.py | `@on_startup` / `@periodic` / pub-sub / 自動検出 |
| API | api/app.py, deps.py, routes/{health,auth,ingest}.py | 認証（JWT/API トークン）、取り込み |
| CLI | cli.py | serve / user create / token create（他はモジュールが追加） |
| フロント | frontend/src/ | ルート自動検出、AppShell、UI キット、i18n（ja/en）、API クライアント、ログイン/セットアップ |

## 3. 進行中（第 1 波の担当一覧）

- PR #1（骨格）は main にマージ済み。第 1 波は PR #2（同ブランチ）で統合中。
- **統合済み**: copilot, llm（`cd backend && uv run pytest` → 85 件 緑）
- **実装中（16）**: detect-web / sigma / detect-ai / sensors / gate / deception / triage-correlate / intel-feeds /
  intel-advisor / respond / api-core / frontend-core / frontend-ops / frontend-intel / lab-eval / devops
- 各エージェントは `.claude/worktrees/agent-*`（ブランチ `worktree-agent-*`）で作業。利用制限で全員が一時中断
  （08:10 UTC リセット後に再開指示済み）。**別セッションで引き継ぐ場合**: 各 worktree の `git status` /
  `git log c4881e1..HEAD` で進捗を確認し、未完ならその worktree で `docs/tasks/<name>.md` の続きを実装 →
  コミット → 統合ブランチへ `git merge --no-edit worktree-agent-<id>`。
- worktree のブランチは古い main（0efcd24）から作られることがある。その場合は `git merge --ff-only c4881e1`
  で骨格に追いつかせてから作業する（copilot/llm 担当はそうした）。

## 4. 次の一手（優先順）

1. 第 1 波の成果をマージし、全テスト・lint・ビルドを緑にする（統合）。
2. E2E 確認: `tokiwa sim` で ai_agent プロファイルを流し、AI アトリビューション → インシデント → トリアージ →
   対処提案 → 承認 → Gate ブロックまで通ること。
3. 評価ハーネスで基準値を取り、`aidetect/scoring.py` の重みを調整。
4. Alembic 導入（ADR-0002）。データ保持期間とパージジョブ。

## 5. 要判断事項（ユーザー）

- ライセンス: Apache-2.0 を暫定採用（ADR-0005）。MIT に変えるなら公開前に。
- 実 LLM での評価実行（費用が発生）: 予算上限を決めてから `tokiwa eval run --llm live`。
- AI カナリアの文言（デコイに埋め込む隠し指示）の強さ・言語。

## 6. 既知の制約・注意

- このクラウド環境からは NVD/KEV/EPSS/JVN/OSV 等の外部 API に出られない（プロキシで 403）。インテルのテストは fixture。
- ARTEX-JP は `/home/user/artex-jp` に読み取り専用でクローン（AGPL-3.0 のためコードは複製しない）。
- Anthropic SDK は `anthropic` 2.x（httpx2 ベース）。`messages.parse(output_format=...)` が使える。

## 7. 失敗した試み・ハマりどころ

- hatchling は `readme` にプロジェクト外パスを指定できない → `backend/README.md` を置いた。
- ruff の E501 は formatter に任せて無効化（日本語 docstring が長くなるため）。
- 18 体同時実行でアカウントのセッション利用制限に到達（約 1.5 時間で全員停止）。作業は worktree に残るので
  SendMessage で再開できる。エージェントには「論理単位ごとにコミット」を指示済み。
- anthropic SDK 2.x は httpx2 ベースのため respx では SDK 通信を捕捉できない → httpx2 のモックトランスポートを注入（llm 担当）。
