# 第 2 波（Wave 2）— 進め方とエージェント用プロンプト

第 1 波（18 モジュール）で機能は揃った。第 2 波の目的は **「実データで検証し、運用に耐える形に仕上げる」**（要件 v0.2 の M3〜M4）。
第 1 波と違い **既存ファイルの修正が中心** なので、担当範囲（触ってよいファイル）を厳密に分け、フェーズを 2 段に分ける。

## フェーズとパッケージ

| フェーズ | パッケージ | 仕様 | 主な担当範囲（ここ以外は原則触らない） |
|---|---|---|---|
| 1（並列 4） | B scoring-tuning | wave2-scoring-tuning.md | `backend/src/tokiwa/aidetect/**`, `enrich/sessionizer.py`, `detect/detectors/ai_*.py`, `backend/src/tokiwa/eval/**`, `eval/**`, `backend/tests/{aidetect,eval}/**` |
| 1 | C frontend-consolidation | wave2-frontend-consolidation.md | `frontend/**` |
| 1 | D config-ops | wave2-config-ops.md | `config.py`（横断的な変更はここだけ）, `db/**`, `backend/alembic/**`, `api/app.py`, `gate/cli.py`, `retention.py`（新規）, `.github/workflows/ci.yml`, `backend/pyproject.toml`, mypy 対象の既存エラー箇所 |
| 1 | E feature-gaps | wave2-feature-gaps.md | `gate/capture.py`, `gate/proxy.py`, `detect/detectors/web_spray.py`（新規）, `respond/**`, `deception/service.py`, `correlate/**`, `config.py` の `ResponseSettings` / `DeceptionSettings` セクションのみ |
| 2（並列 2、フェーズ 1 のマージ後） | A lab-validation | wave2-lab-validation.md | `lab/**`, `docs/purple-team.md`、結合バグは該当モジュールに最小修正 |
| 2 | F security-review | wave2-security-review.md | 全体を読む。修正は最小限・テスト付き |
| 要承認 | G live-llm-eval | wave2-live-llm-eval.md | `eval/` の実行と報告のみ（**ユーザーの予算承認が必要**） |

同時実行は **最大 6 体**（第 1 波では 16〜18 体同時で利用上限に何度も当たり、再開コストが大きかった）。

## 統合担当（新セッションのメイン）の手順

1. `HANDOFF.md` → `AGENTS.md` → この文書 → 各 `wave2-*.md` を読む。
2. main の HEAD を確認（`git fetch origin && git log origin/main --oneline -3`）。第 1 波は PR #5 までで全て main に入っている
   （2026-10-26 マージ、`db9f012`）。それより古い main しか見えない場合はユーザーに確認する。
3. 自分の作業ブランチを最新 main から作る（システムが指定するブランチ名に従う）。
4. フェーズ 1 の 4 体（B, C, D, E）を Agent ツールで **`isolation: "worktree"`** を付けて起動（下のテンプレート）。
5. 完了報告ごとに `git merge --no-edit worktree-agent-<id>` → 全チェック（下記）→ push → PR（ドラフト）。
6. フェーズ 1 を全部マージしたら、フェーズ 2（A, F）を同様に起動。
7. G はユーザーが予算（例 $10〜30）を承認した場合のみ。
8. 区切りごとに `HANDOFF.md` を更新。

### 全チェック（CI と同条件）

```bash
cd backend && FORCE_COLOR=1 TOKIWA_LLM__PROVIDER=mock uv run pytest \
  && uv run ruff check src tests ../scripts ../deploy && uv run ruff format --check src tests ../scripts ../deploy
cd frontend && npm run typecheck && npm run lint && npm run build && npx vitest run
cd backend && uv run tokiwa eval run --dataset ../eval/datasets/lab-mini.jsonl --llm mock --out /tmp/eval-check   # 回帰確認
```

### ハマりどころ（第 1 波の教訓）
- worktree が古いコミットから作られることがある → エージェントに「まず `git merge --ff-only <main の HEAD>` で追いつかせる」と指示。
- 利用上限で止まったら、作業は worktree に残る → リセット後に SendMessage で同じエージェントを再開（新規起動しない）。
- 「論理単位ごとにコミット」を必ず指示（中断時の損失防止）。
- CI は `FORCE_COLOR=1`。CLI 出力を文字列比較するテストは ANSI を除去する。
- 他モジュールのアラート件数を厳密に数えるテストは壊れやすい（例: deception.trip が /.env でも発火）。自モジュールの rule_id に絞る。

## エージェント起動テンプレート（`<...>` を置き換える）

```
You are one of up to 6 parallel engineers on TOKIWA (LLM-driven SIEM/XDR against generative-AI-driven attacks,
the defensive counterpart of ARTEX). Wave 1 (18 modules) is merged; wave 2 hardens and validates it.
You work in your own git worktree.

FIRST: run `git fetch origin && git merge --ff-only origin/main` (your worktree may start from an older commit).
YOUR TASK: docs/tasks/wave2-<name>.md. Read HANDOFF.md, AGENTS.md, docs/tasks/wave2-README.md and your task file first,
then the code you will touch.

Rules:
- Only edit files in your package's scope (table in wave2-README.md). If a change outside it is unavoidable, keep it minimal
  and list it in your final report.
- Commit after every logical step (Conventional Commits, each message ending with
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`). Do NOT push. Do NOT switch branches.
- Before finishing, run the full checks in wave2-README.md (backend with FORCE_COLOR=1; frontend if you touched it).
- Facts you cannot verify go into code/docs as `TODO(verify): ...`. Safety rules in AGENTS.md §2 are non-negotiable.
- Add a work log docs/handoff/<YYYY-MM-DD>-wave2-<name>.md (done / left / TODO(verify) / requests to others) and commit it.

FINAL REPORT (last message, < 300 words): branch name, final commit sha, files changed, check results,
out-of-scope changes, open issues.
```
