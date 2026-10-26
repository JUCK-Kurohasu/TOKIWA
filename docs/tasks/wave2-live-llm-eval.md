# Wave 2 / G: live-llm-eval — 実 LLM での評価（要ユーザー承認）

**ユーザーが予算（例: $10〜30）を承認し、ANTHROPIC_API_KEY を環境に設定した場合のみ実行する。**

## 手順
1. 予算を `--budget-usd` で必ず指定: `uv run tokiwa eval run --dataset <B 担当の評価データ> --llm live --budget-usd <N> --out eval/runs/<ts>`
   （上限に達したらハーネスが止まる。`llm.daily_budget_usd` も確認）。
2. 指標: LLM 判定とラベルの一致率（actor / verdict / AI）、refusal 率と発生カテゴリ、無効出力率、エスカレーション率、
   1 アラートあたりのトークン・費用、トリアージ遅延。
3. refusal や不一致が多いプロンプトを特定し、`triage/prompts.py` のバージョンを上げて改善 → `--compare` で回帰比較（要件 7-6）。
4. 結果を `docs/handoff/<date>-wave2-live-llm-eval.md` と HANDOFF.md に記録（費用の実績を含める）。

## 注意
- 実 API の挙動で未検証の点（pause_turn の継続、web_search と構造化出力の併用可否、strict ツールの制約）はここで確認し、
  `llm/anthropic_provider.py` の `TODO(verify)` を解消する。
