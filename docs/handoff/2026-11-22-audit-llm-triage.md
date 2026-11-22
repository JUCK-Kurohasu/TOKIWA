# 2026-11 監査対応: llm-triage レーン（系統 F「LLM・トリアージ」）

担当 Issue（この順）: #35, #96, #98, #172, #62。指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`
（#35=L08-01, #96=L08-04, #98=L08-10, #172=L18-07, #62=L08-08）。再現は `docs/audit/2026-11/repro/L08/`。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #35 | 完全 | (1) 単価表にないモデルは **最も高い既知単価**（トークン種別ごとの最大。`llm.pricing` の上書きも含む）で見積もる fail-closed（`llm/pricing.py::price_for` / `unpriced_rates`）。(2) モデル名の正規化 `normalize_model`: 小文字化、Bedrock 形式の接頭辞（`anthropic.` / `us.anthropic.` / `global.anthropic.`）と `anthropic/`、スナップショット形の接尾辞（`-YYYYMMDD` / `@YYYYMMDD` / `-vN[:N]` / `-latest`）だけを除く。汎用の前方一致はしない（`claude-opus-5-9` を兄弟モデルの単価で推測しない＝未知扱い）。(3) 各呼び出しに `llm_calls.cost_basis`（nullable 列。`table` / `snapshot` / `unpriced` / NULL=課金なし）を書き込み時に記録（structured・chat の両経路。サーバー側フォールバックの served model も正規化）。トークン 0（予算超過・エラー）は NULL で「料金不明の呼び出し」に数えない。(4) `/llm/usage` に日別 `unpriced_calls` と期間の `unpriced_models`、`/llm/config` に `unpriced_models`（設定中のモデルで単価なし。mock は空）、`LLMCall.cost_basis`。使用量タブに警告文、設定タブの予算メーター下に警告、呼び出し履歴の費用に `*`（見積もり）。ゲートウェイ生成時と見積もり時に WARNING。(5) 整合テスト: `BUILTIN_ANTHROPIC_MODELS` と既定モデルが全部 `table` で引けること、表のキーが正規形であること。表に `claude-fable-5` / `claude-opus-4-6` / `claude-sonnet-4-6` を追加（出典は claude-api リファレンスのモデル表＝キャッシュ 2026-11-03、`TODO(verify)`）。wiki LLM ×4、api-contract | (この行のコミット) |
| #96 | 未着手 | | |
| #98 | 未着手 | | |
| #172 | 未着手 | | |
| #62 | 未着手 | | |

## 要判断

- **#35 無料のローカル LLM（openai_compat の Ollama 等）の扱い**: fail-closed なので、単価表に無いモデル名は最も高い既知単価
  （現状 Fable 5.1 の $10 / $50 per 1M）で見積もられ、既定の日次予算 $5 に達するとルールベースに切り替わる。回避は
  `llm.pricing` に 0 円で登録（`{"llama3.1:8b": {"input": 0, "output": 0}}`）か `llm.daily_budget_usd: 0`。
  プロバイダ別の既定（openai_compat は無料扱い）や「不明モデルは無料」のつまみは作らなかった（有料の OpenAI 互換ゲートウェイで
  同じ穴が開くため）。wiki・設定画面・使用量画面に案内を出した。既定を緩めるかはユーザー判断。

## 既定動作の変更

- #35: 単価表に無いモデルの費用が $0 → 最も高い既知単価の見積もり（上記）。既存の DB の行は `cost_basis` が NULL のまま（遡って再計算しない）。

## 失敗した試み

## 担当外の変更

- `backend/src/tokiwa/db/models/llm.py`（llm モジュール所有と判断）: `LLMCallRow.cost_basis`（nullable、`sync_additive` で既存 DB に追加）。
- `backend/src/tokiwa/schemas/system.py::LLMCall`: `cost_basis: str | None = None`（互換の追加）。`frontend/src/api/types.ts` も更新。

## 他レーンへの依頼

## 未検証事項

- **#35 単価**: 既存表の値は変えていない。claude-api リファレンス（キャッシュ 2026-11-03）では Sonnet 5.5 のキャッシュ読み取りが $0.10
  だが表は 0.20 のまま（多めに見積もる方向なので予算の安全側。`TODO(verify)`）。Haiku 5.5 は 100K トークン超の入力で $0.50 / $2.50
  になる長文単価があるが未対応（`max_input_tokens_per_call` 既定 24,000 なので通常は届かない）。追加した 3 モデルの単価も公式の料金ページでは未確認。
