# タスク: llm — LLM プロバイダ実装・実行時設定・LLM API

## 目的
`tokiwa.llm.gateway` の下で動くプロバイダを実装する。主: Anthropic（Claude）。副: OpenAI 互換（ローカル LLM:
Ollama/vLLM 等。ログを外部に出せない環境向け）。UI から設定・利用状況・監査ログを扱う API。

## 担当範囲
- `backend/src/tokiwa/llm/anthropic_provider.py`, `backend/src/tokiwa/llm/openai_compat.py`（stub を実装）
- `backend/src/tokiwa/llm/settings.py`（新規: settings_kv `llm.config` のオーバーレイ、gateway 再構築）
- `backend/src/tokiwa/llm/gateway.py`（改善は可。ただし公開シグネチャ `structured()` / `chat()` は互換維持）
- `backend/src/tokiwa/api/routes/llm.py`
- `backend/tests/llm/`、`docs/security/llm-safety.md`（新規: プロンプトインジェクション対策・マスキング・監査）

## 要件（Anthropic）— 実装前に claude-api スキル/公式 SDK で形状を確認すること（SDK は anthropic 2.x がインストール済み）
1. `AsyncAnthropic`（`api_key` は `config.anthropic_api_key()`、`base_url` は設定値があるときのみ明示）。
   `timeout=request_timeout_seconds`、`max_retries=2`。
2. 構造化出力: `client.messages.parse(model, max_tokens, system=[...], messages=[...], output_format=Schema,
   output_config={"effort": effort})` → `parsed_output`。thinking は Opus 5.5 では常時（パラメータ省略）。
   Haiku 5.5 は adaptive 既定。`temperature` 等のサンプリングパラメータは送らない（2026-10-21 以降 400）。
3. プロンプトキャッシュ: system ブロックに `cache_control: {"type": "ephemeral"}`（`cache=True` のとき）。
   システムプロンプトは静的に保ち、可変データは user 側へ（gateway 呼び出し側の責務も docs に記載）。
4. Refusal: `stop_reason == "refusal"` → `ProviderResponse.refused=True`（`stop_details.category` を text に残す）。
   `enable_fallbacks=True` かつ deep tier（opus/sonnet 5.5 系）では server-side fallback
   （beta `server-side-fallback-2026-07-01` + `fallbacks="default"`）を使う。parse で beta が使えない場合は
   `client.beta.messages.create` + `output_config.format` の JSON Schema で代替（実装時に SDK を確認）。
   セキュリティ文脈（攻撃ペイロード解析）は `cyber` 分類器に当たりうるので、拒否は正常系として扱う。
5. Web 検索（intel research 用）: `tools=[{"type":"web_search_20260209","name":"web_search","max_uses":N,
   "allowed_domains":[...]}]`。`pause_turn` は継続呼び出しで処理（上限回数）。citations と
   `usage.server_tool_use.web_search_requests` を `ProviderResponse` に詰める。web_search と構造化出力の
   併用可否を確認し、不可なら「検索→要約テキスト」→「構造化抽出（2 回目の呼び出し）」の 2 段にする。
6. `chat()`: tools（ToolSpec → Anthropic tool 定義、`strict: true` 可能なら）、tool_use ブロックを `ToolCall` に、
   `raw_content` に応答ブロックをそのまま（再送用）。forced tool_choice は使わない（Opus 5.5 で 400）。
7. usage（input/output/cache_read/cache_creation）を `LLMUsage` に。

## 要件（OpenAI 互換）
- `httpx` で `/v1/chat/completions`。`response_format={"type":"json_schema", ...}` 非対応サーバー向けに
  「JSON のみで答えよ」+ パース + 1 回リトライのフォールバック。tool calls は OpenAI 形式 ↔ 中立形式に変換。

## 要件（設定・API）
- `llm/settings.py`: `settings_kv["llm.config"]`（provider, models, effort, budget, language, fallbacks, cache,
  API キーは暗号化不要だが **API レスポンスでは決して返さない**）を Settings に重ね、`set_gateway(LLMGateway(...))`。
  起動時に適用（`@on_startup`）。
- `routes/llm.py`（docs/api-contract.md「LLM」）。`/llm/test` は最小の構造化呼び出しでヘルスチェック。

## 受け入れ基準
- Anthropic SDK を `respx` などでモックしたテスト（parse 成功・refusal・invalid JSON・usage 集計・cache_control
  付与・web_search の citations 抽出・pause_turn 継続）。実 API は叩かない。
- 予算超過時に `BUDGET_EXCEEDED` で呼ばれないこと、監査行が残ること。
- `docs/security/llm-safety.md` を作成。
