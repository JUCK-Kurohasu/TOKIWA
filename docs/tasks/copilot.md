# タスク: copilot — SOC コパイロット（参照専用ツール付きチャット）

## 目的
アナリストが自然言語で「この IP は何をした？」「AI エージェントっぽいセッションを要約して」「KEV に該当する
資産は？」と聞けるチャット。LLM は **参照系ツールのみ** を使う（書き込み・実行系ツールは存在しない）。

## 担当範囲
- `backend/src/tokiwa/copilot/`（service.py, tools.py, prompts.py）
- `backend/src/tokiwa/api/routes/copilot.py`
- `backend/tests/copilot/`

## 要件
1. ツール（`ToolSpec`、入力は JSON Schema で厳格に。結果は件数上限・文字数上限・redact 済み）:
   `search_events`（kind/source_ip/path 部分一致/時間範囲/limit≤50）, `get_alert`, `list_alerts`, `get_incident`,
   `list_incidents`, `get_session`, `top_sources`（期間内の送信元ランキング）, `lookup_vuln`（CVE ID）,
   `list_vuln_matches`, `get_asset`, `list_actions`。SQL を LLM に書かせない（パラメータ化クエリのみ）。
2. ループ: `get_gateway().chat()` を最大 `copilot.max_tool_iterations` 回。tool_use → 実行 → tool_result を
   1 メッセージにまとめて返す（並列ツール呼び出し対応）。ツール結果は `untrusted_block` で包む（テレメトリを含むため）。
   エラーは `is_error: true` の tool_result。
3. 会話保存: `copilot_conversations` / `copilot_messages`（provider-native ブロックを `blocks` に保存して再送）。
   履歴は最大 `max_history_messages`。会話のコンテキスト（incident_id 等）があればシステムプロンプトに要約を付与。
4. API（docs/api-contract.md「コパイロット」）。メッセージ送信は SSE（`sse-starlette` か StreamingResponse）で
   `text`（最終回答は一括でも可）・`tool_call`（名前と入力）・`tool_result`（要約）・`done`・`error` を流す。
   会話は所有者のみ参照可（admin は全件）。
5. LLM 未設定（mock）でもエラーにせず案内メッセージを返す。

## 受け入れ基準
- ツール単体テスト（入力検証・上限・redact）。scripted なフェイクプロバイダ（1 回目 tool_use → 2 回目テキスト）で
  ループ・保存・SSE 出力を検証。
