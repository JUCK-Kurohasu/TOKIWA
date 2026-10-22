# タスク: frontend-intel — インテル・資産・ルール・LLM・コパイロット

## 担当範囲
- `frontend/src/pages/intel/`, `pages/assets/`, `pages/rules/`, `pages/llm/`, `pages/copilot/`
- 共有コンポーネントは `frontend/src/components/common/` に新規ファイルで

## 要件
1. Intel（`/intel`）: タブ = 脆弱性（KEV/EPSS/CVSS/資産一致フィルタ、KEV バッジ、EPSS バー）/ 資産一致 /
   アドバイザリ（優先度 P1〜P4、要約・影響・緩和策・検知機会・Sigma 提案（「ルールとして確認」→ /rules へ））/
   ニュース / Web リサーチ（findings カード、出典リンク、「今すぐ調査」）/ ソース状態（最終同期・エラー・手動同期）。
   脆弱性詳細ダイアログ（説明・参照・一致資産・アドバイザリ生成ボタン）。
2. Assets（`/assets`）: 資産 CRUD（ソフトウェア一覧の編集: vendor/product/version/cpe/ecosystem）、重要度。
3. Rules（`/rules`）: タブ = 検知器（有効/無効トグル、説明、MITRE）/ Sigma ルール（一覧・作成・編集（等幅テキストエリア）・
   検証・有効/無効）/ LLM 提案（proposed のレビュー: 内容と根拠を見て承認/却下）。
4. LLM（`/llm`）: 設定（プロバイダ・モデル fast/deep・effort・日次予算・出力言語・フォールバック・キャッシュ、
   API キー入力は書き込み専用）、利用状況（日別費用・トークン・目的別、recharts）、呼び出し監査ログ（一覧→詳細で
   マスク済み入力と出力）、接続テスト。
5. Copilot（`/copilot`）: 会話一覧 + チャット。SSE（`postStream`）でツール呼び出しの進行（「search_events を実行中…」）と
   回答を表示。Markdown は簡易レンダリング（依存追加なしで: 段落・コード・リスト程度）。インシデント詳細から
   「コパイロットに聞く」で `context.incident_id` 付き会話を作れるよう `/copilot?incident=<id>` を受け付ける。
6. 日英対応・ローディング/空/エラー状態。

## 受け入れ基準
- `npm run typecheck && npm run lint && npm run build`。API 形状は docs/api-contract.md に一致。
