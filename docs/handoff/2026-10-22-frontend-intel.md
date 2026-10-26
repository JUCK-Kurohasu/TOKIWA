# 2026-10-22 frontend-intel 作業ログ

担当: `docs/tasks/frontend-intel.md`（インテル・資産・ルール・LLM・コパイロット）
ブランチ: `worktree-agent-a6d36da9cffc68893`（skeleton `c4881e1` から fast-forward して開始）

## やったこと

| ページ | パス | 内容 |
|---|---|---|
| Intel | `/intel` | タブ: 脆弱性（KEV/EPSS/CVSS/資産一致フィルタ、KEV 行は赤）/ 資産一致（状態変更）/ アドバイザリ（P1〜P4、Sigma 提案 →「ルールとして確認」で `/rules`）/ ニュース / Web リサーチ（findings カード・出典リンク・「今すぐ調査」）/ ソース状態（最終同期・エラー・手動同期）。脆弱性詳細ダイアログ（説明・参照・一致資産・アドバイザリ生成）。上部に KEV×一致 / 未対応一致 / P1 の件数チップ |
| Assets | `/assets` | 資産 CRUD、ソフトウェア編集（vendor/product/version/cpe/ecosystem）、一括貼り付け（pip freeze / npm / 「名前 バージョン」/ CPE 2.3）、重要度、削除確認。`?asset=<id>` で直接開く |
| Rules | `/rules` | 検知器（楽観的トグル・MITRE リンク）/ Sigma（一覧・作成・編集・検証・有効/無効・削除、組み込みは複製して編集）/ LLM 提案（本文・根拠・出所 → 検証 / 編集 / 承認 / 却下、承認は確認ダイアログ） |
| LLM | `/llm` | 設定（変更フィールドのみ PUT、API キーは書き込み専用）、状態と予算メーター、接続テスト、利用状況（日別費用+予算線、トークン積み上げ、目的別、表表示）、呼び出しログ（詳細は管理者のみ、マスキング済み入力と出力をプレーンテキスト表示）。`?tab=calls&call=<id>` |
| Copilot | `/copilot` | 会話一覧 + チャット。`postStream` で SSE を受け、ツール呼び出しを「search_events を実行中…」→ 完了/失敗で表示。回答は自前の安全な Markdown レンダラ。停止ボタン、IME 変換中の Enter は送信しない。`?incident=<id>` で `context.incident_id` 付き会話を作成、`?c=<id>` で会話を開く |

共通コンポーネント（`frontend/src/components/common/` に新規ファイルのみ）:
`QueryView`（ローディング/エラー/空、404 は「API 未実装」表示）, `SafeMarkdown`（innerHTML 不使用・http(s)/同一オリジンパスのみリンク化）, `IntelBadges`（KEV/EPSS/CVSS/優先度/MITRE/SafeLink/AI 生成）, `ToggleSwitch`, `OffsetPager`, `DangerConfirm`（ConfirmDialog）, `FilterChip`, `InlineNotice`, `RoleGate`（useCan）, `urlState`（URL クエリ状態）。
エンドポイント固有の型は `frontend/src/api/types-intel.ts`（types.ts は未編集）。

テスト（vitest）: `SafeMarkdown.test.tsx`（生 HTML のエスケープ、javascript:/data: リンク拒否、表・コード・snake_case）、`pages/assets/software.test.ts`（一括貼り付けパーサ・CPE）。

## 現在の状態

- `npm run typecheck && npm run lint && npm run build` 緑、`npx vitest run` 8/8 緑。
- バックエンドは並行開発中のため実 API との結合確認は未実施。API が 404 でも画面は壊れない。
- サイドバー配置: インテリジェンス（Intel 40 / 資産 42 / 検知ルール 44）、調査（コパイロット 25）、システム（LLM 82）。
- 共有ファイル（index.tsx, routes.ts, App.tsx, AppShell.tsx, client.ts, types.ts, biome.json, package.json）は未変更。依存追加なし。

## API の前提（TODO(verify)）

契約で形が固定されていない部分は寛容に実装した。バックエンド実装と突き合わせること。

1. `PUT /llm/config` のキー名は config.py の `LLMSettings` に合わせた: `anthropic_api_key`, `openai_api_key`, `openai_base_url`。`GET /llm/config` が `anthropic_api_key_set` / `openai_api_key_set`（bool）を返せば「設定済み」バッジを出す（無くても動く）。キー自体は決して返さないこと。
2. `GET /llm/usage` の `by_purpose` の値: 数値なら USD 費用として扱う。`{cost_usd, calls, ...}` オブジェクトにも対応。
3. Copilot SSE: `text` は `text`/`delta`/`content` を追記（チャンク・一括どちらも可）。`tool_call` は `id`, `name`, `input`。`tool_result` は `id`（無ければ同名の実行中ステップに対応付け）, `summary` または `content`, `is_error`。`error` は `error`/`message`/`detail`。会話メッセージの `tool_calls` は `[{id?, name, input?, summary?}]` を想定。会話に `context` があればインシデントバナーを表示。
4. 会話一覧・`/detectors`・`/intel/sources` は配列でも `Page` でも受け付ける（`asList`）。
5. `/intel/vulns` の `min_epss` は 0〜1（EPSS の尺度）、`min_cvss` は 0〜10、`kev`/`matched` は `true` のときだけ送る。
6. LLM 提案ルールの `meta` から `rationale`, `advisory_id`, `vuln_ids`, `llm_call_id` を読む（あればリンク表示、他はメタデータとして JSON 表示）。
7. `POST /rules` は 422 の `detail` 配列を項目ごとのメッセージにして表示。組み込み（builtin）ルールは UI 上で読み取り専用扱い（削除ボタンなし、複製して編集）。
8. `/intel/matches` 等のマッチには `asset_name` があれば表示、無ければ `asset_id`。

## 他モジュールへの依頼

- frontend-ops: インシデント詳細の「コパイロットに聞く」は `/copilot?incident=<id>` へリンクするだけでよい。
- llm（routes/llm.py）: 上記 1・2 の形を確定したら `docs/api-contract.md` に追記してほしい。
- copilot（routes/copilot.py）: 上記 3 の SSE フィールド名を契約に追記してほしい。
- sigma / intel-advisor: 提案ルールの `meta` に上記 6 のキーを入れてもらえると、レビュー画面から根拠とアドバイザリへ辿れる。

## 未完・次の一手

- 実バックエンドとの結合確認（特に SSE と LLM 設定の PUT）。必要なら types-intel.ts と各ページを調整。
- バンドルが 945 kB（recharts を含む）。気になるなら LLM/コパイロットを `React.lazy` で分割（routes.ts は eager glob なのでページ内で lazy にする）。
- ストリーム中にエラー/停止した場合、バックエンドがユーザー発言を保存していると、ライブ表示と保存済み表示が一時的に重複しうる（次の送信か「新しい会話」で消える）。
- ニュースのソース絞り込みは自由入力（datalist は表示済みソースから補完）。ソース一覧 API の形が確定したら選択式にできる。
- 調整できる箇所: 1 ページの件数（各タブの `LIMIT`）、EPSS/CVSS フィルタの段階（`VulnsTab.tsx`）、EPSS バーの色の閾値（`IntelBadges.tsx` の `epssColor`）、コパイロットの質問例（`ChatView.tsx` の `suggestionSets`）、ツール名の表示ラベル（同 `toolLabels`）。
