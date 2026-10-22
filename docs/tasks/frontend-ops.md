# タスク: frontend-ops — アラート・インシデント・対処・デセプション

## 担当範囲
- `frontend/src/pages/alerts/`, `pages/incidents/`, `pages/response/`, `pages/deception/`
- 共有コンポーネントは `frontend/src/components/common/` に新規ファイルで（例 `TriagePanel.tsx`, `EventDetail.tsx`）

## 要件
1. Alerts（`/alerts`）: フィルタ（状態・重大度・カテゴリ・送信元・AI スコア下限・検索）、表（重大度・タイトル・
   カテゴリ・送信元・件数・AI スコア・状態・最終検知）、一括で状態変更。詳細（`/alerts/:id`）: 説明・エンティティ・
   MITRE・証拠イベント（HTTP は整形表示）・**LLM トリアージパネル**（判定・信頼度・AI 関与度と根拠・攻撃段階・
   要約・根拠・次の手順・推奨対処（「提案として作成」ボタン → `POST /response/actions`）・モデル/ティア/プロンプト版）・
   再トリアージ（fast/deep）・状態変更。
2. Incidents（`/incidents`）: 一覧。詳細: タイトル・要約・kill chain の段階表示（ATT&CK 戦術の横並び）・
   アクター（AI エージェント判定を目立たせる）・関連アラート・対処（承認/却下ボタン）・トリアージパネル・担当者/状態変更。
3. Response（`/response`）: タブ = 承認待ち / 実行中 / 履歴。承認・却下（理由）・取り消し。TTL と期限の表示。
   「承認なしでは実行されない」ことを UI 文言でも明示。
4. Deception（`/deception`）: 資産一覧（種類・パス・トリップ数・最終トリップ）、作成ダイアログ（種類ごとのフォーム）、
   プレビュー（配信される本文）、トリップ履歴。AI カナリアの説明（何が起きたら AI と断定するか）を表示。
5. 日英対応・ローディング/空/エラー状態。

## 受け入れ基準
- `npm run typecheck && npm run lint && npm run build`。API 形状は docs/api-contract.md に一致。
