# タスク: frontend-core — ダッシュボード・イベント・セッション・ホスト・設定

## 担当範囲
- `frontend/src/pages/dashboard/`（skeleton の placeholder を置き換え）, `pages/events/`, `pages/sessions/`,
  `pages/hosts/`, `pages/settings/`
- `frontend/src/hooks/useLiveStream.ts`（SSE 購読フック: `openEventStream("/stream", ...)`、トピック別に
  TanStack Query のキャッシュ無効化）
- 共有コンポーネントの追加は `frontend/src/components/common/` に **新規ファイル** で（index.tsx は編集しない）

## 要件
1. Dashboard（`/`）: KPI（24h アラート・重大度別、オープンインシデント、AI エージェントセッション数、LLM 費用/予算、
   承認待ち対処、KEV 一致）、時系列チャート（events/alerts/ai_alerts、recharts）、上位送信元（AI スコア付き）、
   上位ルール、最近のインシデント、ライブフィード（SSE で新着アラートが流れる）。AI 関連は紫（`text-ai`）で強調。
2. Events（`/events`）: フィルタ（kind, source_ip, session_id, q, 期間）、表、行クリックで詳細ドロワー
   （HTTP: リクエスト行・ヘッダ・ボディ、JSON 表示）。URL クエリにフィルタを保持。
3. Sessions（`/sessions`）: AI スコア順の一覧（分類バッジ・スコアメータ・リクエスト数・エラー率）。
   詳細（`/sessions/:id`）: 到着間隔のタイムライン（散布図/バー: x=時刻, y=gap_ms、エラーを色分け）で
   「思考待ちのリズム」を可視化、特徴量と根拠（indicators）、リクエスト一覧。
4. Hosts（`/hosts`）: ホスト一覧、ポート表（許可/逸脱を色分け）、ベースライン管理（追加・削除・「現状を学習」）。
5. Settings（`/settings`、admin）: タブ = ユーザー / API トークン（作成時に平文を 1 回だけ表示・コピー）/
   通知チャネル（追加・テスト送信）/ システム（バージョン、ジョブ一覧と手動実行、監査ログ）。
6. 日英対応（`useLocal`）。ローディング/空/エラー状態を必ず実装。API 未実装（404）の場合も画面が壊れない。

## 受け入れ基準
- `npm run typecheck && npm run lint && npm run build` が通る。各ページがサイドバーに出る。
- API 形状は docs/api-contract.md に一致。
