# 2026-10-22 frontend-core 作業ログ（ダッシュボード / イベント / セッション / ホスト / 設定 / SSE フック）

担当: frontend-core（docs/tasks/frontend-core.md）。ブランチ `worktree-agent-a9d518ce5685a20fa`
（骨格コミット c4881e1 に fast-forward してから作業）。作業期間中に api-core / sensors / respond(notify) が
統合ブランチにマージされたため、その形状に合わせて調整済み（最終コミット群）。

## やったこと

| 画面 / 部品 | ファイル | 内容 |
|---|---|---|
| ダッシュボード `/` | `pages/dashboard/{route,TimelineCard,LiveFeed,widgets}.tsx` | KPI 6 枚（24h アラート+重大度内訳、オープンインシデント、AI セッション、LLM 費用/予算メータ、承認待ち、KEV 一致）。時系列は**二軸を使わず** 2 段（イベント量エリア / アラート積み上げ: その他=灰・AI=紫）、hover 同期、表ビュー切替。ライブフィード（SSE、同一アラートの連続更新は集約、AI は紫）。上位送信元（AI スコア）・上位ルール・最近のインシデント |
| イベント `/events` | `pages/events/{route,VolumeStrip}.tsx` | フィルタ（kind / source_ip / session_id / host / dataset / q / 期間プリセット or 任意 since-until）を URL に保持、ページング、取り込み量ストリップ（フィルタ非適用と明示、クリックでその時間帯に絞り込み）、SSE `event.ingested` で「新着 N 件」バナー（行は勝手に動かさない）、詳細ドロワー `?event=<id>` |
| セッション `/sessions`, `/sessions/:id` | `pages/sessions/*` | AI スコア順一覧（分類バッジ・スコアメータ・リクエスト数・エラー率バー・パス数・継続時間）。詳細: スコア vs しきい値、**到着間隔散布図**（x=時刻, y=gap_ms, 対数/線形、ステータス色+形状、バースト帯・推論待ち帯）、**対数ビンのギャップ分布**（二峰性）、UI 算出の統計（中央値・CV・バースト率・推論待ち率・二峰性）、indicators（形式揺れに耐える正規化）、features 表、リクエスト一覧（ギャップ印付き）→ドロワー |
| ホスト `/hosts` | `pages/hosts/*` | ホスト一覧（逸脱数順）、ポート表（許可/逸脱をアイコン+文言で、全 IF バインド警告、開/閉）、逸脱行から「許可に追加」（プリフィル）、「現状を学習」（確認ダイアログに追加される逸脱数を表示）、ベースライン一覧/追加/削除。viewer には書き込み UI を出さない |
| 設定 `/settings`（admin） | `pages/settings/*` | タブを `?tab=` に保持。ユーザー（作成・ロール変更・パスワード再設定・削除、自分は削除/ロール変更不可）、API トークン（作成時のみ平文表示+コピー+使い方、ダイアログを閉じたら state から破棄、失効）、通知チャネル（種類別フォーム、email は `password_env` 推奨、追加 JSON マージ、有効トグル、テスト送信結果）、システム（info、ジョブ一覧と手動実行、監査ログ action/actor フィルタ） |
| SSE フック | `hooks/useLiveStream.ts` | タブ内で EventSource を 1 本だけ共有（参照カウント、StrictMode/遷移用の猶予クローズ）、閉じられたら指数バックオフで再接続、JWT 変更で張り直し、トピック→クエリキー無効化（キー単位スロットル）、直近 100 件バッファ（`useLiveFeed`）、接続状態（`useLiveStatus`） |
| その他フック | `hooks/useApi.ts`, `useSearchState.ts`, `useRole.ts` | 4xx はリトライしない `useApiQuery`、422 detail 整形 `errorMessage`、URL クエリ状態、ロール判定 |
| 共通部品（新規ファイルのみ） | `components/common/{DataState,SideDrawer,EventInspector,PagerBar,ConfirmButton,SecretReveal,LiveDot,HttpStatusBadge,ChartKit,Flash,numfmt}` | 404 を「未提供」として穏やかに表示する DataState、HTTP リクエスト整形表示（非信頼データとして React テキストのみで描画）、テーマ追従のチャートパレット等 |
| 型 | `api/types-core.ts` | Dashboard/Event timeline（`bucket_minutes`）、SessionDetail、HostSummary/HostPort/PortBaseline(In)、User/UserCreate/UserUpdate、ApiTokenCreate(d)、NotificationChannelIn、SystemInfo、AuditEntry |
| テスト | `pages/sessions/rhythm.test.ts` | リズム算出・ヒストグラム・indicators 正規化（vitest 9 件） |

検証: `npm run typecheck && npm run lint && npm run build` 緑、`npx vitest run` 9/9。

## 設計判断（調整できる場所）

- **思考待ちリズムの帯**は UI の目安のみ（`pages/sessions/rhythm.ts` の `BURST_MAX_MS=300`,
  `THINK_MIN_MS=1500`, `THINK_MAX_MS=60000`）。判定はバックエンドの features/ai_score が正。仮説である旨を画面にも明記。
- AI しきい値は UI 側定数 `AI_THRESHOLD=0.7`（`pages/sessions/SessionsList.tsx`、`detection.ai_agent_threshold` 既定値の写し）。
- チャート配色は dataviz バリデータで CVD 分離を確認（`components/common/ChartKit.tsx` 冒頭に記録）。ライトモードの
  黄（4xx）は白地で 3:1 未満のため、形状（▲/◆）・凡例・表で補完。
- SSE 無効化マップは `TOPIC_INVALIDATIONS`（`hooks/useLiveStream.ts`）。`event.ingested` は 15 秒スロットルで
  dashboard/sessions/hosts のみ。イベント一覧は無効化せずバナー表示。

## API 契約からの前提・未確定（TODO(verify)）

- `GET /sessions/{id}` の `timeline[].t`: ISO 文字列を想定、エポック秒/ミリ秒も許容。timeline が空なら events から算出。
  `routes/sessions.py`（detect-ai）は本作業時点で未マージのため実データ未確認。
- `ActorSession.features.indicators` の形式は detect-ai 次第。文字列配列 / `{key|label, ja, en, weight|contribution, value, detail}` 配列 /
  `{key: weight|text}` / `{ja:[...], en:[...]}` を受け付ける（`normalizeIndicators`）。
- `/sessions` は AI スコア降順で返る前提（ページ内でも念のため降順ソート）。
- 上位ルールの AI 判定は `rule_id` が `ai.` / `llm_app.` で始まるかで紫表示（detect-ai の命名規約に依存）。
- SSE は `openEventStream()` ではなく同一 URL/認証方式（`/api/v1/stream?access_token=`）で独自 EventSource を張る。
  `openEventStream` が open/error 状態を公開しないため（接続表示と HTTP エラー後の再接続に必要）。

## 他モジュールへの依頼 / 統合時の注意

- **ライブ購読の一本化**: frontend-ops に `components/common/useOpsLive.ts`（`openEventStream` を画面ごとに開く）がある。
  ページごとに SSE 接続が増える（HTTP/1.1 の同一オリジン 6 本制限に当たりうる）ので、`hooks/useLiveStream.ts`
  （共有 1 本・再接続・無効化マップ）へ統合するのが望ましい。キー接頭辞（alerts / incidents / response / deception）は既に一致。
  `useOpsLive(prefixes, keys)` は `useLiveStream({ topics: prefixes, onMessage: () => invalidate(keys) })` で置換可能。
- **共通部品の重複**（名前衝突は無し、機能重複のみ）: ops の `QueryView`≈`DataState`、`OffsetPager`≈`PagerBar`、
  `DangerConfirm`≈`ConfirmButton`、`EventDetail`≈`EventInspector`、`urlState`≈`hooks/useSearchState`、
  `RoleGate`≈`hooks/useRole`、`InlineNotice`≈`Flash`、`ToggleSwitch`≈通知タブ内スイッチ。統合担当でどちらかに寄せる。
- `api/client.ts`: `openEventStream` に `onOpen/onError` を任意引数で追加してもらえれば、フックをそれに載せ替えられる。
- AppShell のサイドバーはロール未設定ルートを全員に表示し、`role:"admin"` は admin のみ表示。App.tsx はルートの
  role を強制しないため、設定ページは内部で admin 以外に説明を表示している。

## 次の一手

1. detect-ai の `routes/sessions.py` マージ後、実データで timeline/indicators 形式を確認し、必要なら `normalizeIndicators` を簡素化。
2. useOpsLive → useLiveStream の統合と、共通部品の重複整理（上記）。
3. 画面の目視確認（`npm run dev` + `uv run tokiwa serve` + `tokiwa sim`）。本作業ではブラウザでの描画確認は未実施
   （型・lint・ビルド・単体テストのみ）。特に散布図の対数軸と帯、狭幅レイアウトを確認すること。
4. バンドルが 970KB（recharts 含む）。必要ならルート単位の lazy import を routes.ts 側で検討。
