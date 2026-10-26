# 2026-10-22 frontend-ops 作業ログ（アラート・インシデント・対処・デセプション）

担当: `docs/tasks/frontend-ops.md` / ブランチ: `worktree-agent-ad9bc2f796d3b3c82`（skeleton `c4881e1` に fast-forward してから作業）

## やったこと

| 画面 | パス | 内容 |
|---|---|---|
| Alerts 一覧 | `/alerts` | フィルタ（状態・重大度・カテゴリ・送信元・AI スコア下限・検索）を URL クエリに保持、クイックチップ（未対応 / AI ≥70% / デセプション）、表（重大度・タイトル・カテゴリ・送信元・件数・AI スコア・状態・最終検知）、一括状態変更、ページング、`incident_id` 絞り込み |
| Alert 詳細 | `/alerts/:id` | 説明・エンティティ・MITRE（attack.mitre.org リンク）・証拠イベント（HTTP 整形、LLM 引用バッジ、取得不能 ID の件数表示）・検知詳細 JSON・**LLM トリアージパネル**・再トリアージ（fast/deep）・状態変更・手動の対処提案。`triaging` 中は 5 秒ポーリング |
| Incidents 一覧 | `/incidents` | 状態・重大度・アクター種別フィルタ、AI エージェント行を紫で強調、キルチェーン簡易表示 |
| Incident 詳細 | `/incidents/:id` | アクター判定カード（AI エージェントは紫で大きく、LLM の根拠を列挙）、ATT&CK 14 戦術のキルチェーン（観測順の番号・到達段階・LLM 判定段階）、関連アラート、対処（承認/却下/取り消し）、手動提案、トリアージパネル、担当者/状態変更、「コパイロットに聞く」（`/copilot?incident=<id>`） |
| Response | `/response?tab=` | 承認待ち / 実行中 / 履歴。承認ダイアログで実行内容・TTL・LLM 提案の注意を表示、却下（理由は任意・監査ログ）、取り消し、TTL 残り時間バー、KPI。「承認なしでは実行されません」を常時表示 |
| Deception | `/deception?tab=` | 資産一覧（種類・パス・カナリア値（マスク）・トリップ数・最終トリップ・有効切替・プレビュー・削除確認）、種類別の作成ダイアログ（作成後にプレビューを開く）、プレビュー（本文はテキスト表示・トークンを強調）、トリップ履歴（行展開で EventDetail）、**AI カナリアの判定条件の説明** |

共有コンポーネント（すべて新規ファイル）:
- `frontend/src/components/common/TriagePanel.tsx` — TriageResult の全項目 + 出所（tier/model/prompt_version/llm_call_id/escalated/rejected_evidence_ids）。推奨対処 →「提案として作成」（`POST /response/actions`）
- `frontend/src/components/common/EventDetail.tsx` — `EventDetail` / `EvidenceList` / `HttpView`。テレメトリは攻撃者制御データなので **テキストとしてのみ描画**（`dangerouslySetInnerHTML` なし、ペイロード内 URL はリンク化しない）
- `frontend/src/components/common/KillChain.tsx` — `KillChain` / `KillChainMini` / `normalizeTactic`（snake_case・表示名・TA ID を正規化、未知値は「その他」）
- `frontend/src/components/common/ResponseActions.tsx` — `ActionCard`、承認/却下/取り消しダイアログ、`ProposeActionDialog`、`ApprovalNotice`、状態/提案元バッジ
- `frontend/src/components/common/OpsKit.tsx` — 状態バッジ、Pager、DebouncedInput、Meter、MetaItem、MitreChips、Notice、FilterChip 等
- `frontend/src/components/common/opsLabels.ts` — 列挙値の日英ラベル、`useCanOperate`（analyst/admin のみ操作可、viewer は閲覧のみ）、`fmt`、`mitreUrl`、`useNow`
- `frontend/src/components/common/useOpsLive.ts` — `/stream` SSE を購読しトピック接頭辞（`alert.` / `incident.` / `action.` / `deception.`）で Query を無効化（デバウンス）。`/stream` が 404 でも画面は壊れない
- `frontend/src/api/types-ops.ts` — `AlertUpdate` / `IncidentUpdate` / `ActionProposal` / `DeceptionAssetIn` / `DeceptionPreview` / 列挙配列

**共有ファイルの変更: なし**（index.tsx・routes.ts・App.tsx・AppShell.tsx・client.ts・types.ts は未編集、依存追加なし）。

## 現在の状態
- `npm run typecheck && npm run lint && npm run build` 緑。
- 実バックエンド未完成のため、契約どおりの形のモック API（リポジトリ外）+ Playwright で全画面を巡回し、一括変更・推奨対処からの提案・再トリアージ・承認・却下・資産作成・プレビュー・トリップ展開を操作確認。ページ例外なし（console エラーはモックに意図的に置いていない `/stream` の 404 と、存在しないアラート ID のテストのみ）。スクリーンショット等の成果物はコミットしていない。

## API 前提（バックエンド担当と要すり合わせ）
1. `GET /response/actions` の `status` は **単一値** と解釈。タブごとに状態別に並列取得してマージし、クライアント側でも状態で再フィルタ（フィルタ無視の実装でも表示は正しい）。1 状態あたり最大 100 件、履歴は「さらに読み込む」で limit 増加（上限 500）。
2. トリアージの推奨対処から作る提案は `proposed_by: "llm"`、手動提案は `"user"`。サーバーが上書きする方針ならそれで良い（クリックした人は監査ログ側で記録される想定）。
3. `POST /response/actions/{id}/approve` は executor 実行後の `ResponseAction` を返す想定。`status=failed` の理由は `result.error`（なければ `result.message`）を表示。
4. `PATCH /deception/assets/{id}` は部分更新（UI は `{enabled}` のみ送信）。
5. `PATCH /incidents/{id}` で `assignee: null` を送ると担当解除される想定（`exclude_none` 実装だと解除できない）。
6. `POST /incidents/{id}/triage` はティア指定なし（契約どおり）。アラートは `?tier=fast|deep`。
7. トリップ（`GET /deception/trips`）は `Event.deception.{asset_id, asset_kind, token}` を参照し、資産名は `GET /deception/assets` と突き合わせ。
8. `GET /deception/preview/{id}` は analyst 以上 → viewer はプレビューボタン無効。
9. 一覧の検索 `q`・`min_ai_score` は文字列のまま送信（例 `0.7`）。

## TODO(verify)
- `content_template` のプレースホルダ構文（deception モジュールが決める）。UI では構文を示さず「空欄で既定テンプレート、プレビューで確認」と案内している。
- AI カナリア説明文中のヘッダ名 `X-Debug-Auth` / パス `/api/internal/<token>` は **例示**（UI にも明記）。実際の文言は deception 実装・設定に合わせて調整可。
- リンク先 `/sessions/:id`（frontend-core）、`/copilot?incident=`（frontend-intel のタスク仕様に記載）の実在。

## 他モジュールへの依頼
- frontend-core: `hooks/useLiveStream.ts` が入ったら `components/common/useOpsLive.ts` を置き換え/統合して SSE 接続を 1 本にしたい。
- respond: 失敗理由は `result.error` に文字列で入れてもらえると UI にそのまま出る。
- triage-correlate: `Incident.kill_chain` は AttackStage の snake_case 推奨（表示名・TA ID も UI 側で吸収はする）。

## 調整できる箇所
- AI 強調のしきい値: 0.7（一覧・詳細）、インシデントの「AI エージェントの疑い」は 0.5（`IncidentDetail.tsx`）。
- ポーリング間隔: 一覧 30 秒、対処 30 秒、デセプション資産 60 秒、トリアージ中 5 秒。
- ラベル・説明文: `components/common/opsLabels.ts` と各ページの `strings`（日英）。

## 次の一手
1. 実バックエンドと結合して API 前提 1〜9 を確認・修正。
2. vitest でラベル/正規化（`normalizeTactic`, `mitreUrl`, `formatDuration`）の単体テスト追加。
3. SSE フックの統合（上記依頼）。
