# 2026-11-23 監査対応レーン: frontend-followups（第 2・3 弾で UI が未作成のまま残ったもの + triage の lost update）

担当（この順）: lost update（自動トリアージ中の誤検知化が `triaging` に戻る）→ #166 / #173 の UI → #132 の UI → #40 の UI。
前提の NOTES: `2026-11-22-audit-web-detect.md`（#166/#173 の API・lost update の再現）、`2026-11-22-audit-sensors.md`（#132）、
`2026-11-21-audit-tokens-roles.md`（#40 の出所ラベル）。

## 対応状況

| 項目 | 状態 | 何をしたか | コミット |
|---|---|---|---|
| lost update（Issue 未登録。web-detect レーンが再現） | 完全 | `triage/service.py` の `_triage_alert`: 状態の書き込みを条件付き UPDATE に。(1) `new → triaging` は `WHERE status='new'`（ORM の `row.status = ...` は無条件 UPDATE になるので廃止）。自動トリアージで 0 行（読んだ後に人間が変えた）なら LLM を呼ばずに終える。(2) 判定の保存は 1 文で `triage` は常に書き、`status` は `CASE WHEN status IN ('new','triaging') THEN 'triaged' ELSE status END`。保存後に行を読み直してから `alert.updated` を publish（以前は古い状態を流しえた）。(3) 実行中に誤検知へ変わったアラートからは対処を提案しない（実行開始時に既に誤検知だった強制再トリアージは従来どおり）。テスト `tests/triage/test_triage_status_race.py`（コンテキスト読込中の FP・LLM 呼び出し中の FP・acknowledged・通常の new→triaging→triaged・FP の強制再トリアージ・取り込み直後の PATCH の E2E）。修正前のコードで E2E は 3/3 失敗、修正後は成功を確認 | fee2f0c |
| #166 / #173 UI | UI は完全（Issue としては部分。下記） | `frontend/src/pages/alerts/`: (1) `FalsePositiveDialog.tsx` — 状態を誤検知にすると開く。再発の抑制を「サーバー既定（初期選択、`suppress` を送らない）/ 抑制しない（`suppress:false`）/ 時間指定（`suppress_hours`、1〜8760）/ 恒久（`suppress_permanent`）」、「送信元を問わない」（`suppress_any_source`、攻撃も黙る旨の警告付き）、理由（`reason`）。アラート詳細と一覧の一括変更の両方で使う（一括は以前、黙って既定の抑制を作っていた）。(2) 誤検知から戻すとき（詳細・一括）に「抑制も解除される」確認。(3) 誤検知のアラート詳細に、そのアラートから作られた抑制（`GET /alert-suppressions?source_alert_id=…&active=false`）と解除ボタン。(4) 新ページ `/alert-suppressions`（サイドバー「監視 → 抑制・許可リスト」、アラート一覧の右上にもリンク）: 種類タブ（すべて / 誤検知 / 許可リスト）・期限切れ・解除済みの表示切替・解除（analyst、確認付き）・**許可リスト作成は admin だけにボタン表示**（CIDR と期間が必須、ルール ID・パス任意、扱い downgrade / suppress、ルールを絞らないときは警告）。サーバー側の上限（`allowlist_max_hours`・/8・/32）は UI から読めないのでヒントで示し、422 の文言をそのまま表示。純粋関数は `suppression.ts`、テスト `suppression.test.tsx`（9 件）。wiki Web-UI ×4 に「アラート」の誤検知ダイアログと新節「抑制・許可リスト」 | （このコミット） |
| #132 UI | 未着手 | | |
| #40 UI | 未着手 | | |

## 要判断

- （#166 / #173 の Close 判断）UI は web-detect NOTES の「未作成」分をすべて作った。ただし Issue の推奨のうち次は未対応なので、
  **#166 / #173 は Refs のまま**が妥当: #166 推奨 (3)「rule_id ごとの FP 率をダッシュボードに」（集計 API が無い）、
  #173 推奨 (1)「良性コーパスを eval の回帰セットにして CI 条件に」（web-detect でも未実施）。#173 推奨 (3)「RFC1918 を『監査対象だが提案しない』」は
  web-detect が「許可リストで宣言する運用」と判断済み（既定にはしていない）。
- （#166 UI）誤検知ダイアログの初期選択は「サーバー既定」（`suppress` を送らない = `detection.fp_suppress_hours`、既定 168h）。
  サーバーの値は UI から読めないため、選択肢の文言に設定名と既定値を書いた。
- （lost update）実行中に人間が誤検知にしたアラートからは、トリアージ結果に対処の推奨があっても提案を作らない。インシデント側
  （`_triage_incident`）の提案は今回変えていない（状態を書かないので lost update は無い。インシデントを誤検知にした直後に提案が出うる点は残る）。

## 既定動作の変更

- （lost update）自動トリアージの途中でアナリストがアラートの状態を変えたら（誤検知・確認済み・解決など）、その状態が残る
  （以前は `triaged` に戻りえた）。読込直後に変わっていた場合、自動トリアージは LLM を呼ばずに終える（費用が掛からない。判定は空のまま）。
  強制再トリアージ（`POST /alerts/{id}/triage`）は状態に関係なく最後まで走り、判定を保存するが状態は変えない（triaging / new のときだけ triaged に）。
- （lost update）実行中に誤検知へ変わったアラートからは block_ip / rate_limit 等の提案を作らない。

## 失敗した試み

## 担当外の変更

- なし（#166 / #173 は `frontend/src/pages/alerts/` と wiki のみ）。サイドバーへの追加は `pages/alerts/route.tsx` の `routes` に 1 件（`routes.ts` は不変）。

## 他レーンへの依頼

- detect（web-detect の後任）: `tests/detect/test_alert_suppression.py` の `_no_auto_triage`（lost update 回避のため自動トリアージを
  切っていた autouse フィクスチャ）は、この修正で不要になった。外すかどうかは detect 側の判断（このレーンでは触っていない）。

## 未検証事項

- （lost update）PostgreSQL での挙動は未確認（SQLite WAL のみ）。READ COMMITTED では条件付き UPDATE の WHERE が最新の確定行で
  再評価されるので、同じ結果になるはず（推論）。
