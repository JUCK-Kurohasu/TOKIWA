# 2026-11-23 監査対応レーン: frontend-followups（第 2・3 弾で UI が未作成のまま残ったもの + triage の lost update）

担当（この順）: lost update（自動トリアージ中の誤検知化が `triaging` に戻る）→ #166 / #173 の UI → #132 の UI → #40 の UI。
前提の NOTES: `2026-11-22-audit-web-detect.md`（#166/#173 の API・lost update の再現）、`2026-11-22-audit-sensors.md`（#132）、
`2026-11-21-audit-tokens-roles.md`（#40 の出所ラベル）。

## 対応状況

| 項目 | 状態 | 何をしたか | コミット |
|---|---|---|---|
| lost update（Issue 未登録。web-detect レーンが再現） | 完全 | `triage/service.py` の `_triage_alert`: 状態の書き込みを条件付き UPDATE に。(1) `new → triaging` は `WHERE status='new'`（ORM の `row.status = ...` は無条件 UPDATE になるので廃止）。自動トリアージで 0 行（読んだ後に人間が変えた）なら LLM を呼ばずに終える。(2) 判定の保存は 1 文で `triage` は常に書き、`status` は `CASE WHEN status IN ('new','triaging') THEN 'triaged' ELSE status END`。保存後に行を読み直してから `alert.updated` を publish（以前は古い状態を流しえた）。(3) 実行中に誤検知へ変わったアラートからは対処を提案しない（実行開始時に既に誤検知だった強制再トリアージは従来どおり）。テスト `tests/triage/test_triage_status_race.py`（コンテキスト読込中の FP・LLM 呼び出し中の FP・acknowledged・通常の new→triaging→triaged・FP の強制再トリアージ・取り込み直後の PATCH の E2E）。修正前のコードで E2E は 3/3 失敗、修正後は成功を確認 | （このコミット） |
| #166 / #173 UI | 未着手 | | |
| #132 UI | 未着手 | | |
| #40 UI | 未着手 | | |

## 要判断

- （lost update）実行中に人間が誤検知にしたアラートからは、トリアージ結果に対処の推奨があっても提案を作らない。インシデント側
  （`_triage_incident`）の提案は今回変えていない（状態を書かないので lost update は無い。インシデントを誤検知にした直後に提案が出うる点は残る）。

## 既定動作の変更

- （lost update）自動トリアージの途中でアナリストがアラートの状態を変えたら（誤検知・確認済み・解決など）、その状態が残る
  （以前は `triaged` に戻りえた）。読込直後に変わっていた場合、自動トリアージは LLM を呼ばずに終える（費用が掛からない。判定は空のまま）。
  強制再トリアージ（`POST /alerts/{id}/triage`）は状態に関係なく最後まで走り、判定を保存するが状態は変えない（triaging / new のときだけ triaged に）。
- （lost update）実行中に誤検知へ変わったアラートからは block_ip / rate_limit 等の提案を作らない。

## 失敗した試み

## 担当外の変更

## 他レーンへの依頼

- detect（web-detect の後任）: `tests/detect/test_alert_suppression.py` の `_no_auto_triage`（lost update 回避のため自動トリアージを
  切っていた autouse フィクスチャ）は、この修正で不要になった。外すかどうかは detect 側の判断（このレーンでは触っていない）。

## 未検証事項

- （lost update）PostgreSQL での挙動は未確認（SQLite WAL のみ）。READ COMMITTED では条件付き UPDATE の WHERE が最新の確定行で
  再評価されるので、同じ結果になるはず（推論）。
