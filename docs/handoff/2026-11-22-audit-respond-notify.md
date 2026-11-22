# 2026-11-22 監査対応レーン: respond-notify（系統 E「対処・通知」の工数 S）

担当 Issue（この順）: #63 → #64 → #118 → #128 + #168 → #130。
指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`（#63=L09-02, #64=L09-04, #118=L09-09, #128=L09-08,
#168=L17-06, #130=L09-12）。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #63 | 進行中 | backend: 新テーブル `response_suppressions`（`db/models/response_suppression.py`）と `respond/suppress.py`。却下・取り消しで抑止を記録（指定時 `suppress`＝自動提案を破棄、無指定でも `manual_only`＝`response.auto_approve_cooldown_minutes` 既定 24 時間は自動承認しない）。`create_proposal` が同じトランザクションで照合（IP/CIDR は重なり）。API: reject/revert の `suppress_hours`/`suppress_permanent`/`reason`、`GET/POST /response/suppressions`、`POST .../{id}/lift`。テスト `tests/respond/test_respond_suppression.py` | (backend) |
| #64 | 未着手 | | |
| #118 | 未着手 | | |
| #128 + #168 | 未着手 | | |
| #130 | 未着手 | | |

## 要判断

- **#63**: 人間が API から提案したものは `suppress` 中でも作成する（自動承認だけ禁止）。人間の明示的な提案を黙って捨てない
  ため。抑止を優先して 409 にする案もある。
- **#63**: 照合は「型 + 対象」。block_ip を抑止しても同じ IP の rate_limit / tarpit は提案される（指摘の推奨どおり）。
  「全種別を抑止」が要るなら `action_type` を任意にする拡張が必要。

## 既定動作の変更

- **#63**: 人間が却下・取り消した (型, 対象) は、その後 24 時間（`response.auto_approve_cooldown_minutes`）自動承認されない
  （提案は作られ、人間の承認を待つ）。以前は取り消した直後の次のアラートで同じ遮断が自動承認され再適用されていた。
  0 にすると旧動作。自動承認を使っていない構成では見た目の変化なし（抑止一覧に `manual_only` 行が増えるだけ）。

## 失敗した試み

## 担当外の変更

## 他レーンへの依頼

## 未検証事項
