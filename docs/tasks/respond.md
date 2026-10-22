# タスク: respond — 対処ワークフロー・Gate ポリシー・通知

## 目的
FR-12 / FR-10: 可逆な対処の提案 → 人間の承認 → 実行 → 期限切れ/取り消し。Gate が取得するポリシーの生成。
アラート/インシデント/承認待ちの通知。

## 担当範囲
- `backend/src/tokiwa/respond/`（service.py（stub を実装）, executors.py, policy.py, expiry.py, validate.py）
- `backend/src/tokiwa/notify/`（service.py, channels.py, render.py）
- `backend/src/tokiwa/api/routes/response.py`, `backend/src/tokiwa/api/routes/gate.py`, `backend/src/tokiwa/api/routes/notify.py`
- `backend/tests/respond/`, `backend/tests/notify/`、`docs/response.md`

## 要件
1. `propose_action(proposal)`: 検証（`validate.py`: target は IP/CIDR（block/rate_limit/tarpit/deceive/nftables）、
   `response.protected_cidrs` とサーバー自身/プライベート管理網の扱い、TTL 上限、params の許可キー）。
   同一 (type,target) の proposed/active があれば新規作成せず理由を追記。`action.proposed` publish。
   自動承認は `auto_approve_enabled` ∧ type ∈ `auto_approve_actions` のときのみ（approved_by="policy"）。
2. 承認/却下/取り消し API（analyst 以上）。承認 → executor 実行 → `active`、`expires_at = now + ttl`。
   すべて `record_audit`。**承認なしに executor が走るコードパスが無いことをテストで保証**（FR-12 受け入れ基準）。
3. executors（型ごと、`Executor.apply/revert` インタフェース）:
   - block_ip / rate_limit / tarpit / deceive: DB 状態のみ（Gate ポリシーに反映）。冪等。
   - deploy_canary: deception モジュールの API（`tokiwa.deception.service` があれば）で資産追加。無ければ失敗扱い。
   - notify: notify サービスで送信。webhook: 設定 URL へ JSON（SSRF 対策: 許可ホスト設定・プライベート IP 拒否オプション）。
   - nftables_block: `response.nftables_enabled` が False なら必ず失敗。True でも **固定テンプレート**
     （`nft add element inet tokiwa blocklist { <validated ip> timeout <ttl>s }`）を `asyncio.create_subprocess_exec`
     で引数配列として実行（シェル経由禁止）。テストでは実行関数をモック。
4. 期限切れジョブ `@periodic("response.expiry", every=30)`: active で expires_at 超過 → revert → expired。
5. Gate ポリシー `GET /api/v1/gate/policy`（scope gate）: active なアクションを `GatePolicy` に集約、
   `deception.policy.build_gate_decoys()` の結果を合成、内容ハッシュを `version` に。
6. 通知: チャネル（webhook/slack/discord/email(smtplib を to_thread)）。`alert.created`（severity ≥ チャネル閾値）、
   `incident.created/updated`（重大度上昇時のみ）、`action.proposed`（承認依頼）を購読。重複抑制（同じ対象は N 分に 1 回）。
   本文は日英テンプレート、UI へのリンク（`notify.public_ui_url`）。秘密は API で返さない（マスク）。
   `notify.default_webhook_url` があれば暗黙チャネルとして扱う。

## 受け入れ基準
- 提案の検証（保護 CIDR 拒否、TTL 上限）、状態遷移、承認なしで実行されないこと、期限切れ、ポリシー集約（CIDR/重複/version）。
- 通知: 閾値・重複抑制・チャネル別ペイロード形状（HTTP はモック）。
