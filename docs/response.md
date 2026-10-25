# 対処（Respond）・Gate ポリシー・通知

> 担当: respond モジュール。コード: `backend/src/tokiwa/respond/`, `backend/src/tokiwa/notify/`,
> `api/routes/{response,gate,notify}.py`。テスト: `backend/tests/respond/`, `backend/tests/notify/`。

## 1. ライフサイクル

```
proposed ──approve──▶ approved ──executor 成功──▶ active ──expires_at 経過──▶ expired
   │                     │                          └──revert──▶ reverted
   └──reject──▶ rejected  └──executor 失敗──▶ failed
（一回限りの notify / webhook: approved ──成功──▶ expired（result.one_shot = true））
```

| 遷移 | 誰が | 実装 |
|---|---|---|
| 提案 | ルール / LLM（triage）/ ユーザー（API）| `propose_action()` / `create_proposal()` |
| 承認 | analyst 以上（API）、またはポリシー（下記 2 条件）| `approve_action()`（`proposed` からのみ・原子的に） |
| 実行 | 承認直後に自動 | `_execute()`（**唯一の `Executor.apply` 呼び出し元**） |
| 却下 | analyst 以上 | `reject_action()`（`proposed` からのみ） |
| 取り消し | analyst 以上 | `revert_action()`（`active` かつ reversible のみ） |
| 期限切れ | `@periodic("response.expiry", 30s)` | `expire_due_actions()`（`active` のみ。何も実行しない） |

- すべての遷移を `record_audit` に記録（`response.propose / propose_duplicate / propose_rejected / approve /
  execute / execute_failed / reject / revert / revert_failed / expire`）。
- バス: 新規提案で `action.proposed`、以降の変化（重複マージ含む）は `action.updated`。
- 重複: 同一 `(action_type, 正規化 target)` が `proposed / approved / active` なら新規作成せず、理由を追記して既存を返す。
- 起動時、`approved` のまま `executed_at` が無い行（実行中にプロセス停止）は `failed` にする（**自動再実行しない**）。
- 実行直前に現在の設定で **再検証** する（提案後に protected_cidrs を追加した場合などは `failed`）。
- 取り消しは先に状態を `reverted` にしてから executor.revert を呼ぶ（Gate は次のポーリングで即解除）。
  revert が失敗したら `active` に戻し `result.revert_error` を記録、API は 502。
- 期限切れは状態を `expired` にしてから revert。revert 失敗は `result.revert_error` に記録（nft 要素はカーネル側 timeout でも消える）。

## 2. 安全性（FR-12）

1. **承認なしに実行されない**。`_execute()` は DB の行が `approved` かつ `approved_by` / `approved_at` 付きでなければ拒否。
   `approved` にするのは `approve_action()` だけで、呼び出し元は
   (a) `POST /response/actions/{id}/approve`（`AnalystUser`）と
   (b) `create_proposal()` 内の `if auto_approve_allowed(...)` のみ。
2. 自動承認は **2 キー**: `response.auto_approve_enabled = true` **かつ** 型が `response.auto_approve_actions` に含まれる。
   既定は off / 空。承認者は `approved_by = "policy"`。
3. executor が受け取るのは `ExecutionRequest`（正規化 IP/CIDR・パス・識別子、許可キーの型付き params、TTL 秒、
   incident/alert ID、前回 apply の結果）だけ。**提案理由（LLM の自由文かもしれない）は渡らない**。
   シェル文字列は作らない（nft は固定 argv テンプレート + `create_subprocess_exec`）。
4. API からの提案は `proposed_by` を強制的に `user` にする（`policy` / `llm` の詐称不可）。
5. 証明するテスト（`tests/respond/test_respond_safety.py`）:
   - 全 ActionType × 全提案元 × 自動承認が成立しない 3 パターンで、提案・バス・期限切れジョブ・Gate ポリシーを
     通しても executor が一度も呼ばれない。
   - 列挙された型だけが自動承認され、他は `proposed` のまま。
   - 未承認/却下済みの行で `_execute()` が拒否。同時承認 5 本でも実行は 1 回。
   - AST 検査: `Executor.apply` の呼び出しは `_execute` だけ、`_execute` は `approve_action` だけ、
     `approve_action` は API ルートと `auto_approve_allowed` ガード内だけ。respond 配下にシェル実行が無い。
   - API: 未認証 401、センサートークン 401、viewer 403。

## 3. 提案の検証（`respond/validate.py`）

| 型 | target | params（許可キー・既定） | TTL |
|---|---|---|---|
| block_ip | IP / CIDR | なし | 必須（既定 `default_ttl_minutes`、上限 `max_ttl_minutes` で切り詰め） |
| rate_limit | IP / CIDR | `requests_per_minute` int 1..100000（既定 `default_rate_limit_rpm`=60） | 同上 |
| tarpit | IP / CIDR | `delay_ms` int 1..30000（既定 `default_tarpit_delay_ms`=2000） | 同上 |
| deceive | IP / CIDR | なし | 同上 |
| nftables_block | **単一 IP** | なし | 同上（nft の element timeout にも使う） |
| deploy_canary | 絶対パス `/[A-Za-z0-9._~/-]*`（`..` `//` 不可） | `kind` ∈ decoy_path / honeytoken / ai_canary（既定 decoy_path） | 同上 |
| notify | IP / CIDR（正規化のみ）または識別子 `[A-Za-z0-9][A-Za-z0-9._:/@-]*` | `channel_id`（32 hex または `default`、任意） | なし（指定は無視・note） |
| webhook | IP / CIDR（ネットワーク対象と同じ保護チェック）または識別子 | `endpoint` = `response.webhook_urls` のキー（既定 `default`） | なし |

ネットワーク対象の拒否条件:
- IP/CIDR として解釈できない（ホスト名・空白・`;`・スコープ ID `%` 等）。
- `min_prefix_v4`（16）/ `min_prefix_v6`（48）より広い（`0.0.0.0/0` 等）。
- 未指定アドレス・マルチキャスト・`255.255.255.255`。
- `protected_cidrs`（既定 `127.0.0.0/8`, `::1/128`）と **重なる**（内包・被内包の両方向）。
- `protect_server_addresses=true`（既定）のとき、サーバー自身のインタフェースアドレス（psutil、キャッシュ）。
- `block_private_targets=true` のとき、プライベート / ULA / リンクローカル（管理網保護。ラボでは既定 off）。

正規化: ホストビットを落とす（`203.0.113.77/24` → `203.0.113.0/24`）、/32・/128 は素のアドレス、
IPv4-mapped IPv6 は IPv4 に。未知の params キー、型違い（bool / 文字列の数値）は拒否。

`propose_action()` は検証失敗で `None` を返し `response.propose_rejected` を監査に残す。API は 422 + 理由。

## 4. 実行器（`respond/executors.py`）

| 型 | 動作 | revert |
|---|---|---|
| block_ip / rate_limit / tarpit / deceive | DB 状態のみ（`active` 行が Gate ポリシーに入る）。冪等 | 状態変更で解除 |
| deploy_canary | `tokiwa.deception.service.create_asset(DeceptionAssetIn)` を呼び `result.asset_id` を保存。モジュール/関数が無ければ失敗 | `delete_asset(id)`（無ければ `disable_asset(id)`） |
| notify | `notify.service.send_action_notice()`: 全有効チャネル（または `channel_id`）へ。閾値・重複抑制を無視。本文は検証済みフィールドのみ | 不可 |
| webhook | `response.webhook_urls[endpoint]` へ固定 JSON（`source, event, action_id, action_type, target, ttl_seconds, incident_id, alert_id`）。SSRF ガード | 不可 |
| nftables_block | `response.nftables_enabled=false` なら **必ず失敗**。true なら `nft add element inet tokiwa blocklist { <ip> timeout <ttl>s }`（IPv6 は `blocklist6`）を argv 配列で実行 | `nft delete element ...`（無効化中は実行せずスキップ） |

### nftables を使う場合の事前準備（管理者が手動で）

TOKIWA はテーブル/セット/ルールを作らない（要素の追加・削除だけ）。例:

```bash
nft add table inet tokiwa
nft add set inet tokiwa blocklist  '{ type ipv4_addr; flags timeout; }'
nft add set inet tokiwa blocklist6 '{ type ipv6_addr; flags timeout; }'
nft add chain inet tokiwa input '{ type filter hook input priority 0; policy accept; }'
nft add rule inet tokiwa input ip  saddr @blocklist  drop
nft add rule inet tokiwa input ip6 saddr @blocklist6 drop
```

TODO(verify): 対象ディストリの nft バージョンで上記構文と、非 root 実行時の権限付与（`CAP_NET_ADMIN` 等）を確認すること。

## 5. Gate ポリシー（`GET /api/v1/gate/policy`, token scope `gate`）

- 対象: `status=active` かつ `expires_at` が未来（または無し）の block_ip / rate_limit / tarpit / deceive。
  期限切れジョブ実行前でも期限を過ぎたものは含めない。
- `blocked` / `deceive`: アドレスファミリごとに `ipaddress.collapse_addresses`（重複・内包・隣接を統合）、v4 → v6 の昇順。
- `rate_limited`: 同一キーは最小 rpm（厳しい方）。`tarpit`: 同一キーは最大 ms（上限 30000）。
- `decoys` / `html_injection`: `tokiwa.deception.policy.build_gate_decoys()` の結果。例外時はデコイ無しで配信（遮断は止めない）。
- `version`: 上記内容（`generated_at` を除く）の正規化 JSON の SHA-256。内容が同じなら同じ値。
- `ETag: "<version>"` を返す。`If-None-Match` が一致すれば 304（本文なし）。Gate は使わなくてもよい。

## 6. 通知（`notify/`）

| 購読トピック | 送信条件 | 重複抑制キー |
|---|---|---|
| `alert.created` | チャネルの `min_severity` 以上 | `alert:<source_ip>`（無ければ fingerprint） |
| `incident.created` | 同上 | `incident:<id>` |
| `incident.updated` | **重大度が上がった時のみ**（直前の重大度はメモリ保持。再起動直後は基準なしで送らない） | `incident:<id>` |
| `action.proposed` | 承認依頼（severity=high 扱い）。`notify_action_proposals=false` で停止。ポリシーで自動承認済みなら「自動承認」文面 | `action:<type>:<target>` |

- 重複抑制: 同じキーは `notify.dedup_minutes`（既定 10 分）に 1 回。ただし **前回より重大度が高ければ送る**。
  少なくとも 1 チャネルへ配送成功した時だけ窓を開始。状態はメモリ（再起動で最大 1 通余分に送る程度）。
- チャネル: DB の有効チャネル + `notify.default_webhook_url`（暗黙の webhook、id `default`、閾値 `default_min_severity`、
  API の一覧には出ない。`POST /notify/channels/default/test` でテスト可）。
- 本文: 日英テンプレート（`notify.language` = ja / en / both）。UI リンクは `notify.public_ui_url` +
  `/alerts/<id>`, `/incidents/<id>`, `/response?action=<id>`。制御文字除去・長さ上限。

### チャネル設定とペイロード

| kind | config | ペイロード |
|---|---|---|
| webhook | `url`, `headers`（任意、値は秘密） | `{source:"tokiwa", kind, severity, title, text, url, fields, data, sent_at}` |
| slack | `url`（Incoming Webhook） | `{text, blocks:[header, section(mrkdwn), section(fields), context(link)]}`。`< > &` をエスケープ（`<!channel>` 等を無効化） |
| discord | `url` | `{username:"TOKIWA", embeds:[{title, description, url, color, fields, timestamp}], allowed_mentions:{parse:[]}}` |
| email | `host, port(587), from_addr, to_addrs[], username?, password? / password_env?, starttls(true), ssl(false), timeout_seconds` | text/plain。smtplib を `asyncio.to_thread` で実行 |

- 秘密のマスク: `url` → `https://<host>/********`、`password` → `********`、`headers` の値 → `********`。
  PATCH でマスク値をそのまま返すと既存の秘密を保持する。エラーメッセージに URL のパス（トークン）を含めない。
- メールのパスワードは `password_env`（環境変数名）推奨（DB に秘密を置かないため）。
- SMTP にはプライベート宛先拒否を適用しない（社内リレーが一般的なため）。

### SSRF ガード（webhook / slack / discord / webhook executor 共通: `notify/outbound.py`）

- スキームは http / https のみ。リダイレクトは追わない（3xx は失敗）。
- 許可ホスト（`notify.allowed_hosts` / `response.webhook_allowed_hosts`）: `example.com` は完全一致、`.example.com` はサブドメイン含む。空なら制限なし。
- `notify.block_private_destinations` / `response.webhook_block_private`（既定 true）: 名前解決した **全** アドレスが
  グローバルユニキャストでなければ拒否（ループバック・RFC1918・リンクローカル/メタデータ・CGNAT・ULA・予約・IPv4-mapped）。
- 残存リスク: 名前解決と httpx の接続の間の DNS リバインディング。厳格な環境では許可ホストを設定する。

## 7. 設定（調整できるところ）

`response.*`（`ResponseSettings`）:

| キー | 既定 | 意味 |
|---|---|---|
| auto_approve_enabled / auto_approve_actions | false / [] | 自動承認の 2 キー |
| default_ttl_minutes / max_ttl_minutes | 60 / 10080 | TTL 既定と上限（超過は切り詰め、`result.validation_notes` に記録） |
| protected_cidrs | 127.0.0.0/8, ::1/128 | 絶対に対象にしない範囲（管理端末・監視系・上流 LB を足す） |
| protect_server_addresses | true | サーバー自身の IP を保護 |
| block_private_targets | false | プライベート宛を拒否（本番の管理網保護） |
| min_prefix_v4 / min_prefix_v6 | 16 / 48 | 広すぎる CIDR の拒否 |
| default_rate_limit_rpm / default_tarpit_delay_ms | 60 / 2000 | params 省略時の値 |
| webhook_urls | {} | webhook executor の名前付き宛先 |
| webhook_allowed_hosts / webhook_block_private / webhook_timeout_seconds | [] / true / 10 | SSRF ガード・タイムアウト |
| nftables_enabled / nftables_binary | false / nft | nft executor |

`notify.*`（`NotifySettings`）: `default_webhook_url`, `default_min_severity`, `public_ui_url`, `language`（both）,
`dedup_minutes`（10）, `notify_action_proposals`（true）, `allowed_hosts`, `block_private_destinations`（true）,
`http_timeout_seconds`（10）。

## 8. API

`docs/api-contract.md`「対処」「Gate ポリシー」「通知」を参照。補足:
- `GET /response/actions/{id}`（user）を追加。
- 状態違反は 409、検証エラーは 422、revert の executor 失敗は 502、見つからない 404。
- `POST /response/actions/{id}/approve` は実行結果を含めて返す（`active` / `expired`(one-shot) / `failed`）。
- `DELETE /notify/channels/{id}` は 204。

## 9. 既知の制約・今後

- 二人承認（提案者と別人の承認）は未実装。必要なら `approve_action` で `actor != 提案者` を強制する。
- deception の `create_asset` / `delete_asset` の正式な関数名は deception モジュールと要合意（現状はダックタイピング）。
- 通知の重複抑制・インシデント重大度の記憶はプロセス内メモリ（複数プロセス構成では共有されない）。
- `action.proposed` の承認依頼に含める提案理由（LLM 由来の可能性あり）は人間向け表示のみ。エスケープ・長さ制限済み。
