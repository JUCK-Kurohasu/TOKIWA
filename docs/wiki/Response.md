> 🌐 **日本語** · [English](Response-en) · [中文](Response-zh) · [Español](Response-es)

# 対処（承認ワークフロー）

TOKIWA は脅威を見つけると対処を **提案** しますが、**人間が承認するまで何も実行しません**。
すべての遮断は期限付き（TTL）で、取り消せます。

## ライフサイクル

```
proposed（提案）──承認──▶ approved ──実行成功──▶ active（有効）──期限切れ──▶ expired
    │                        │                       └──取り消し──▶ reverted
    └──却下──▶ rejected      └──実行失敗──▶ failed
```

| 操作 | 誰が | 備考 |
|---|---|---|
| 提案 | LLM（トリアージ）/ ルール / ユーザー | 同じ種類・同じ対象の提案が既にあれば、新規に作らず理由を追記する |
| 承認・却下 | `analyst` 以上 | 承認すると即座に実行される |
| 取り消し | `analyst` 以上 | `active` かつ取り消し可能なもの |
| 期限切れ | 自動（30 秒ごとに確認） | TTL を過ぎたら解除 |

すべての操作は監査ログに記録されます。

## 対処の種類

| 種類 | 対象 | 何が起きるか |
|---|---|---|
| `block_ip` | IP / CIDR | Gate がその送信元に 403 を返す |
| `rate_limit` | IP / CIDR | Gate が 1 分あたりのリクエスト数を制限（既定 60）。超えると 429 |
| `tarpit` | IP / CIDR | Gate が応答を遅らせる（既定 2,000 ms、上限 30 秒） |
| `deceive` | IP / CIDR | Gate がその送信元へのすべての応答をデコイにする |
| `nftables_block` | 単一 IP | ホストの nftables のセットに追加（**既定で無効**） |
| `deploy_canary` | パス | デセプション資産（デコイ・ハニートークン・AI カナリア）を配置 |
| `notify` | — | 通知チャネルへ送信 |
| `webhook` | — | 設定済みの Webhook に固定形式の JSON を送信 |

Gate に関わる対処は、Gate が次にポリシーを取得したとき（既定 5 秒以内）に反映されます。

## 安全装置

1. **承認なしには実行されません**。実行処理は、承認済み（承認者と承認時刻つき）の行しか受け付けません。
   これはテスト（全種類 × 全提案元の組み合わせ、同時承認、コードの静的検査）で保証しています。
2. **LLM の自由文は実行系に渡りません**。実行器が受け取るのは、検証済みの種類・正規化された IP / CIDR・型付きパラメータ・TTL だけです。
   シェルのコマンド文字列は作りません。
3. 提案の検証で次のような対象は拒否されます。
   - IP / CIDR として解釈できないもの（ホスト名や `;` を含むものなど）
   - 広すぎる範囲（IPv4 で /16 より広い、IPv6 で /48 より広い。`0.0.0.0/0` など）
   - **保護対象**（`response.protected_cidrs`。既定 `127.0.0.0/8`、`::1/128`）と重なるもの
   - サーバー自身の IP アドレス（`response.protect_server_addresses`、既定 ON）
4. 実行の直前に、現在の設定で **もう一度検証** します（提案後に保護対象を追加した場合などは `failed` になります）。

> 💡 管理端末・監視システム・上流のロードバランサの IP は `response.protected_cidrs` に追加しておくことを強く勧めます。

## TTL（有効期間）

- 既定 60 分（`response.default_ttl_minutes`）、上限 7 日（`response.max_ttl_minutes`）。上限を超える指定は切り詰められます。
- 期限が来ると自動的に解除されます。

## 自動承認（既定 OFF）

特定の種類だけ承認を省略できます。**2 つの設定を両方** 有効にしたときだけ働きます。

```yaml
response:
  auto_approve_enabled: true
  auto_approve_actions: ["rate_limit", "tarpit"]   # ここに列挙した種類だけ
```

自動承認された対処の承認者は `policy` と記録されます。遮断（`block_ip`）の自動承認は、誤検知の影響が大きいので慎重に判断してください。

> 提案者と承認者を別人にする「二者承認」は、v0.1 ではまだ強制されません（次の開発フェーズで設定項目として追加予定）。

## nftables で遮断する（任意）

Gate を通らない通信も止めたい場合に使います。**既定では無効** で、有効にしない限り必ず失敗します。
TOKIWA はテーブル・セット・ルールを作らず、セットへの要素の追加・削除だけを行うので、管理者が事前に準備します。

```bash
nft add table inet tokiwa
nft add set inet tokiwa blocklist  '{ type ipv4_addr; flags timeout; }'
nft add set inet tokiwa blocklist6 '{ type ipv6_addr; flags timeout; }'
nft add chain inet tokiwa input '{ type filter hook input priority 0; policy accept; }'
nft add rule inet tokiwa input ip  saddr @blocklist  drop
nft add rule inet tokiwa input ip6 saddr @blocklist6 drop
```

その上で `TOKIWA_RESPONSE__NFTABLES_ENABLED=true` を設定します。上記の構文と、root 以外で実行する場合の権限
（`CAP_NET_ADMIN` など）は、お使いのディストリビューションで確認してください（未検証）。

## 通知

**設定 → 通知チャネル** で Webhook / Slack / Discord / メールを登録すると、次のタイミングで通知されます。

| きっかけ | 条件 |
|---|---|
| アラート作成 | チャネルの最低重大度以上 |
| インシデント作成 | 同上 |
| インシデント更新 | 重大度が上がったときだけ |
| 対処の提案 | 承認依頼として送る（`notify.notify_action_proposals` で停止可） |

- 同じ内容は 10 分に 1 回まで（`notify.dedup_minutes`）。ただし重大度が上がった場合は送ります。
- 通知の言語は `notify.language`（`ja` / `en` / `both`）。リンクには `notify.public_ui_url` を使います。
- **SSRF 対策**: 送信先は http / https のみで、リダイレクトは追いません。既定では、名前解決した結果がプライベート
  アドレス（ループバック・社内網・クラウドのメタデータなど）なら拒否します。許可するホストを
  `notify.allowed_hosts` で限定することもできます。
- メールのパスワードは DB に保存せず、`password_env`（環境変数名）で渡すことを勧めます。
