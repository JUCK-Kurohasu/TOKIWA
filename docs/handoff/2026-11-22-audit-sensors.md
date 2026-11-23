# 2026-11-22 監査修正 — sensors レーン（系統 H センサー・インテル、工数 S）

担当: #70 #121 #123 #131 #132 + 未登録（Zeek `username` ほか、Refs #169）。
所有: `backend/src/tokiwa/sensors/`、`intel/`（#132 のみ）、`config.py` の `AgentSettings`、`docs/wiki/Sensors*.md`、
`backend/tests/sensors/`・`tests/intel/`。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #70 cmdline マスキング | 完全 | `sensors/cmdline.py`（argv 単位の専用マスカー）をホストセンサーで `redact_text` の前に適用。`agent.send_cmdline`（既定 true）で cmdline 自体を送らない選択。Copilot の `event_brief` も同じマスカーを通す（旧エージェント・他経路で入った未マスク値対策） | 9e76359 |
| #121 新規接続上限 | 部分 | 上限超過時は優先度順（ESTABLISHED > SYN_RECV、outbound > inbound > loopback、プロセス付き > 無し）に報告し、超過分は既知扱いにせず次周期へ持ち越す（seen = 既報告で継続中 ∪ 今回報告分）。PORT_SNAPSHOT に `connections_new` / `connections_truncated` と `degraded=connections_truncated`、新検知器 `sensor.connections_truncated`（medium、送信元 IP なし＝対処提案の対象にならない）。上限は既存の `agent.max_connections_per_cycle` | c053ad2 |
| #123 Suricata to_client | 部分 | alert の source/destination を「攻撃側 / 被攻撃側」にする: (1) `alert.source`/`alert.target`（ルールの `target` キーワード）を優先、(2) `direction=to_client` かつ `metadata.attack_target` が `Client_Endpoint` ならパケット方向のまま（悪性サーバー → 自社クライアント。公式例）、(3) その他の `to_client` は入れ替え（フロー開始側＝クライアントを攻撃者に）、(4) それ以外はパケット方向。`labels` に `suricata.direction` / `suricata.attribution` / `suricata.swapped`、元の方向は raw に残る。公式例を含む fixture `suricata_eve_direction.json`。残り: 推奨 (2) net_ids の attacker/victim 分離、(3) 資産台帳の保護対象を protected_cidrs に — 他レーン | (#123) |
| #131 ログ書式・時刻 | 未着手 | | |
| #132 withdrawn アドバイザリ | 未着手 | | |
| 未登録 Zeek username（Refs #169） | 未着手 | | |

## 要判断

- #70: 監査の推奨は `send_cmdline` 既定 False。**既定は true（マスク済みで送る）のまま**にした — cmdline は Sigma（`process.command_line`）と
  デセプション照合（`process.cmdline`）が使っており、既定で消すと検知が減るため。秘密を argv に置く運用が多い環境では
  `TOKIWA_AGENT__SEND_CMDLINE=false` を推奨（Wiki に記載）。既定を false にするかはユーザー判断。

## 既定動作の変更

## 失敗した試み

## 担当外の変更

- `backend/src/tokiwa/detect/detectors/sensor_health.py`（新規ファイル。拡張点への追加のみ）: `sensor.connections_truncated`（#121）。

- `backend/src/tokiwa/copilot/tools.py`（copilot レーン）: `event_brief` の `process.cmdline` を `tokiwa.sensors.cmdline.mask_argv` に通す 2 行 + import 1 行（#70）。
- `backend/src/tokiwa/config.py`: `AgentSettings` に項目追加のみ（自セクション）。

## 他レーンへの依頼

- （#123 残り）detect / respond レーン: `net_ids` の entities に attacker_ip / victim_ip を分けて持ち、対処提案を attacker 側だけにする（推奨 (2)）。
  既定の `protected_cidrs` に資産台帳の保護対象サーバー IP を含める（推奨 (3)）。本レーンの修正で Event.source が攻撃側になったので、
  現状の `source_ip` ベースでも to_client の主要ケースは正しくなった。

- （#121 残り）監査推奨 (2) の「SYN_RECV を件数サマリ（ポート別・送信元数）に集約し個別イベントにしない」は未対応。現状は優先度で後回しにするだけで、
  持続的な SYN フラッドでは毎周期 1000 件の SYN_RECV イベントが送られる（取り込み負荷）。集約はイベント形（新 dataset）を伴うので別タスク。

- llm レーン: `llm/redact.py` の `url_credentials` はユーザー名が空の URL（`redis://:pw@host`）を拾わない（`([^/\s:@]+)` が 1 文字以上を要求）。
  cmdline はセンサー側で補ったが、nginx / Gate のクエリ等は未対応。`([^/\s:@]*)` にすれば直る。
- api レーン: `POST /api/v1/ingest/events` はサーバー側で cmdline をマスクしない（data-handling で既出）。ingest 時に
  `tokiwa.sensors.cmdline.mask_argv` を `process.cmdline` / `network.process.cmdline` / `port.listeners[].process.cmdline` に掛ければ旧エージェントも救える。

## 未検証事項

- #123: docs.suricata.io はこのサンドボックスから名前解決できず、代わりに GitHub の一次資料（master, 2026-11 取得）で確認した:
  `OISF/suricata/doc/userguide/output/eve/eve-json-format.rst`（alert 例: `direction: "to_client"`, `flow.src_ip` = フロー開始側,
  `metadata.attack_target: ["Client_Endpoint"]`、「`alert.source` / `alert.target` は target キーワード使用時」）、`doc/userguide/rules/meta.rst`
  （`target:[src_ip|dest_ip]`）、`src/output-json-alert.c`（`AlertJsonSourceTarget` が `source`/`target` に `ip`/`port`、`direction` は
  `FLOW_PKT_TOSERVER` で決まる、alert の `src_ip` はパケット方向）。TODO(verify): `direction` が alert に入った版（7.0?）、
  eve の alert `metadata` 出力が無効だと (2) が効かず (3) に落ちる（自社クライアントがマルウェア配布サーバーから受けたアラートで
  クライアントが「攻撃者」になる。ET 以外のルールセットでも同様）、ET の `attack_target` の他の値（`Client_and_Server` 等）は未確認のため使っていない。

- #70 のマスク対象は代表的なツールの既知オプション（mysql 系 `-pX`、`sshpass -p`、`redis-cli -a`、`mongosh -p`、`openssl -k` / `pass:`、
  `curl -u`、`smbclient -U user%pass`、名前に password/secret/token/api-key 等を含む長いオプション、`*_KEY=` 等の環境変数代入）。
  **未対応（意図的）**: スキーム無し `user:pass@host`（impacket 形式。`image:tag@sha256:` と衝突）、位置引数のパスワード（`htpasswd -b`、
  `sqlplus u/p@db`）、1 ダッシュの長いオプション（`keytool -storepass`）、`xfreerdp /p:`、curl `-b/--cookie`、引用符内の空白を含む秘密
  （`'my secret'` の後半）、`-` で始まる値。
- #70 トレードオフ: `--api-key <canary>` のように引数で渡されたハニートークンは伏字になりデセプション照合に掛からなくなる
  （既存の `key=value` を伏字にする設計と同じ扱い。docs/deception.md「観測可能性」）。位置引数・URL パスに入ったカナリアは従来どおり見える。

## メモ

- 統合担当より: `tests/deception/test_deception_variants.py::test_canary_header_with_unknown_value_is_an_attempt[typo]` は
  テスト自体の原因でまれに落ちる（上流 852caf6 で修正済み）。全体スイートで見えても本レーンの変更とは無関係。
