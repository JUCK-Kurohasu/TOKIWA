# 2026-11-22 監査修正 — sensors レーン（系統 H センサー・インテル、工数 S）

担当: #70 #121 #123 #131 #132 + 未登録（Zeek `username` ほか、Refs #169）。
所有: `backend/src/tokiwa/sensors/`、`intel/`（#132 のみ）、`config.py` の `AgentSettings`、`docs/wiki/Sensors*.md`、
`backend/tests/sensors/`・`tests/intel/`。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #70 cmdline マスキング | 完全（既定値だけ推奨と違う → 要判断） | `sensors/cmdline.py`（argv 単位の専用マスカー）をホストセンサーで `redact_text` の前に適用。`agent.send_cmdline`（既定 true）で cmdline 自体を送らない選択。Copilot の `event_brief` も同じマスカーを通す（旧エージェント・他経路で入った未マスク値対策） | 9e76359 |
| #121 新規接続上限 | 部分 | 上限超過時は優先度順（ESTABLISHED > SYN_RECV、outbound > inbound > loopback、プロセス付き > 無し）に報告し、超過分は既知扱いにせず次周期へ持ち越す（seen = 既報告で継続中 ∪ 今回報告分）。PORT_SNAPSHOT に `connections_new` / `connections_truncated` と `degraded=connections_truncated`、新検知器 `sensor.connections_truncated`（medium、送信元 IP なし＝対処提案の対象にならない）。上限は既存の `agent.max_connections_per_cycle` | c053ad2 |
| #123 Suricata to_client | 部分 | alert の source/destination を「攻撃側 / 被攻撃側」にする: (1) `alert.source`/`alert.target`（ルールの `target` キーワード）を優先、(2) `direction=to_client` かつ `metadata.attack_target` が `Client_Endpoint` ならパケット方向のまま（悪性サーバー → 自社クライアント。公式例）、(3) その他の `to_client` は入れ替え（フロー開始側＝クライアントを攻撃者に）、(4) それ以外はパケット方向。`labels` に `suricata.direction` / `suricata.attribution` / `suricata.swapped`、元の方向は raw に残る。公式例を含む fixture `suricata_eve_direction.json`。残り: 推奨 (2) net_ids の attacker/victim 分離、(3) 資産台帳の保護対象を protected_cidrs に — 他レーン | b82b27d |
| #131 ログ書式・時刻 | 完全 | (1) 読めない行（不正 JSON・ヘッダ無し Zeek TSV）と解釈できない時刻を `ParseStats` で数え、`LogSource.health_event()` が警告ログ＋`agent.health` イベント（初回は即時、以降 `agent.health_report_seconds`=300 秒ごとに差分）。新検知器 `sensor.log_parse_failures`（読めない行 medium / 時刻のみ low、送信元 IP なし）。意図的なスキップ（Suricata stats、アクセスログでない JSON、Zeek ヘッダ）は数えない。(2) nginx `escape=default` の `\xHH`（nginx ソースで確認）を復号して取り込み（`recovered` として計数・初回警告）。(3) `agent.log_timezone`（IANA / `+09:00` / UTC。不正値は起動時に ValidationError）。未設定時はオフセット無し時刻を従来どおり UTC とみなしつつ計数・警告（アラートはしない）。Caddy の wall 時刻、µs/ns エポックも解釈。時刻の未来ずれのクランプはサーバー側 #19 の既存処理 | 7f7f1b5 |
| #132 withdrawn アドバイザリ | 部分 | GHSA / OSV の取り下げを捨てずに `SourceResult.withdrawn` で渡し、`store.apply_withdrawals` が既存行に `data.withdrawn`（アドバイザリ ID → 日時）を記録。取り下げたアドバイザリがその feed のデータ提供元で、他の package feed が裏付けていなければ ecosystem 付きの affected を削除（NVD の CPE は残す）。他のソースが無い行（GHSA だけの行など）は affected を空にし `data.withdrawn_at`。更新理由 `withdrawn` で `intel.vuln_updated` を発行 → matcher が再照合し open の露出を `[auto-closed]` で mitigated に。未知 ID の取り下げは行を作らない。取り下げ解除（再公開）で印を消す。残り: UI の「取り下げ済み」バッジ（frontend）、OSV の取り下げが querybatch で返らない場合の扱い（未確認） | 3c3206a |
| 未登録 Zeek username（Refs #169） | 完全 | `_SENSITIVE_KEYS` に `username`（Zeek http.log。`base/protocols/http/main.zeek` で確認）・`remote_user`（nginx `$remote_user`）・`user_id`（Caddy アクセスログ。`modules/caddyhttp/server.go` で確認）を追加し raw で伏字。検知器・enricher が raw のこれらを読んでいないことを確認。Data-Handling（4 言語）の表も更新 | e8e1979 |

## 要判断

- #70: 監査の推奨は `send_cmdline` 既定 False。**既定は true（マスク済みで送る）のまま**にした — cmdline は Sigma（`process.command_line`）と
  デセプション照合（`process.cmdline`）が使っており、既定で消すと検知が減るため。秘密を argv に置く運用が多い環境では
  `TOKIWA_AGENT__SEND_CMDLINE=false` を推奨（Wiki に記載）。既定を false にするかはユーザー判断。

## 既定動作の変更

- #131: エージェントが `agent.health`（kind=custom）イベントを送るようになった（問題を数えたときだけ。最短 300 秒間隔）。
  dataset を縛ったトークン（`--dataset nginx.access` 等）でも 403 にならないよう、ingest は `agent.health` を縛りの例外にした
  （そうしないとバッチ全体が拒否され、シッパーが 403 を保持して詰まる）。
- #131: 新検知器 `sensor.log_parse_failures` / #121 `sensor.connections_truncated` がアラートを出す（どちらも送信元 IP 無し）。
  リポジトリの `tests/fixtures/logs/nginx_access.json` のように不正行を含むログを `agent once` で読むと health イベントが 1 件増える。
- #123: Suricata の to_client アラートで Event.source / destination が入れ替わる（net_ids の source_ip・相関・対処提案の対象が変わる）。

## 失敗した試み

- 特になし。`tests/sensors/` は `__init__.py` が無く兄弟テストモジュールを相対 import できないため、psutil の偽物はテストごとに持つ。

## 担当外の変更

- `backend/src/tokiwa/copilot/tools.py`（copilot レーン）: `event_brief` の `process.cmdline` を `tokiwa.sensors.cmdline.mask_argv` に通す 2 行 + import 1 行（#70）。
- `backend/src/tokiwa/api/routes/ingest.py`（api レーン）: `check_binding` で `agent.health` を dataset 縛りの例外に（定数 1 つ + 2 行、#131）。
- `backend/src/tokiwa/detect/detectors/sensor_health.py`（新規ファイル。拡張点への追加のみ）: `sensor.connections_truncated`（#121）・`sensor.log_parse_failures`（#131）。
- `backend/src/tokiwa/config.py`: `AgentSettings`（自セクション）に `send_cmdline` / `log_timezone`（+ validator）/ `health_report_seconds` を追加のみ。
- `docs/wiki/Configuration*.md`（共有）: Agent の表に `agent.send_cmdline` / `max_connections_per_cycle` / `log_timezone` / `health_report_seconds` の 4 行を追加のみ。
- `docs/wiki/Data-Handling*.md`（data-handling の成果物）: センサー表の nginx/Caddy・Zeek・ホストセンサーの 3 行を現状に合わせて修正（#169・#70）。

## 他レーンへの依頼

- （#132 残り）frontend: 脆弱性詳細・露出一覧で `vuln.data.withdrawn_at`（行全体が取り下げ）/ `vuln.data.withdrawn`（個別アドバイザリの取り下げ）を
  「取り下げ済み」バッジで表示。matcher の自動クローズ理由は従来の文言（"no longer matches current asset software / vulnerability data"）のまま。

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

- #169 追加調査で他に見つけた資格情報系の漏れ候補（未対応・判断材料）: Suricata EVE のペイロード出力（`payload_printable`、http-body 出力）は
  キー名ではなく本文なので `redact_text` のパターン頼み（`Authorization: Basic` や `password=` は伏字、独自形式は残る）。Zeek の ftp.log
  （`user`/`password`）や Suricata の ftp/smtp イベントはそもそも取り込まない。

- #132: GitHub の `GET /advisories`（`updated>=` で取得）が取り下げ済みアドバイザリを返し、取り下げ時に `updated_at` が更新されるかは
  一次情報で未確認（TODO(verify)。fixture には `withdrawn_at` 付きの例がある）。OSV は既知 ID の詳細を `modified` が新しいときだけ再取得する。
  OSV スキーマ上 withdrawn の設定は modified の更新を伴うはずだが、`/v1/querybatch` が取り下げ済みエントリを返すかは未確認 —
  返さない場合、OSV 由来の取り下げはこの経路では届かない（その OSV エントリの affected は残る）。
- #132: affected は出所なしの和集合なので、同じ CVE 行に複数の GHSA が畳み込まれ、データ提供元でない方が取り下げられた場合は印だけ付けて
  affected は変えない（重複 GHSA の取り下げで本物の露出を閉じないための保守的な選択）。

- #131: nginx の `escape=default` の挙動は nginx の `src/http/modules/ngx_http_log_module.c`（`ngx_http_log_escape`: 0x00-0x1F, `"`, `\`,
  0x7F 以上を `\xHH`、大文字 16 進）を GitHub から取得して確認。Caddy の `time_format` の `wall` 系の実際の出力形式
  （`2006/01/02 15:04:05.000`）は Go のレイアウト名からの推定で、実機出力は未確認（TODO(verify)）。

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
