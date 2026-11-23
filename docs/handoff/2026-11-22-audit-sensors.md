# 2026-11-22 監査修正 — sensors レーン（系統 H センサー・インテル、工数 S）

担当: #70 #121 #123 #131 #132 + 未登録（Zeek `username` ほか、Refs #169）。
所有: `backend/src/tokiwa/sensors/`、`intel/`（#132 のみ）、`config.py` の `AgentSettings`、`docs/wiki/Sensors*.md`、
`backend/tests/sensors/`・`tests/intel/`。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #70 cmdline マスキング | 完全 | `sensors/cmdline.py`（argv 単位の専用マスカー）をホストセンサーで `redact_text` の前に適用。`agent.send_cmdline`（既定 true）で cmdline 自体を送らない選択。Copilot の `event_brief` も同じマスカーを通す（旧エージェント・他経路で入った未マスク値対策） | (#70) |
| #121 新規接続上限 | 未着手 | | |
| #123 Suricata to_client | 未着手 | | |
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

- `backend/src/tokiwa/copilot/tools.py`（copilot レーン）: `event_brief` の `process.cmdline` を `tokiwa.sensors.cmdline.mask_argv` に通す 2 行 + import 1 行（#70）。
- `backend/src/tokiwa/config.py`: `AgentSettings` に項目追加のみ（自セクション）。

## 他レーンへの依頼

- llm レーン: `llm/redact.py` の `url_credentials` はユーザー名が空の URL（`redis://:pw@host`）を拾わない（`([^/\s:@]+)` が 1 文字以上を要求）。
  cmdline はセンサー側で補ったが、nginx / Gate のクエリ等は未対応。`([^/\s:@]*)` にすれば直る。
- api レーン: `POST /api/v1/ingest/events` はサーバー側で cmdline をマスクしない（data-handling で既出）。ingest 時に
  `tokiwa.sensors.cmdline.mask_argv` を `process.cmdline` / `network.process.cmdline` / `port.listeners[].process.cmdline` に掛ければ旧エージェントも救える。

## 未検証事項

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
