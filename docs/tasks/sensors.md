# タスク: sensors — ホストセンサー・ログ/IDS アダプタ・ポート監視

## 目的
FR-01/02/03: リスニングポートと接続の定期収集、ベースライン逸脱検知、スキャン兆候検知。
加えて nginx/caddy の JSON アクセスログ、Suricata EVE、Zeek ログを `Event` に正規化して送る `tokiwa agent`。

## 担当範囲
- `backend/src/tokiwa/sensors/`（host.py, logtail.py, nginx.py, caddy.py, suricata.py, zeek.py, shipper.py, cli.py）
- `backend/src/tokiwa/enrich/ports.py`（PORT_SNAPSHOT → host_ports 更新 + PORT_CHANGE 派生イベント追加）
- `backend/src/tokiwa/detect/detectors/port_*.py`, `backend/src/tokiwa/detect/detectors/net_*.py`
- `backend/src/tokiwa/schemas/hosts.py`（HostPort, PortBaseline, HostSummary）
- `backend/src/tokiwa/api/routes/hosts.py`
- `backend/tests/sensors/`, `backend/tests/fixtures/logs/`（nginx/caddy/eve/zeek のサンプル）
- `lab/nginx/`（JSON ログ形式の nginx 設定例。lab-eval と調整、ファイル名は `lab/nginx/tokiwa-json.conf`）

## 要件
1. ホストセンサー（psutil、`asyncio.to_thread`）: listener（proto, bind_ip, port, pid, process name/exe/cmdline/user）
   と ESTABLISHED/SYN_RECV 接続を収集。`PORT_SNAPSHOT` を `interval_seconds` ごと、接続は差分または集計で
   `CONNECTION`。権限不足でプロセス情報が取れない場合は欠損として扱う（エラーにしない）。
2. シッパー: バッチ・リトライ（指数バックオフ）・オフライン時のメモリ内バッファ上限・`X-Tokiwa-Token`。
   `tokiwa agent run`（`AgentSettings` を使用、CLI オプションで上書き）。`tokiwa agent once --print`（1 回収集して
   標準出力に JSON、デバッグ用）。
3. ログアダプタ: ファイル tail（ローテーション対応: inode 変化/切り詰め検知、開始位置は末尾 or 先頭オプション）。
   - nginx: `log_format` JSON（推奨フィールドを `lab/nginx/tokiwa-json.conf` に定義）→ HTTP Event（dataset `nginx.access`）
   - caddy: 標準 JSON アクセスログ → HTTP Event（`caddy.access`）。ヘッダは redact
   - Suricata EVE: `alert` → IDS_ALERT, `http` → HTTP, `flow` → CONNECTION, `dns` → DNS
   - Zeek: `conn.log`, `http.log`, `notice.log`（TSV と JSON 両対応）
   すべて `tokiwa.llm.redact` でヘッダ・クエリの秘密をマスクしてから送る。raw は 4KB に切り詰め。
4. サーバー側 Enricher `ports`: PORT_SNAPSHOT を受けたら `host_ports` と比較して opened/closed/process_changed の
   PORT_CHANGE イベントを **events リストに追加**（同バッチで保存・検知される）。初回スナップショットは
   「学習」扱いで PORT_CHANGE を出さないオプション（既定: 出すが info）。
5. 検知器:
   - `port.unexpected_listener`（ベースライン外の新規 listener。0.0.0.0/:: バインドは重大度↑）
   - `port.public_exposure`（allow_public=false のポートが全インタフェースにバインド）
   - `port.process_changed`（既知ポートの所有プロセスが変化）
   - `net.port_scan`（同一送信元が窓内で多数の宛先ポート/ホストへ接続: CONNECTION/IDS/HTTP の dest_port から）
   - `net.ids_alert`（Suricata/Zeek のシグネチャをアラート化、severity マップ）
6. API `routes/hosts.py`（docs/api-contract.md「ホスト・資産」の hosts 部分。baselines/learn を含む）。

## 受け入れ基準
- psutil をモックしたホストセンサーのテスト、各ログ形式の fixture パーステスト、ローテーション tail のテスト。
- 統合テスト: スナップショット 2 回（2 回目に新ポート）を ingest → `port.unexpected_listener` アラート（P1 受け入れ基準）。
- ベースラインに追加すると同条件で発火しない。
