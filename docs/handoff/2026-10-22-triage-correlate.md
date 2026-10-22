# 2026-10-22 triage-correlate 作業ログ

担当: docs/tasks/triage-correlate.md（FR-07 / FR-09）
ブランチ: `worktree-agent-aaa1ce3cae4951b8b`（作業開始時に skeleton コミット c4881e1 へ fast-forward。ワークツリーが skeleton 以前を指していたため）

## やったこと

| ファイル | 内容 |
|---|---|
| `correlate/killchain.py` | ATT&CK 技術 ID / 戦術 ID (TA00xx) → 戦術の対応表、カテゴリ別フォールバック、キルチェーン順の順序付き集合 |
| `correlate/scoring.py` | 重大度ブースト（AI / KEV / port_request、各 +1 段・critical で頭打ち）、アクター推定、代表カテゴリ、CVE 抽出（純粋関数） |
| `correlate/service.py` | `alert.created` / `alert.updated` 購読。source_ip・actor session・host+port・CVE を `incident_window_minutes` 内で共有するオープンなインシデントへ紐付け、なければ新規作成。新規リスナー直後の同ポート宛てリクエスト系アラート → `correlated:port_request`。集約値は紐付いた全アラートから毎回再計算（冪等）。変化したときだけ `incident.created/updated` を publish。`actor_sessions.incident_id` を逆リンク |
| `triage/evidence.py` | 対象（TriageSubject）と証拠コンテキスト構築、HTTP 証拠の圧縮（path/query/body 先頭 512 字/許可ヘッダ/ステータス/タイミング、raw は送らない）、evidence_id 検証、対処ターゲット検証 |
| `triage/prompts.py` | `PromptTemplate`（`triage.alert@1`, `triage.incident@1`）。テレメトリ・検知器メタデータはすべて `untrusted_block()`、system に `UNTRUSTED_DATA_POLICY` + `language_instruction()` |
| `triage/fallback.py` | ルールベース `TriageResult`。同じロジックを `@register_mock_responder(TriageResult)` に登録（プロンプト内のデータブロックを解析して同一判定） |
| `triage/service.py` | 閾値未満はルールのみ → fast → 条件で deep 昇格 → evidence 検証（不正 ID 除外・記録、有効 0 件なら 1 回だけ再試行）→ 失敗時ルール。`TriageRecord` 保存（アラートは `triaged`）、`propose_action()` へ提案。Semaphore で同時実行制限、同一対象の多重実行防止 |
| `api/routes/alerts.py`, `incidents.py` | api-contract どおりの一覧/詳細/PATCH/強制トリアージ。PATCH・強制トリアージは `record_audit` |
| `tests/correlate/`, `tests/triage/` | 71 テスト（スケルトン含む全体）。統合: ingest → alert → incident → triaged（mock LLM）、refusal 時の rules フォールバック |

結果: `uv run pytest` 71 passed（約 7 秒）、`ruff check` / `ruff format --check` 緑、`mypy` は自モジュールでエラーなし。

## 設計判断（調整ポイント）

- **昇格条件**: `confidence < escalate_confidence_below` または `max(ルール重大度, fast 判定重大度) >= escalate_severity`。deep が失敗したら fast 判定を採用（`tier=fast, escalated=true`）。fast が失敗（予算超過・refusal・不正出力）したら deep は試さずルールへ（コスト優先）。`?tier=` 指定時はそのティアのみで昇格しない。
- **強制トリアージ API** は `auto_triage` と `min_severity_for_llm` を無視して LLM を使う。
- **証拠が 1 件もロードできない対象**は LLM に送らずルール判定（根拠必須のため）。
- **対処提案のターゲット**は「証拠イベントの送信元 IP と完全一致する単一 IP」のみ。CIDR・ホスト名・URL・宛先（自サーバー）IP は破棄。LLM の params は渡さず、reason は 500 字で切る。ルール判定由来は `proposed_by=rule`、LLM 由来は `llm`。ルール判定の提案は high 以上のみ（critical→block_ip、AI→deceive、その他 high→rate_limit、TTL 60 分）。
- **インシデントの再トリアージ**は重大度・キルチェーン・AI スコア（0.1 刻み）・ブーストタグ・カテゴリの「署名」が変わったときだけ（`incident_signature`）。実行中の更新は 1 回の再実行にまとめる。署名はプロセス内メモリ（再起動後の初回更新で 1 回再トリアージされる）。
- **インシデントの重大度・actor_type はルール主**。LLM 判定は `triage` 列と summary に入る。actor_type はルールが `unknown` のときだけ LLM（rules 以外）の判定を採用。
- `correlate/service.py` の `NEW_INCIDENT_MIN_SEVERITY = low`: info アラートは既存インシデントに付くだけで新規作成しない（PORT_CHANGE の学習ノイズ対策）。設定化するなら `TriageSettings` に移す（共有ファイルなので今回は定数）。
- false_positive にされたアラートは紐付いたまま重大度計算から外す。
- インシデント更新（相関・トリアージ書き込み）は `correlation_lock()`（プロセス内 asyncio.Lock）で直列化。単一プロセス前提（ラボ規模）。

## 未完・既知の制約

- **KEV ブースト**はアラート自身が参照する CVE（entities 値・tags・`details.cve(s)`）のみ。資産（host）→ `vuln_matches` → KEV という間接参照は未実装（intel-advisor の matcher と合わせて検討）。`VulnRow.id` 一致のみで `aliases` は見ていない。
- **port_request** のホスト照合はベストエフォート（双方にホスト名があるときのみ一致を要求、なければポートだけ）。リスナー情報は `entities.host/port` → PORT_CHANGE 証拠の `port.socket.port` / `host.name` の順で取る。
- 1 アラートだけのインシデントはアラートとインシデントで LLM を 2 回呼ぶ（仕様どおり）。コストが問題になれば「単一アラートのインシデントはアラート判定を流用」を検討。
- `mypy src` に既存のエラー 6 件（`db/session.py`, `detect/context.py`, `llm/gateway.py`。いずれも本タスク外・未変更）。

## 他モジュールへの依頼

- **respond**: `propose_action()` は本モジュールから `ActionProposal(proposed_by=llm|rule, alert_id|incident_id, ttl_minutes)` で呼ばれる。同一 (type,target) の重複排除と保護 CIDR 検証をお願いしたい。未実装（NotImplementedError）の間は警告 1 回で提案をスキップする。
- **detect-ai**: sessionizer が `actor_sessions` を upsert するとき `incident_id` を None で上書きしないでほしい（相関が逆リンクを書く）。`classification` はインシデントの actor_type 推定に使う。
- **sensors**: `port.*` 検知器のアラートに `entities={"host": ..., "port": "..."}` を入れてもらえると port_request 相関と host+port 紐付けが確実になる。
- **deception**: AI カナリア接触アラートに tag `ai_canary`（または entities 値 `ai_canary`）を付けると AI 判定が決定的になる。
- **frontend-ops**: 一覧の `status` / `severity` / `category` / `actor_type` はカンマ区切りで複数指定可。強制トリアージは同期で数秒〜数十秒かかりうる。
- **統合担当（docs）**: `docs/api-contract.md` のインシデント強制トリアージに `?tier=fast|deep` を追記してほしい（実装済み。共有ファイルのため本ブランチでは未編集）。新しいバストピック・設定項目の追加はなし。

## TODO(verify)

- `correlate/killchain.py` の MITRE ATLAS（AML.T0051 / T0054 / T0057）→ 戦術の対応は表示用の便宜的なもの。ATLAS 正本で確認すること。

## 次の一手

1. respond マージ後、`propose_action` を実体にして統合テスト（提案 → 承認 → Gate ポリシー）を追加。
2. 実 LLM（`claude-haiku-5-5` / `claude-opus-5-5`）でプロンプト品質と refusal 率を評価（lab-eval の評価セット）。必要ならプロンプト版を上げる。
3. KEV ブーストの資産経由参照、`NEW_INCIDENT_MIN_SEVERITY` の設定化を判断。
