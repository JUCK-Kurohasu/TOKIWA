# 2026-11-21 監査対応レーン: tokens-roles（系統 G: API・認証のトークン権限・寿命、ロール、閲覧監査、データ削除）

担当 Issue（この順）: #40 → #33 → #163(a)(b) → #157 → #164 → #167 → #158。
指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`（#40=L07-05, #33=L07-01, #163=L18-04, #157=L17-02,
#164=L10-08, #167=L17-03, #158=L17-04）。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #40 | 部分 | 出所ラベル（`ingest.token_id`/`ingest.token`、クライアントの `ingest.*` は破棄）、トークンの `allowed_sensor_ids`/`allowed_datasets`（API・CLI `--sensor-id`/`--dataset`）、gate スコープ無しトークンの `gate.*`/`deception.*`/kind=deception に `ingest.trust=low`。protected_cidrs は既存（`response.protected_cidrs`）なので文書化のみ。repro をテスト化（`tests/api/test_ingest_provenance.py`） | 608ef21 |
| #33 | 部分 | `tokiwa token create` / `ApiTokenCreate` / UI の既定スコープを `ingest` のみに。Gate 用は `--scope ingest --scope gate` を明示。`token create` の全呼び出し（AGENTS.md, README, .env.example, docs/deploy.md, docs/gate.md, wiki Installation/Quick-Start/Sensors/CLI ×4 言語）を更新（lab/scripts/init-tokens.sh・Makefile・scripts は既に明示）。Gate はポリシー取得 403 時に「gate スコープ不足」のヒントをログ。docs/gate.md・docs/deception.md・wiki Deception×4 に「gate トークン漏えい＝デセプション配置の漏えい」。既存トークンの scopes は不変 | 3bc39ab |
| #163 | 部分（(a)(b) は完全、(c)(d) は auth レーン） | (a) `ApiTokenRow` に `expires_at`/`created_by`/`rotated_from`（nullable）。期限切れは 401 `API token expired`。API `expires_in_days`（既定は無期限のまま）と `POST /tokens/{id}/rotate`。CLI `tokiwa token create --expires-in-days` / `list [--all]` / `revoke <id\|name>` / `rotate <id\|name> --grace-hours --expires-in-days`（共通処理 `tokiwa/auth/api_tokens.py`、監査 actor `cli`。CLI 作成も監査に残るようになった）。(b) Gate: `gate/tokens.py` の `TokenSource` がトークンファイルを mtime/サイズ/inode 変化で再読込、401 で強制再読込して変わっていれば即再送、変わらなければイベントをキューに保持してバックオフ（以前は 401 でバッチ破棄）。空・読めないファイルは直前のトークンを維持。`GateSettings.token_file`（`TOKIWA_GATE__TOKEN_FILE`）を追加し lab の gate に設定。UI のトークン一覧に「期限切れ」バッジ | 6b4d6f0 |
| #157 | 完全 | viewer にはイベントを伏字済み射影で返す（403 ではなく射影なので viewer の画面は壊れない）。`tokiwa/api/visibility.py`。対象: events 一覧/詳細、sessions 詳細の events、alerts 詳細の evidence、deception trips（バイパス経路も塞いだ）。伏字: query・request_body・ヘッダ値（UA/host/content-type/accept/content-length 以外）・referrer のクエリ・raw・Gate 以外の message・cmdline・llm_app.prompt・deception.token。フロントの body 整形は JSON.parse 失敗時に原文表示なので崩れない（確認済み）。wiki Web-UI ×4 にロール表を追記 | 0cd2e99 |
| #164 | 部分 | `copilot.min_role`（既定 analyst、viewer/admin に変更可）未満は会話作成・送信が 403（既存会話の閲覧は可）。ユーザー別（user.id キー）の送信レート `copilot.messages_per_minute`（既定 6/分、0=無制限）超過で 429 + Retry-After（ストリーム開始前に判定、409 等の拒否は枠を消費しない）。UI は既存の ApiErrorState で 403/429 を表示（送信時に会話作成→403 を `sendError` で表示することをコード上で確認） | (このコミット) |
| #167 | 未着手 | | |
| #158 | 未着手 | | |

### #40 で残したもの（部分の理由）
- (2) 後半「低信頼ソースのみで構成されたインシデントからは block 提案を作らない」: 提案は `triage/service.py`（frontend
  レーンが同時編集中）と `respond/service.py` にまたがるため未実装。実装案: `respond.service.create_proposal` で
  evidence イベントの `labels["ingest.trust"] == "low"` だけなら `proposed_by in (llm, rule)` の提案を拒否 or
  「低信頼」フラグ付きで作る。
- (3) 承認 UI に「このアラートを作ったトークン/センサー」を表示: フロント（他レーンへの依頼）。データは
  evidence イベントの `labels["ingest.token"]` / `sensor_id` / `labels["ingest.claimed_sensor_id"]` にある。
- (4) トークンごとの受信レート/件数の異常監視: 未着手。
- 送信元 CIDR（allowed_cidrs）でのトークン縛り: 未着手（リバースプロキシ越しの peer IP の扱いを決める必要あり）。

### #33 で残したもの（部分の理由）
- (2) Gate へ配るポリシーからハニートークン値を外す（Gate 側でテンプレート + HMAC 派生）: deception / gate / respond の
  ポリシー生成（`routes/gate.py` は frontend レーン、`deception/policy.py`）にまたがる設計変更のため未実装。
- (3) トークンを送信元 IP に縛る（allowed_cidrs）・last_used の IP 記録: 未実装（#40 の残りと同じ）。
- UI での警告（gate スコープにチェックしたときの注意書き）: 既定値の変更のみ。文言追加は frontend レーンへ依頼。

### #157 の補足
- パス（`http.path`）は viewer にも見せる（トリアージ画面が成り立たないため）。パスに個人情報が入るアプリでは不十分。
- `alerts.details`（検知器が入れる抜粋）・インシデントの LLM 分析文・`/llm/calls` 一覧の `related` は射影していない。
  抜粋に本文が入る検知器がある場合は別途。Copilot は #164 で既定 analyst 以上（viewer に許可すると search_events ツール
  経由で本文抜粋が LLM 回答に出うる）。

### #164 で残したもの
- 予算の用途別分割（triage/incident の予約枠と copilot 枠）・ユーザー別日次上限・同時会話数上限・予算 80%/100% 通知:
  `llm/gateway.py`（LLM レーン）にまたがるため未実装。
- レート制限はプロセス内メモリ（ワーカーごと）。複数ワーカー構成では「ワーカー数 × 上限」になる。
- UI で viewer に Copilot のメニュー自体を隠す: `min_role` は設定で変わるのでフロントが知る手段（例 `/auth/me` や
  `/system/info` に copilot 可否）が必要。frontend レーンへ依頼。

### #163 で残したもの
- (c) `tokiwa user reset-password`、(d) CLI の DB 例外で SQL パラメータを出さない（hide_parameters）: auth レーン担当のため未着手。
- TOKIWA Agent（`tokiwa agent run`、sensors モジュール）のトークンファイル再読込: 担当外のため未実装。`gate/tokens.py` の
  `TokenSource` を sensors の shipper でも使えば同じ挙動にできる。
- 期限切れが近いトークンの通知（UI バナー・notify）: 未実装。

## 要判断

- **#40 既定は「印を付ける」で拒否しない**: gate スコープの無いトークンからの `gate.*` を既定で拒否すると、ラボの
  `tokiwa sim ingest`（`lab/compose.yaml` の sim トークンは ingest のみ）と `scripts/seed_demo.py`（`--scope ingest`）が
  `gate.http` を送っているため壊れる。拒否したい運用はトークンに `allowed_datasets` を付ける。全体スイッチ
  （例 `ingest.reject_untrusted_gate_datasets`）を設けるかは要判断。
- **#40 無制限トークンの sensor_id は従来どおりクライアント値**（後方互換）。縛ったトークンのみ強制。

- **#33 既定スコープを ingest のみに変更（選択肢 b）**: 既定を変え、`token create` を呼ぶ docs・wiki・テストを同時に直した。
  既存トークンの scopes は変えないので稼働中の Gate は壊れない。新規に `tokiwa token create gate-1` だけで Gate を作った利用者は
  ポリシー取得が 403 になる（fail-open でプロキシは動くが遮断・デコイが効かない）ため、Gate のログに
  「--scope ingest --scope gate で作り直す」ヒントを出す。

- **#163 トークンの既定有効期限は無期限のまま**（後方互換）。recommendation の「既定 90 日」は、期限切れで Gate/agent の
  取り込みが黙って止まる運用リスクがあるため（期限通知が未実装）、`--expires-in-days` / `expires_in_days` の opt-in にした。
  既定 90 日にするかは要判断（するなら期限通知とセットで）。
- **#163 Gate の 401 を「保持して再試行」に変更**: 以前は 401 でバッチ破棄（`dropped_rejected`）。トークン失効後に誰も直さないと
  キュー上限（既定 10000）まで溜まり古いものから捨てる（メモリは有界）。403/422 は従来どおり破棄。
- **#163 rotate の猶予の既定は 24 時間**（API/CLI とも）。0 で即時失効。

## 失敗した試み

（なし）

## 担当外の変更

- `frontend/src/api/types.ts`（`ApiToken` に `allowed_sensor_ids?`/`allowed_datasets?`）、`frontend/src/api/types-core.ts`
  （`ApiTokenCreate`/`ApiTokenCreated` に同フィールド）。型の追加のみ。
- `schemas/system.py` の `ApiToken`/`ApiTokenCreate` にフィールド追加（default 付き）。`ApiTokenCreate.scopes` の既定を `[ingest]` に（#33）。
- `frontend/src/pages/settings/TokensTab.tsx`: 作成フォームの既定スコープを `["ingest"]` に（1 行）。
- `AGENTS.md` / `README.md` / `.env.example` / `docs/deploy.md` の `token create` 例（#33）。
- `config.py` の `GateSettings` に `token_file: Path | None = None`（#163。gate セクションのみ）。
- `gate/app.py`: `Gate.token` を `TokenSource` 経由のプロパティに（`self.tokens`）。shipper / policy に `TokenSource` を渡す（数行）。
- `api/deps.py` の `require_token_scope` に期限切れ判定（担当部分）。
- `lab/compose.yaml`: gate サービスに `TOKIWA_GATE__TOKEN_FILE`（with-token.sh の env と併用。ファイルが読めればファイル優先）。
- `frontend/src/pages/settings/TokensTab.tsx`: 状態列に「期限切れ」バッジ（数行）。
- `tests/gate/test_gate_shipper.py`: 401 を恒久エラーの parametrize から外した（挙動変更のため）。
- `config.py` の `CopilotSettings` に `min_role` / `messages_per_minute`（#164。copilot セクションのみ）。
- `api/routes/alerts.py`（`get_alert` の evidence に `project_events`、2 行）、`api/routes/deception.py`（`list_trips` に同、3 行）（#157）。

## 他レーンへの依頼

- frontend: viewer（`copilot.min_role` 未満）にはコパイロットの入力欄を無効化して説明を表示（#164）。
- LLM: 予算の用途別枠（copilot が triage を枯渇させない）（#164 の残り）。

- frontend: トークン画面に「ローテーション」ボタン（`POST /tokens/{id}/rotate`、新トークンを一度だけ表示）と有効期限の入力
  （`expires_in_days`）、`created_by` 列（#163）。

- frontend: 承認画面・アラート詳細の evidence に `labels["ingest.token"]`（送信トークン名）、`ingest.trust=low` の
  バッジ、`ingest.claimed_sensor_id` を表示（#40 (3)）。トークン作成フォームに `allowed_sensor_ids`/`allowed_datasets`
  の入力欄（任意）。
- triage/respond: 上記「低信頼のみのインシデントから block を提案しない」。

## 未検証事項

- 実 LLM のトリアージが `ingest.trust=low` ラベルを見て提案を控えるかは未検証（ラベルは evidence に含まれるが、
  プロンプトで意味付けしていない）。
