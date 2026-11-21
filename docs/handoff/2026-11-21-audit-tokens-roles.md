# 2026-11-21 監査対応レーン: tokens-roles（系統 G: API・認証のトークン権限・寿命、ロール、閲覧監査、データ削除）

担当 Issue（この順）: #40 → #33 → #163(a)(b) → #157 → #164 → #167 → #158。
指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`（#40=L07-05, #33=L07-01, #163=L18-04, #157=L17-02,
#164=L10-08, #167=L17-03, #158=L17-04）。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #40 | 部分 | 出所ラベル（`ingest.token_id`/`ingest.token`、クライアントの `ingest.*` は破棄）、トークンの `allowed_sensor_ids`/`allowed_datasets`（API・CLI `--sensor-id`/`--dataset`）、gate スコープ無しトークンの `gate.*`/`deception.*`/kind=deception に `ingest.trust=low`。protected_cidrs は既存（`response.protected_cidrs`）なので文書化のみ。repro をテスト化（`tests/api/test_ingest_provenance.py`） | 608ef21 |
| #33 | 部分 | `tokiwa token create` / `ApiTokenCreate` / UI の既定スコープを `ingest` のみに。Gate 用は `--scope ingest --scope gate` を明示。`token create` の全呼び出し（AGENTS.md, README, .env.example, docs/deploy.md, docs/gate.md, wiki Installation/Quick-Start/Sensors/CLI ×4 言語）を更新（lab/scripts/init-tokens.sh・Makefile・scripts は既に明示）。Gate はポリシー取得 403 時に「gate スコープ不足」のヒントをログ。docs/gate.md・docs/deception.md・wiki Deception×4 に「gate トークン漏えい＝デセプション配置の漏えい」。既存トークンの scopes は不変 | (このコミット) |
| #163 | 未着手 | | |
| #157 | 未着手 | | |
| #164 | 未着手 | | |
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

## 失敗した試み

（なし）

## 担当外の変更

- `frontend/src/api/types.ts`（`ApiToken` に `allowed_sensor_ids?`/`allowed_datasets?`）、`frontend/src/api/types-core.ts`
  （`ApiTokenCreate`/`ApiTokenCreated` に同フィールド）。型の追加のみ。
- `schemas/system.py` の `ApiToken`/`ApiTokenCreate` にフィールド追加（default 付き）。`ApiTokenCreate.scopes` の既定を `[ingest]` に（#33）。
- `frontend/src/pages/settings/TokensTab.tsx`: 作成フォームの既定スコープを `["ingest"]` に（1 行）。
- `AGENTS.md` / `README.md` / `.env.example` / `docs/deploy.md` の `token create` 例（#33）。

## 他レーンへの依頼

- frontend: 承認画面・アラート詳細の evidence に `labels["ingest.token"]`（送信トークン名）、`ingest.trust=low` の
  バッジ、`ingest.claimed_sensor_id` を表示（#40 (3)）。トークン作成フォームに `allowed_sensor_ids`/`allowed_datasets`
  の入力欄（任意）。
- triage/respond: 上記「低信頼のみのインシデントから block を提案しない」。

## 未検証事項

- 実 LLM のトリアージが `ingest.trust=low` ラベルを見て提案を控えるかは未検証（ラベルは evidence に含まれるが、
  プロンプトで意味付けしていない）。
