# 2026-11-21 監査対応レーン: tokens-roles（系統 G: API・認証のトークン権限・寿命、ロール、閲覧監査、データ削除）

担当 Issue（この順）: #40 → #33 → #163(a)(b) → #157 → #164 → #167 → #158。
指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`（#40=L07-05, #33=L07-01, #163=L18-04, #157=L17-02,
#164=L10-08, #167=L17-03, #158=L17-04）。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #40 | 部分 | 出所ラベル（`ingest.token_id`/`ingest.token`、クライアントの `ingest.*` は破棄）、トークンの `allowed_sensor_ids`/`allowed_datasets`（API・CLI `--sensor-id`/`--dataset`）、gate スコープ無しトークンの `gate.*`/`deception.*`/kind=deception に `ingest.trust=low`。protected_cidrs は既存（`response.protected_cidrs`）なので文書化のみ。repro をテスト化（`tests/api/test_ingest_provenance.py`） | (このコミット) |
| #33 | 未着手 | | |
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

## 要判断

- **#40 既定は「印を付ける」で拒否しない**: gate スコープの無いトークンからの `gate.*` を既定で拒否すると、ラボの
  `tokiwa sim ingest`（`lab/compose.yaml` の sim トークンは ingest のみ）と `scripts/seed_demo.py`（`--scope ingest`）が
  `gate.http` を送っているため壊れる。拒否したい運用はトークンに `allowed_datasets` を付ける。全体スイッチ
  （例 `ingest.reject_untrusted_gate_datasets`）を設けるかは要判断。
- **#40 無制限トークンの sensor_id は従来どおりクライアント値**（後方互換）。縛ったトークンのみ強制。

## 失敗した試み

（なし）

## 担当外の変更

- `frontend/src/api/types.ts`（`ApiToken` に `allowed_sensor_ids?`/`allowed_datasets?`）、`frontend/src/api/types-core.ts`
  （`ApiTokenCreate`/`ApiTokenCreated` に同フィールド）。型の追加のみ。
- `schemas/system.py` の `ApiToken`/`ApiTokenCreate` にフィールド追加（default 付き）。

## 他レーンへの依頼

- frontend: 承認画面・アラート詳細の evidence に `labels["ingest.token"]`（送信トークン名）、`ingest.trust=low` の
  バッジ、`ingest.claimed_sensor_id` を表示（#40 (3)）。トークン作成フォームに `allowed_sensor_ids`/`allowed_datasets`
  の入力欄（任意）。
- triage/respond: 上記「低信頼のみのインシデントから block を提案しない」。

## 未検証事項

- 実 LLM のトリアージが `ingest.trust=low` ラベルを見て提案を控えるかは未検証（ラベルは evidence に含まれるが、
  プロンプトで意味付けしていない）。
