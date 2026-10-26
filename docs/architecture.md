# TOKIWA アーキテクチャ

> 正本。モジュール構成・データフロー・拡張ポイント・安全設計をここに集約する。
> 変更したら同じコミットでこの文書も更新すること。

## 1. 位置づけ — ARTEX と対をなすもの

| | ARTEX (ARTEX-JP) | TOKIWA |
|---|---|---|
| 役割 | AI 自律型ペネトレーションテスト（攻撃側 / Red） | LLM 駆動 SIEM/XDR（防御側 / Blue） |
| LLM の使い方 | エージェントが偵察・攻撃を自律実行 | ルール検知の後段でトリアージ・相関・提案（実行は人間承認） |
| 主対象 | Web アプリ / API / 資産 | ポート・HTTP リクエスト・LLM アプリ・脆弱性情報 |
| 構成 | Go + Next.js + PostgreSQL | Python (FastAPI) + React (Vite) + SQLite/PostgreSQL |
| 連携 | 攻撃トラフィックの生成源 | ARTEX のトラフィックを検知・評価（パープルチーム） |

TOKIWA の主眼は **「生成AI/LLM エージェントによる攻撃」を見分けて止めること**。従来の署名検知に加え、
AI エージェント特有の振る舞い（思考待ちのリズム、エラー応答に即応したペイロード変異、JS からの API 発見、
デコイ内の隠し指示への追従）を特徴量化してアトリビューションする。

## 2. 全体図

```
                ┌──────────────── Sensors ────────────────┐
 Internet ──▶  TOKIWA Gate (reverse proxy)  ── full HTTP capture (body incl.) + enforce (block/rate/tarpit/deceive)
                TOKIWA Agent (host)         ── psutil ports/conns, nginx/caddy JSON logs, Suricata EVE, Zeek
                Protected LLM app hooks     ── prompts (llm_app events)
                └──────────────┬──────────────────────────┘
                               │ POST /api/v1/ingest/events  (API token, scope=ingest)
                               ▼
 ┌──────────────────────── TOKIWA Server (FastAPI, single process) ─────────────────────────┐
 │ pipeline.process_events                                                                  │
 │   enrich (sessionizer, asset mapper, ...) → store events → detect (registry) → alerts    │
 │                                                    │ bus: alert.created                  │
 │   correlate: alerts → incidents (kill chain, AI score, KEV boost)                        │
 │   triage:    LLM gateway (fast tier → escalate to deep tier), evidence validation        │
 │   respond:   proposals → human approval → executors (gate policy, webhook, nft*)         │
 │   deception: decoys / honeytokens / AI canaries → gate policy                            │
 │   intel:     KEV / EPSS / NVD / OSV / JVN / GHSA / RSS + LLM web research → advisories   │
 │   notify:    webhook / Slack / Discord / email                                           │
 │   copilot:   chat with read-only tools                                                   │
 │ API /api/v1/* + SSE /api/v1/stream + static UI                                           │
 └───────────────────────────────┬──────────────────────────────────────────────────────────┘
                                 │ GET /api/v1/gate/policy (scope=gate)
                                 ▼
                           TOKIWA Gate
```

## 3. リポジトリ構成

```
TOKIWA/
├── CLAUDE.md / AGENTS.md / HANDOFF.md   AI 向け取扱説明書・現在地
├── docs/                                設計（本書）、API 契約、ADR、タスク仕様、検知カタログ
├── backend/                             Python パッケージ `tokiwa`（uv 管理）
│   ├── src/tokiwa/
│   │   ├── config.py      設定（env TOKIWA_* / tokiwa.yaml）。モジュールごとにセクション
│   │   ├── schemas/       Pydantic スキーマ = モジュール間・API の契約
│   │   ├── db/            SQLAlchemy (async)。models/ 配下は自動 import
│   │   ├── bus.py         プロセス内 pub/sub
│   │   ├── runtime.py     @on_startup / @periodic（定期ジョブ）
│   │   ├── plugins.py     自動検出ユーティリティ
│   │   ├── pipeline/      取り込みパイプライン
│   │   ├── enrich/        エンリッチャ（自動検出）
│   │   ├── detect/        検知エンジン + detectors/（自動検出）
│   │   ├── correlate/     相関・インシデント化
│   │   ├── triage/        LLM トリアージ
│   │   ├── llm/           ゲートウェイ・プロバイダ・マスキング・プロンプト
│   │   ├── intel/         脆弱性/脅威インテリジェンス + sources/（自動検出）
│   │   ├── respond/       対処（承認ワークフロー・実行器）
│   │   ├── deception/     Mirage（デコイ・ハニートークン・AI カナリア）
│   │   ├── gate/          リバースプロキシ・センサー（別プロセス）
│   │   ├── sensors/       ホストセンサー・ログアダプタ（別プロセス: tokiwa agent）
│   │   ├── notify/        通知
│   │   ├── copilot/       SOC コパイロット
│   │   ├── eval/          評価ハーネス・ラボ用トラフィックシミュレータ
│   │   ├── api/           app factory + routes/（自動検出）
│   │   └── cli.py         `tokiwa` コマンド
│   └── tests/
├── frontend/                            React + Vite + Tailwind v4（pages/*/route.tsx 自動検出）
├── rules/sigma/                         Sigma ルール
├── lab/                                 Docker Compose のラボ（被監視アプリ・ゲート・シミュレータ）
├── eval/                                評価データセット・結果
└── deploy/                              Dockerfile / compose
```

## 4. データフロー詳細

### 4.1 取り込み（Ingest）
1. センサーが `Event`（`schemas/events.py`）に正規化して `POST /api/v1/ingest/events` へバッチ送信。
2. `pipeline.process_events`:
   - `ingested_at` 付与 → 登録順に **Enricher** 実行（`session_id` 付与、`asset_id` 付与など）
   - **DetectionEngine.run**（純粋関数・DB なし）→ `AlertDraft[]`
   - 1 トランザクションで events 保存 + alerts の重複排除 upsert（`fingerprint` + `dedup_window_seconds`）
   - bus へ `event.ingested` / `alert.created` / `alert.updated` を publish
3. 同期処理（API はトリアージ完了を待たない。トリアージは bus 購読側で非同期）。

### 4.2 検知（Detect）
- `detect/base.py` の `Detector` を継承し `@register_detector`。`detect/detectors/*.py` は自動 import。
- ステートレス（署名）とステートフル（`ctx.window()` / `ctx.state` を使う窓集計）の二種。
- Sigma ルールは `detectors/sigma.py` が `rules/sigma/` と DB の `rules` テーブルを読み込んで評価。
- 実行時の有効/無効は `engine.overrides`（`settings_kv: detection.overrides` から復元）。

### 4.3 相関・トリアージ
- correlate: `alert.created` を購読 → 同一送信元/セッション/エンティティを `incident_window_minutes` で束ねて
  Incident を作成・更新（kill chain、AI スコア、KEV 該当 CVE ブースト）。
- triage: `min_severity_for_llm` 以上を LLM へ。fast tier → 信頼度が低い/重大度が高いと deep tier へ昇格。
  出力は `TriageResult` 固定。`evidence_ids` が実在しない場合は除外・再試行（要件 7-5）。
  LLM 不在・予算超過・拒否（refusal）時はルールベース判定にフォールバック。

### 4.4 対処（Respond）
- 提案元: ルール / LLM（`recommended_actions`）/ ユーザー。`ActionType` の許可リストのみ。
- `proposed` → 人間が承認 → executor 実行 → `active`（TTL）→ `expired`/`reverted`。
- 自動承認は `response.auto_approve_enabled` かつ `auto_approve_actions` に含まれる型だけ（既定 OFF）。
- **LLM の自由文は実行系に渡らない**。実行器が受け取るのは検証済みの型・IP/CIDR・TTL のみ。
- Gate は `GET /api/v1/gate/policy` を定期取得し、block / rate-limit / tarpit / deceive を適用。

### 4.5 インテリジェンス（Intel）
- `intel/sources/*.py` が KEV / EPSS / NVD / OSV / JVN / GHSA / RSS を取得（`IntelSource`）。
- `intel.store` が CVE 単位でマージ。`intel.matcher` が資産のソフトウェア（CPE/製品名/バージョン）と照合。
- `intel.advisor` が KEV 該当・高 EPSS・資産一致を優先して LLM で `AdvisoryAnalysis` を生成。
  Sigma ルール案は検証後 `rules` に `proposed` で保存（自動有効化しない）。
- `intel.research` が Claude のサーバーサイド Web 検索で 0day/悪用報告を定期調査し `ResearchOutput` を保存。

## 5. 拡張ポイント一覧（並列開発のための約束）

| 追加したいもの | 置き場所 | 登録方法 | 共有ファイル編集 |
|---|---|---|---|
| 検知器 | `backend/src/tokiwa/detect/detectors/<family>_<name>.py` | `@register_detector` | 不要 |
| エンリッチャ | `backend/src/tokiwa/enrich/<name>.py` | `@register_enricher` | 不要 |
| API ルート | `backend/src/tokiwa/api/routes/<resource>.py` | `router = APIRouter(...)` | 不要 |
| 定期ジョブ/起動処理 | 各モジュール内 | `@periodic` / `@on_startup` | 不要 |
| バス購読 | 各モジュール内（`@on_startup` で subscribe） | `bus.subscribe` | 不要 |
| DB テーブル | `backend/src/tokiwa/db/models/<module>.py` | 自動 import | 不要 |
| インテル取得元 | `backend/src/tokiwa/intel/sources/<id>.py` | `@register_source` | 不要 |
| CLI サブコマンド | `tokiwa/<module>/cli.py` の `app = typer.Typer()` | `cli._SUBCOMMANDS` に既登録 | 不要 |
| 設定項目 | `config.py` の自モジュールのセクションのみ | — | 自セクションのみ |
| UI ページ | `frontend/src/pages/<name>/route.tsx` | `export const route` | 不要 |
| モック LLM 応答 | 各モジュール | `@register_mock_responder(Schema)` | 不要 |

## 6. イベントバス（topics）

`bus.py` の docstring が正本。主要トピック: `event.ingested`, `alert.created`, `alert.updated`,
`incident.created`, `incident.updated`, `action.proposed`, `action.updated`, `deception.tripped`,
`intel.vuln_updated`（`VulnRecord`、`data.update_reasons` = kev_added / epss_spike）, `intel.vuln_matched`, `intel.advisory`, `llm.call`。SSE (`/api/v1/stream`) はこれをそのまま中継する。

## 7. 安全設計（LLM）

`docs/security/llm-safety.md` を参照。要点:
1. テレメトリは常に非信頼データ。`llm/prompting.untrusted_block()` で JSON 化・エスケープして包む。
2. 送信前マスキング（`llm/redact.py`）。ヘッダ許可/秘匿リスト、トークン・鍵・メール・カード番号。
3. 出力はスキーマ固定（構造化出力）。範囲外は破棄。evidence_ids を実在検証。
4. ツールは参照系のみ（Copilot）。書き込み系は存在しない。
5. 監査: 全 LLM 呼び出しを `llm_calls` に記録（モデル・プロンプト版・トークン・費用・入出力）。
6. コスト: 日次予算、呼び出し単位の入力上限、ティア分け、プロンプトキャッシュ。
7. Refusal（安全分類器による拒否）を正常系として扱い、ルール判定へフォールバック。

## 8. 能動的防御（Active Defense）の線引き

TOKIWA の「能動的」は **自組織の資産上でのみ** 行う:
- デコイ・ハニートークン・AI カナリア（隠し指示に追従したら AI と判定）、迷路（トークン浪費）、tarpit。
- 攻撃元への反撃（hack-back）、第三者システムへのアクセス、マルウェア的ペイロードの返送は **行わない**。
- すべての遮断は可逆（TTL・revert）で、既定は人間承認必須。
