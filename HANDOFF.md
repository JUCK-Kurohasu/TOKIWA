# HANDOFF.md — 現在地と次の一手

> 新しいセッション/アカウントはまずここを読む。作業の区切りごとに **必ず更新** する。
> 秘密情報・社内情報は書かない。

最終更新: 2026-10-26（セッション 1 / 統合担当）
作業ブランチ: `claude/affectionate-knuth-1inglo`（main に PR #1〜#3 マージ済み、PR #4 で残りを統合中）

## 1. 現在の状態（サマリ）

- **第 1 波（18 モジュール）: 全て実装・統合済み**。`cd backend && uv run pytest` 緑（1,281 件・約 70 秒）、ruff クリーン、
  `cd frontend && npm run typecheck && npm run lint && npm run build && npx vitest run` 緑。
- **E2E（モック LLM）が通る**: `uv run tokiwa eval run --dataset ../eval/datasets/lab-mini.jsonl --llm mock --out <dir>`
  - 攻撃セッション検知 5/5、正常セッション誤検知 0%、アラート適合率 100%（87 件）、AI アトリビューション P/R/AUC = 1.0、
    取り込み→アラート p50 10ms、アラート→トリアージ p50 1.3s、31 検知器が稼働。
  - **注意（過大評価）**: データセットは検知器と同じ仮説から合成したもの。実トラフィック・ARTEX での検証が未了。
    human_attacker 2 セッション中 1 つが振る舞いスコアで benign 判定。モック LLM の actor 一致率は 13%（実 LLM 未評価）。
- Docker: devops 担当がサンドボックスで dockerd を起動してイメージビルド・スモーク・compose（SQLite/PostgreSQL）まで確認済み。
  ただし `lab/compose.yaml` の `up` と GitHub Actions 上の CI は未実行。

## 2. モジュール一覧（すべて main または PR #4）

| 領域 | 主なファイル | 作業ログ |
|---|---|---|
| 骨格（契約・拡張点） | config / schemas / db / bus / runtime / pipeline / detect/engine / llm/gateway | — |
| Web 署名・レート検知（17） | detect/detectors/web_*.py, detect/web_common.py | docs/handoff/2026-10-22-detect-web.md |
| Sigma（評価器・25 ルール・API） | detect/sigma/, rules/sigma/, routes/rules.py, detectors.py | …-sigma.md |
| AI エージェント振る舞い検知（6） | aidetect/, enrich/sessionizer.py, detectors/ai_*.py, llm_app_*.py, routes/sessions.py | …-detect-ai.md |
| センサー・ポート監視 | sensors/, enrich/ports.py, detectors/port_*.py, net_*.py, routes/hosts.py | …-sensors.md |
| Gate | gate/ | …-gate.md, docs/gate.md |
| Mirage（デセプション） | deception/, detectors/deception_trip.py, routes/deception.py | …-deception.md, docs/deception.md |
| LLM プロバイダ | llm/anthropic_provider.py, openai_compat.py, settings.py, routes/llm.py | …-llm.md, docs/security/llm-safety.md |
| 相関・トリアージ | correlate/, triage/, routes/alerts.py, incidents.py | …-triage-correlate.md |
| インテル（フィード） | intel/sources/, store.py, sync.py, cli.py, routes/intel.py | …-intel-feeds.md |
| インテル（照合・助言・リサーチ） | intel/matcher.py, advisor.py, research.py, routes/assets.py, intel_advice.py | …-intel-advisor.md |
| 対処・Gate ポリシー・通知 | respond/, notify/, routes/response.py, gate.py, notify.py | …-respond.md, docs/response.md |
| コパイロット | copilot/, routes/copilot.py | …-copilot.md |
| API コア・SSE | routes/users,tokens,events,dashboard,system,audit,stream.py, api/pagination.py | …-api-core.md |
| フロント（各画面） | frontend/src/pages/* | …-frontend-core/ops/intel.md |
| ラボ・シミュレータ・評価 | eval/, lab/, eval/datasets/lab-mini.jsonl | …-lab-eval.md, docs/purple-team.md |
| DevOps | deploy/, .github/workflows/ci.yml, Makefile, scripts/ | …-devops.md, docs/deploy.md |

## 3. 統合で入れた修正（このセッション）

- `fix(api)`: `?access_token=` を SSE ストリームのみに限定（JWT のログ漏えい防止）。
- `fix(bus)`: `drain()` の無限スピン（Python 3.12+ の gather が完了済みタスクで即返る）→ 評価ハーネスがハングしていた。
- `chore(config)`: `llm.max_output_tokens` 既定 8000（deep モデルは思考を無効化できず上限に含まれる）。
- テストの頑健化（監査ログ件数、評価の回帰テスト）。

## 4. 次の一手（第 2 波・優先順）

1. **実データでの検証**: `lab/compose.yaml` を実際に `up` → `tokiwa sim run` 全プロファイル → ARTEX をラボに向けた
   パープルチーム演習（docs/purple-team.md）。その結果で `aidetect/scoring.py` の重みを調整（現状は合成データでのみ 100%）。
2. **実 LLM 評価**（費用発生。要ユーザー承認と予算）: `tokiwa eval run --llm live --budget-usd <N>`。refusal 率・一致率・コスト。
3. **フロント統合の後始末**: SSE フック一本化（`hooks/useLiveStream.ts` と `components/common/useOpsLive.ts`）、
   重複コンポーネント（QueryView/DataState、OffsetPager/PagerBar、EventDetail/EventInspector 等）の統合、
   `api/types-*.ts` を `types.ts` へ集約、ページの遅延読み込み（バンドル 1.27MB）、実バックエンドとの画面確認（Playwright）。
4. **設定の整理**: Gate の CLI 専用 5 設定を `GateSettings` へ、sensors のサーバー側設定を `detection` へ移す、
   空文字の `TOKIWA_*` を未設定扱いにする、各モジュールの定数（NVD 待機・閾値等）の設定化。
5. **運用基盤**: Alembic 導入（ADR-0002）、データ保持期間とパージジョブ、mypy の既存 6 エラー（db/session.py,
   detect/context.py, llm/gateway.py）解消と CI での必須化。
6. **機能の残り**: Gate → `next-action`/`rsc` ヘッダ透過と `response_content_type` 記録（detect-web 依頼）、
   多 IP パスワードスプレー検知、アクター横断の指紋統合（detect-ai）、対処の二者承認（respond）、
   オフライン評価用のデセプション資産シード（lab-eval 依頼）、KEV ブーストの host→vuln_matches 経由（triage）。

## 5. 要判断事項（ユーザー）

- ライセンス: Apache-2.0 を暫定（ADR-0005）。
- 実 LLM での評価実行の予算。
- AI カナリアの文言の強さ・言語、robots.txt / llms.txt カナリアの有効化（既定 OFF。アプリ本来のファイルを置き換える）、
  デセプションの法務確認（docs/deception.md に TODO(verify)）。
- 対処の二者承認（提案者≠承認者）を必須にするか。

## 6. 既知の制約・注意

- このクラウド環境からは NVD/KEV/EPSS/JVN/OSV/GHSA に出られない → インテルは公式仕様ベースの fixture で検証。
  **JVN は 2026-04 以降 MyJVN の刷新告知あり**（旧フィード前提の実装が使えない可能性。TODO(verify)）。
- ARTEX-JP は `/home/user/artex-jp` に読み取り専用（AGPL-3.0 のためコード複製なし）。インポータは形式の相互運用のみ。
- Anthropic SDK は 2.x（httpx2）。respx では SDK 通信を捕捉できない → httpx2 モックトランスポート。
- 未検証の事実は各コード・作業ログに `TODO(verify)`（CVE-2025-55182 の内部フィールド名、AI クローラ UA 一覧、
  MITRE ATLAS ID、A2A/MCP の .well-known パス 等）。

## 7. 失敗した試み・ハマりどころ

- hatchling は `readme` にプロジェクト外パスを指定できない → `backend/README.md`。
- ruff の E501 は formatter に任せて無効化。
- 16〜18 体同時実行で 5 時間枠の上限に 3 回、その後週次上限に到達。中断のたびに約 30 万トークンの文脈を読み直す
  再開コストが発生する → 第 2 波は 4〜6 体程度に絞り、新しいセッションから始めるのが効率的。
- worktree が骨格以前のコミット（0efcd24）から作られることがある → `git merge --ff-only <skeleton>` で追いつかせる。
- エージェントのブランチ統合: `git merge --no-edit worktree-agent-<id>`。衝突は docs（api-contract/architecture）のみだった。
