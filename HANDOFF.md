# HANDOFF.md — 現在地と次の一手

> 新しいセッション/アカウントはまずここを読む。作業の区切りごとに **必ず更新** する。
> 秘密情報・社内情報は書かない。

最終更新: 2026-10-26（セッション 1 / 統合担当・第 1 波クローズ）
状態: **第 1 波はすべて main にマージ済み**（PR #1〜#5、main = `db9f012` 以降）。GitHub Actions の CI 全ジョブ緑。
**第 2 波は未着手**（仕様は `docs/tasks/wave2-*.md` に作成済み）。次のセッションは §0 から始める。
**利用者向け Wiki**（日本語既定 + 英・中・西）の正本は `docs/wiki/`。main へのマージで `.github/workflows/wiki.yml` が
GitHub Wiki に同期する（2026-10-26 に初回公開済み: 13 ページ × 4 言語。`GITHUB_TOKEN` で push できることを確認）。

## 実 API 初回接続で判明したこと（2026-10-30・Anthropic キー登録後）

- **provider が `mock` のままだった**ため、接続テストもトリアージも全てモックの応答だった（応答 0〜1 ms・費用 $0・出力 200 tokens 固定が目印）。
  UI の状態カードは設定値（`provider`）しか出さず、`MockProvider.available()` も常に True で、気づけなかった。
  → 状態カードに `active_provider` と「mock で動作中」警告を追加。接続テストを fast / deep の両方に変更し、結果が mock のときは注意書きを表示。
- **コパイロットが 400 で失敗**（実 API で初めて判明）: `Schemas contains too many optional parameters (46) ... (limit: 24)`。
  11 ツールを `strict: true` で送ると、オプション引数の合計が 1 リクエストあたり 24 を超えるため。
  既存のリトライは「エラー文に `strict` を含む場合のみ」で、実際の文面に当たらず（テストも自分の想定文面で書かれていた）無効だった。
  → `anthropic_provider.py`: strict 対象のオプション引数が 24 超ならはじめから strict なしで送る。400 は文面に依らず 1 回だけ strict なしで再試行
  （再試行も失敗したら例外を伝播し、strict は無効化しない）。ツール入力は `copilot/tools.py` の Pydantic（`extra="forbid"`）で検証されるので安全性は変わらない。
- `TODO(verify)`: 上限 24 が「1 リクエスト」単位か、ネストをどう数えるかは API の文面からの推定（`STRICT_MAX_OPTIONAL_PARAMS`）。
- 未確認: Opus（deep）経路の `betas=server-side-fallback` / `fallbacks="default"` が実 API で通るか、トリアージの `TriageResult` スキーマが
  実 API で通るか。接続テストの deep と、コパイロット・トリアージの実行ログ（LLM → 呼び出し履歴）で確認すること。

### UI の小修正（2026-10-30）
- コパイロットの「送信」が狭い幅で縦に 2 行に折り返す問題: `Textarea` が `w-full` で行内の幅を取り、ボタンが縮んでいた（ボタンは `h-9` 固定のため文字だけがはみ出す）。
  `ChatView.tsx` の送信 / 停止ボタンに `shrink-0 whitespace-nowrap`、`Textarea` に `min-w-0 flex-1` を付けて解消（共通 `Button` は未変更）。
- ロゴを盾から山並み（3 峰）に変更: `components/common/BrandMark.tsx`（サイドバー・ログイン画面）と `public/favicon.svg`。パスは両者で同期すること。

## 0. 次のセッションはここから — 第 2 波の始め方

### ユーザーが新セッションに貼るプロンプト（例）

```
HANDOFF.md の §0 と docs/tasks/wave2-README.md を読んで、TOKIWA の第 2 波を始めて。
フェーズ 1（B scoring-tuning / C frontend-consolidation / D config-ops / E feature-gaps）を
worktree で並列実行し、終わったものから統合・全チェック・ドラフト PR まで進めて。同時実行は最大 6 体。
G（実 LLM 評価）は私が予算を伝えるまで実行しないこと。
```

### 統合担当（新セッションのメイン）の手順

1. 読む: この §0 → `AGENTS.md` → `docs/tasks/wave2-README.md` → `docs/tasks/wave2-*.md`（7 本）。
   §1〜§7 は第 1 波の記録なので、必要になったら参照すればよい。
2. `git fetch origin && git log origin/main --oneline -3` で main の HEAD を確認し、作業ブランチを最新 main から作る
   （ブランチ名はシステムの指定に従う）。
3. 環境準備（初回のみ）: `cd backend && uv sync`、`cd frontend && npm ci`。
   **ベースラインとして wave2-README の「全チェック」を一度通しておく**（後で落ちたとき、自分たちの変更が原因か切り分けるため）。
4. フェーズ 1: B / C / D / E の 4 体を Agent ツールで `isolation: "worktree"` を付け、wave2-README のテンプレートで起動。
5. 完了報告ごとに `git merge --no-edit worktree-agent-<id>` → 全チェック（`FORCE_COLOR=1`）→ push → ドラフト PR
   （1 本にまとめてよい）。衝突しやすい組み合わせと既定の解き方:
   - **D × E — `config.py`**: D は横断的な整理、E は `ResponseSettings` / `DeceptionSettings` への追加のみ。両方を残す形で解決。
   - **D × E — `gate/`**: D は `gate/cli.py` と `GateSettings`、E は `gate/capture.py` / `proxy.py`。D が設定を proxy に渡す
     配線を変えた場合は E の変更を D の新しい配線に合わせる。
   - **B → E（依存）**: B の評価ハーネスは E の `deception.service.seed_defaults()` を使う（無ければフォールバックする仕様）。
     E を先にマージできれば、B のマージ後にフォールバックが使われていないことを確認する。
6. フェーズ 1 を全部マージしたら、フェーズ 2: A lab-validation / F security-review の 2 体。
   A は Docker が必要。第 1 波ではサンドボックスで dockerd を起動してビルドできた（`docs/handoff/2026-10-22-devops.md`）が、
   `docker compose up` でラボ全体を動かしたことはまだない（ネットワーク制約でイメージ取得に失敗する可能性あり。未確認）。
7. G live-llm-eval: ユーザーが予算と `ANTHROPIC_API_KEY`（環境のシークレット）を用意した場合のみ。
8. 区切りごとにこのファイルを更新する（§0 の進捗表、§1 の状態、§4 の次の一手）。

### 進捗（第 2 波）

| パッケージ | 仕様 | 状態 | ブランチ / PR | 作業ログ |
|---|---|---|---|---|
| B scoring-tuning | docs/tasks/wave2-scoring-tuning.md | 未着手 | — | — |
| C frontend-consolidation | docs/tasks/wave2-frontend-consolidation.md | 未着手 | — | — |
| D config-ops | docs/tasks/wave2-config-ops.md | 未着手 | — | — |
| E feature-gaps | docs/tasks/wave2-feature-gaps.md | 未着手 | — | — |
| A lab-validation | docs/tasks/wave2-lab-validation.md | 未着手（フェーズ 1 の後） | — | — |
| F security-review | docs/tasks/wave2-security-review.md | 未着手（フェーズ 1 の後） | — | — |
| G live-llm-eval | docs/tasks/wave2-live-llm-eval.md | 要ユーザー承認 | — | — |

### 第 2 波の完了条件（要件 v0.2 の M3〜M4 に対応）

- A: ラボで AI エージェント検知 → インシデント → 対処提案 → 人間承認 → Gate が 403 を返す、まで一気通貫で通る。
- B: シードで分けたテスト分割で P / R / F1 / AUC を報告し、回帰評価が CI に入る（30 秒以内）。
- C: 主要画面の Playwright E2E が実バックエンドに対して緑、初期 JS < 500KB。
- D: Alembic で起動、mypy が CI 必須で緑、保持期間パージが動く。
- E: 各機能にテスト（二者承認は既定 OFF）。
- F: `docs/security/review-wave2.md` を作成し、高以上の指摘は修正済み。

### 第 2 波の途中で必要になるユーザー判断（未回答なら既定で進める）

| 判断 | 関係するパッケージ | 未回答時の既定 |
|---|---|---|
| 対処の二者承認を必須にするか | E | 設定項目 `response.require_second_approver` を作り、既定 OFF |
| 実 LLM 評価の予算・実行可否 | G | 実行しない |
| robots.txt / llms.txt カナリアの有効化 | （設定のみ） | 既定 OFF のまま |
| AI カナリア文言の強さ・言語 | B（評価）, F（レビュー） | 現行の文言のまま評価・レビューし、所見を報告 |

### 見積もり（第 1 波の実測からの外挿・誤差 ±2 倍）

- フェーズ 1〜2（6 パッケージ）+ 統合: 延べ処理 約 0.7〜1.6 億トークン（大半はキャッシュ読み出し）、API 単価換算で約 $80〜200。
  サブスクリプション利用時は請求ではなく利用上限の消費として効く（5 時間枠で 1〜3 枠程度の見込み）。
- G（TOKIWA 自身が使う LLM の費用）: lab-mini 1 回 約 $1〜3、10 倍規模で約 $10〜30。

## 1. 現在の状態（第 1 波の結果サマリ）

- **第 1 波（18 モジュール）: 全て実装・統合済み**。`cd backend && uv run pytest` 緑（1,281 件・約 70 秒）、ruff クリーン、
  `cd frontend && npm run typecheck && npm run lint && npm run build && npx vitest run` 緑。
- **E2E（モック LLM）が通る**: `uv run tokiwa eval run --dataset ../eval/datasets/lab-mini.jsonl --llm mock --out <dir>`
  - 攻撃セッション検知 5/5、正常セッション誤検知 0%、アラート適合率 100%（87 件）、AI アトリビューション P/R/AUC = 1.0、
    取り込み→アラート p50 10ms、アラート→トリアージ p50 1.3s、31 検知器が稼働。
  - **注意（過大評価）**: データセットは検知器と同じ仮説から合成したもの。実トラフィック・ARTEX での検証が未了。
    human_attacker 2 セッション中 1 つが振る舞いスコアで benign 判定。モック LLM の actor 一致率は 13%（実 LLM 未評価）。
- Docker: devops 担当がサンドボックスで dockerd を起動してイメージビルド・スモーク・compose（SQLite/PostgreSQL）まで確認済み。
  GitHub Actions の CI（backend / frontend / docker build+smoke / infra lint）も PR #5 で全緑。`lab/compose.yaml` の `up` は未実行。

## 2. モジュール一覧（すべて main にマージ済み）

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

> パッケージ分けと手順は §0 と `docs/tasks/wave2-README.md` が正本。以下は第 1 波終了時点の課題の洗い出し（背景用）。

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

- **Wiki**: クラウドセッションの git プロキシはセッション対象のリポジトリしか認可しないため、セッションから
  `<repo>.wiki.git` に直接 push できない → 同期は GitHub Actions（`GITHUB_TOKEN`, `contents: write`）で行う。
  使い方・設定・CLI を変えたら `docs/wiki/` の日本語ページを直し、同じ PR で `-en` / `-zh` / `-es` にも反映、
  `python3 scripts/check_wiki.py` で確認（CI の infra lint でも実行）。詳細は `docs/wiki/README.md`。

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
- **実フィードでの初回実行（ユーザー環境, 2026-10-27）で gzip の二重解凍が露見**: `intel/sources/_common.fetch()` が解凍済み本文に
  `Content-Encoding` を残したまま Response を作り直していた → KEV/GHSA/RSS が `DecodingError`。修正済み。fixture を返す
  MockTransport は圧縮応答（`Content-Encoding: gzip`）も試すこと（サンドボックスからは実フィードに出られず検出できなかった）。
- `tokiwa serve --reload` は `reload_dirs` を tokiwa パッケージに限定（既定の backend/ だと data/ の SQLite 書き込みごとに
  watchfiles が "change detected" を出していた）。
- CI は `FORCE_COLOR=1` で動く → Typer/Rich の CLI 出力を文字列比較するテストは ANSI を除去してから判定する（`re.sub(r"\x1b\[[0-9;]*m", "", out)`）。ローカル再現は `FORCE_COLOR=1 uv run pytest`。
