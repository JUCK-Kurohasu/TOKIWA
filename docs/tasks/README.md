# タスク仕様（ワークパッケージ）

各ファイルが 1 モジュール分の作業単位。並列エージェント・別アカウントの Claude・人間のいずれが拾っても
同じ品質で進められるよう、**目的 / 担当範囲（触ってよいファイル）/ 要件 / 受け入れ基準** を書く。

## 進め方（全タスク共通）

1. `HANDOFF.md` → `AGENTS.md` → `docs/architecture.md` → `docs/api-contract.md` → 担当タスクを読む。
2. 既存の契約（`backend/src/tokiwa/schemas/`, `detect/base.py`, `llm/base.py`, `llm/gateway.py`, `runtime.py`,
   `bus.py`, `api/deps.py`, `frontend/src/routes.ts`, `frontend/src/api/*`）を読んで、それに合わせて実装する。
3. **担当範囲のファイルだけ** を作成・編集する。共有ファイルの変更が必要なら最小限にし、完了報告に明記。
4. テストを書く（外部ネットワークなし）。`cd backend && uv run pytest && uv run ruff check src tests &&
   uv run ruff format --check src tests` を通す。フロントは `npm run typecheck && npm run lint && npm run build`。
5. 小さくコミット（Conventional Commits）。最後に `docs/handoff/` に作業ログ（やったこと・未完・次の一手・
   他モジュールへの依頼・TODO(verify)）を 1 ファイル追加する。HANDOFF.md 本体は統合担当が更新する。

## 定義済みの完了条件（Definition of Done）
- 受け入れ基準をすべて満たし、テストが緑。
- 新しい設定項目・API・イベントトピックは docs（architecture / api-contract）に追記済み。
- 安全規約（AGENTS.md §2）に反していない。特に LLM 出力が実行系へ直結していない。

## 一覧

| ファイル | 内容 | 主な成果物 |
|---|---|---|
| detect-web.md | Web 攻撃の署名・レート検知 | detectors/web_*.py |
| sigma.md | Sigma 評価器・ルール管理 | detect/sigma/, detectors/sigma.py, routes/rules.py, routes/detectors.py |
| detect-ai.md | AI エージェント攻撃の振る舞い検知 | enrich/sessionizer.py, detectors/ai_*.py, detectors/llm_app_*.py, routes/sessions.py |
| sensors.md | ホスト・ログ・IDS センサー | sensors/, enrich/ports.py, detectors/port_*.py, net_*.py, routes/hosts.py |
| gate.md | リバースプロキシ・センサー/エンフォーサ | gate/ |
| deception.md | Mirage（デコイ/ハニートークン/AI カナリア） | deception/, detectors/deception_*.py, routes/deception.py |
| llm.md | LLM プロバイダ・設定・監査 API | llm/anthropic_provider.py, llm/openai_compat.py, routes/llm.py |
| triage-correlate.md | 相関・インシデント化・LLM トリアージ | correlate/, triage/, routes/alerts.py, routes/incidents.py |
| intel-feeds.md | 脆弱性フィード取り込み | intel/sources/, intel/store.py, intel/sync.py, intel/cli.py, routes/intel.py(一部) |
| intel-advisor.md | 資産照合・LLM 助言・Web リサーチ | intel/matcher.py, intel/advisor.py, intel/research.py, routes/assets.py, routes/intel_advice.py |
| respond.md | 対処ワークフロー・Gate ポリシー・通知 | respond/, notify/, routes/response.py, routes/gate.py, routes/notify.py |
| copilot.md | SOC コパイロット | copilot/, routes/copilot.py |
| api-core.md | ユーザー/トークン/イベント/ダッシュボード/システム/SSE | routes/users.py, tokens.py, events.py, dashboard.py, system.py, stream.py |
| frontend-core.md | ダッシュボード・イベント・セッション・ホスト・設定 | frontend/src/pages/{dashboard,events,sessions,hosts,settings} |
| frontend-ops.md | アラート・インシデント・対処・デセプション | frontend/src/pages/{alerts,incidents,response,deception} |
| frontend-intel.md | インテル・ルール・LLM・コパイロット・資産 | frontend/src/pages/{intel,rules,llm,copilot,assets} |
| lab-eval.md | ラボ環境・トラフィックシミュレータ・評価 | lab/, eval/, backend/src/tokiwa/eval/ |
| devops.md | Docker・CI・開発補助 | deploy/, .github/workflows/, scripts/ |
