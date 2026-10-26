# eval/ — 評価データセットと評価結果

TOKIWA の検知・AI アトリビューション・LLM トリアージを **ラベル付きデータセット** で測るための置き場。
コードは `backend/src/tokiwa/eval/`、CLI は `tokiwa sim ...` / `tokiwa eval ...`。

```
eval/
├── datasets/            ラベル付きデータセット（JSONL）。小さいものだけコミット
│   ├── lab-mini.jsonl   5 プロファイル入りの最小セット（seed 42, 248 events / 8 sessions）
│   └── lab-mini.meta.json   生成条件（seed, mix, generator_version）と集計
└── runs/                `tokiwa eval run` の出力（gitignore 済み）
    └── <UTC ts>/metrics.json, report.md
```

## 使い方（`backend/` で実行）

```bash
uv run tokiwa sim profiles                                      # プロファイル一覧
uv run tokiwa sim generate --out ../eval/datasets/mix.jsonl     # 既定ミックス（16 sessions, seed 1）
uv run tokiwa sim generate --out ../eval/datasets/ai.jsonl --profile ai_agent=5,benign_browser=10 --seed 7
uv run tokiwa eval run --dataset ../eval/datasets/lab-mini.jsonl                 # mock LLM（無料・オフライン）
uv run tokiwa eval run --dataset ... --compare ../eval/runs/<前回> --fail-on-regression
uv run tokiwa eval run --dataset ... --llm live --budget-usd 0.50                # 実 LLM（費用が発生）
uv run tokiwa eval compare ../eval/runs/<今回> ../eval/runs/<前回>
uv run tokiwa eval import-artex <ARTEX traffic> --out ../eval/datasets/artex-x.jsonl --host gate
uv run tokiwa eval info ../eval/datasets/lab-mini.jsonl
```

同じ seed・オプションなら生成ファイルはバイト単位で同一（ID も seed から決定的に作る）。

## データセット形式

1 行 1 `Event`（`schemas/events.py`）。正解は `labels`:

| key | 値 |
|---|---|
| `actor` | `benign` / `automated_scanner` / `human` / `ai_agent`（`ActorType`） |
| `profile` | `benign_browser` / `scanner` / `human_attacker` / `ai_agent` / `llm_app_attacker` / `artex` |
| `session` | 正解セッション ID（例 `ai_agent-01`） |
| `attack` | `none` / `recon` / `sqli` / `xss` / `path_traversal` / `cmd_injection` / `ssti` / `log4shell` / `idor` / `prompt_injection` / `ai_canary_follow` / `artex` |
| `phase` | プロファイル内の段階（recon / enumerate / exploit / canary ...） |

ハーネスは再生前に `labels`（と `sim:`/`label:`/`truth:` で始まる tag）を **除去** する。検知器や LLM は正解を見ない。

## 評価の流れと指標

`tokiwa eval run` は一時 SQLite（`<out>/work`、終了後削除。`--keep-work` で保持）で、サーバーと同じく
サービスパッケージと `@on_startup` フックを起動（定期ジョブなし）→ イベントを Gate 相当のバッチ（1 秒窓・最大 100 件）で
`pipeline.process_events` に投入 → バスの drain（非同期トリアージ完了）を待ち → alerts / incidents / actor_sessions /
llm_calls を読み戻して採点する。時刻は「最後のイベント = 現在」にずらす（相対時刻＝リズム特徴は保存）。
`--speed 1` で実時間、`--speed 10` で 10 倍速の再生。

| 指標 | 定義 |
|---|---|
| attack session detection rate | アラートが 1 件以上帰属した攻撃セッション / 攻撃セッション（プロファイル別も） |
| benign session FPR | アラートが帰属した正常セッション / 正常セッション（全重大度 / medium 以上） |
| event recall | 攻撃ラベルのイベントのうちアラート証拠に含まれた割合（**下限値**: 窓集計型は一部の証拠しか引用しない） |
| benign event FPR | 正常アクターのイベントのうち証拠に含まれた割合 |
| alert precision | 攻撃セッションのみに帰属したアラート / 何らかに帰属したアラート。検知器別にも出す |
| AI attribution P/R/F1/AUC | セッションスコア = max(actor_session.ai_score, alert.ai_score, triage.ai_agent_likelihood)。`detection.ai_agent_threshold` 以上、または sessionizer の分類が `ai_agent` で AI と判定。AUC は Mann–Whitney |
| LLM agreement | トリアージ済みアラート/インシデントで actor_type・悪性判定・AI 判定が正解と一致した割合（tier 別件数） |
| cost | `llm_calls` のトークン・USD 合計、アラートあたり / トリアージあたり |
| latency | バッチ処理時間（取り込み→アラート）p50/p95、アラート→トリアージ p50/p95（バス観測、無ければ DB の updated_at） |

アラートの正解帰属は `evidence_event_ids` 経由が基本。証拠に正解付きイベントが無い場合のみ `source_ip` で帰属する
（シミュレータはセッションごとに別の送信元 IP を使う）。

## 回帰比較（要件 7-6）

`--compare` は主要指標を前回の `metrics.json` と比較し、許容幅（率は ±0.02 など、コスト・遅延は相対）を超えて
悪化したものを `regressions` に列挙する。`--fail-on-regression` で CI ゲートにできる。許容幅は
`backend/src/tokiwa/eval/report.py` の `KEY_METRICS` で調整する。

## 調整できるところ

- プロファイルの振る舞い（間隔分布・バースト幅・変異戦略）: `tokiwa/eval/profiles.py`, `payloads.py`
- 生成ミックス・セッション数: `--profile name=count,...`、既定は `profiles.DEFAULT_MIX`
- 被害アプリのモデル（オフライン）: `tokiwa/eval/virtual.py`（`lab/victim/app.py` と同期。パリティテストあり）
- 指標の許容幅: `report.KEY_METRICS`。AI 判定閾値: `TOKIWA_DETECTION__AI_AGENT_THRESHOLD`

## 既知の限界

- シミュレータのリズム・変異は **仮説のモデル**（docs/tasks/detect-ai.md）。実 AI エージェント（ARTEX）での検証は
  docs/purple-team.md の手順で行うこと。シミュレータで高得点でも実環境の保証にはならない。
- オフライン生成は Gate のデセプション（デコイ応答・HTML 注入カナリア）をモデル化していない。被害アプリ自身の
  ラボ用カナリア（`/api/internal/debug` + `X-Debug-Auth`）のみ。`/api/internal/debug` は既定のデコイパス。
- オフライン再生の DB にはデセプション資産が無いため、カナリアトークン一致による検知は live ラボでのみ評価できる。
