# 生成AI / LLM エージェント攻撃の検知（detect-ai）設計

> 対象: FR-13（AI エージェント攻撃のアトリビューション）/ FR-14（LLM アプリへのプロンプトインジェクション）/
> FR-15（AI/LLM クライアント指紋・意味的偵察）。ADR-0006 の実装。
> **本書の特徴量・重みはすべて「仮説」に基づく初期値であり、実トラフィックでは未検証。** 合成セッション（テスト）での
> 分離は確認済みだが、それは「仮説どおりに作ったデータで仮説どおりに分類できる」ことしか示さない。
> 実運用前に lab-eval の評価ハーネスと ARTEX 演習で再調整すること（§8）。

## 1. 何を区別するか

| 分類 (`ActorType`) | 意味 |
|---|---|
| `ai_agent` | LLM が意思決定する自律エージェント（ARTEX 型）。AI スコア ≥ `detection.ai_agent_threshold`（既定 0.7）、または AI カナリア追従 |
| `automated_scanner` | 応答に依存しない従来型スキャナ（固定ワードリスト・一定高速） |
| `human` | 攻撃意図はあるが AI/スキャナに帰属できない活動（手動の攻撃者である可能性が高い） |
| `benign` | 攻撃意図の兆候がない正常利用（主に実ブラウザ） |
| `unknown` | リクエスト数不足（< 5）や判断材料不足 |

単位は **アクターセッション** = `source_ip` + クライアント指紋（UA + 安定ヘッダ名集合のハッシュ）、
アイドル `detection.session_idle_timeout_seconds`（既定 1800 秒、**イベント時刻** 基準）で分割。

## 2. 事実（観測・確認済み）と仮説の区別

### 2.1 事実として確認したこと
- ARTEX-JP（`/home/user/artex-jp`、AGPL のため参照のみ・コード非複製）のコードを読んで確認:
  - ワーカーエージェントは Bash サブプロセス経由で curl / python(urllib, requests) / node / git / Playwright 等を実行し、
    HTTP はそれらツールの既定 UA・既定ヘッダで送られる（`agent/worker.go` の proxyEnv が各ツール向け CA 変数を設定）。
  - 偵察スキル `skills/api-recon` は静的 JS バンドルを並列取得（ThreadPoolExecutor, max_workers=20〜24）してから
    API ルートを抽出し、その後ランタイム（Puppeteer/ブラウザ）で列挙する手順。UA は
    `Mozilla/5.0 (spa-api-recon)` のような **Mozilla 接頭辞だが実ブラウザのエンジントークンを持たない** 文字列。
  - ワーカーのプロンプトは「最初に阻まれても（フィルタ/404/無反応）探り尽くしたことにはならない。回避手段を試し尽くせ」
    と指示している → エラー後の変種試行が設計上起こる。
  - LLM 呼び出しは推論（thinking / effort）付きモデルに対応しており、ツール呼び出しの間に推論待ちが入る。
  - ツールは並列実行可能（`Concurrent` フラグ）、複数ワーカーが並列にインテントを処理する。
- ブラウザの Client Hints（`sec-ch-ua*`）と Fetch Metadata（`sec-fetch-*`）は安全なコンテキスト（HTTPS / localhost）
  でしか送られない（このため HTTP では欠落を異常扱いしない）。
- MCP Streamable HTTP は `Mcp-Session-Id` / `MCP-Protocol-Version` ヘッダを使う。OpenAI / Anthropic の公式 SDK
  （Stainless 生成）は `X-Stainless-*` ヘッダを送る。

### 2.2 仮説（評価で検証が必要）
| ID | 仮説 | 対応する特徴量 |
|---|---|---|
| H1 | **思考待ちのリズム**: 並列ツール呼び出しのバースト（< 0.3 s）と LLM 推論待ち（1〜60 s）が交互に現れる。人間は不規則で長い、スキャナは一定高速 | `burst_frac`, `think_frac`, `bursts`, `think_gap_cv`, `bimodality_coef` |
| H1' | LLM の推論待ちは人間の間隔より相対的に規則的（CV が小さい） | `think_gap_cv` |
| H2 | **応答条件付き変異**: エラー応答（500/400/WAF 403）直後、推論待ちを挟んで同一エンドポイント・同一パラメータに変種を送る。スキャナは応答に関係なく即座に固定リストを撃つ | `adaptive_mutations`, `reflexive_mutations`, `mutation_chain_max`, `mutation_conditionality` |
| H3 | **意味的探索**: OpenAPI / GraphQL introspection / robots / JS / AI エコシステム（MCP, ai-plugin, llms.txt）を読んでから、リンクされていない **実在** ルート（非 404）を Referer なしで直接叩く | `spec_fetches`, `api_after_discovery_hits`, `discovered_hit_rate`, `ai_ecosystem_probes` |
| H4 | **自然言語の痕跡**: ペイロードのコメントやカスタムヘッダに説明文（英/日）を書く | `nl_attack_payloads`, `nl_score_max` |
| H5 | **ツール指紋**: HTTP ライブラリ / CLI / ヘッドレス / AI 系 UA / LLM SDK ヘッダ、ブラウザ詐称（UA はブラウザなのにヘッダ集合はライブラリ） | `client_family`, `header_anomalies`, `llm_sdk_headers` |
| H6 | **AI カナリア追従**: デコイ内の隠し指示（deception モジュール）に従う → ほぼ決定的 | `canary_hits` |

## 3. データフロー

```
ingest → pipeline.process_events
  └ enrich: Sessionizer (enrich/sessionizer.py, order=50)
      SessionTracker.observe_batch(events)   ← メモリ内・同期・I/O なし
        - HTTP: session_id 付与 / RequestObs 生成 / 同一エンドポイント直前要求との関係を annotate
        - 非 HTTP（deception / llm_app）: 同一 IP の直近セッションへ紐付け（canary_hits 等）
        - 触れたセッションをバッチ末尾で 1 回だけ再スコア（features → scoring）
      条件付きでバッチ upsert → actor_sessions（incident_id は書かない）
  └ detect: ai.* / llm_app.* 検知器（ai.agent_session は tracker のスナップショットを読む）
  └ store events（events.session_id 列に入る）+ alerts
```

- メモリ上限: セッション数 `Sessionizer.max_sessions`（既定 4096, LRU）× 観測窓 `max_obs`（既定 256 件/セッション）。
  特徴量は **直近 256 要求の窓** で計算、`request_count` / `error_count` / `unique_paths` はセッション全体。
- 永続化: 前回から `flush_interval_seconds`（1 s）経過 / dirty ≥ `flush_max_dirty`（256）/ 分類変化のいずれかで 1 トランザクション。
  加えて定期ジョブ `aidetect.sessions_flush`（5 s）、シャットダウン時、`GET /sessions*` 直前に flush。
- `ai_score` は **ピーク値**、`ai_agent` 判定は **粘着**（後で静かになっても AI 判定を失わない）。
  現在窓のスコアは `features.ai_score_current`。
- 大きいセッション（≥128 観測）への少量追加は最短 2 s 間隔で再スコア（stale 扱い、永続化前に必ず再計算）。

## 4. 特徴量（`aidetect/features.py`、純粋関数）

| グループ | 特徴量 | 定義 |
|---|---|---|
| タイミング | `gap_median_ms`, `gap_p90_ms`, `gap_cv` | 到着間隔の分布（静的アセットを除いた「能動」要求が 6 件以上ならそれで計算、`timing_basis`） |
| | `burst_frac` / `mid_frac` / `think_frac` / `long_frac` | 間隔が < 0.3 s / 0.3〜1 s / 1〜60 s / > 60 s の割合 |
| | `bursts`, `mean_burst_size` | 2 件以上のバースト（間隔 < 0.3 s で連結）の数・平均サイズ |
| | `think_gap_median_ms`, `think_gap_cv`, `n_think_gaps` | 思考帯の間隔の中央値・変動係数 |
| | `bimodality_coef` | log10(間隔) に対する Sarle の二峰性係数（> 0.555 で多峰の目安。説明用、重みなし） |
| | `rps` | 要求数 / 継続時間 |
| エラー | `error_rate`, `not_found_rate`, `server_error_rate`, `blocked_rate` | ステータス比率（blocked = 403/406/429） |
| 変異 | `adaptive_mutations` | 直前（同一 method+パステンプレート、180 s 以内）がエラー、かつ今回が「変種」、かつ間隔 ≥ 0.8 s |
| | `reflexive_mutations` | 変種だが間隔 < 0.8 s（応答を読んでいない＝ファジング） |
| | `post_error_mutation_rate`, `mutation_conditionality` | P(変種|直前エラー)、P(変種|エラー) − P(変種|成功) |
| | `mutation_chain_max`, `mutation_think_gap_median_ms`, `mutation_similarity_median` | 連鎖長・変異前の間隔・類似度 |
| 探索 | `spec_fetches`, `js_fetches`, `ai_ecosystem_probes`, `discovery_kinds`, `graphql_introspection` | `aidetect/recon.py` のカタログ |
| | `api_after_discovery`, `api_after_discovery_hits`, `discovered_hit_rate` | 探索源取得後 300 s 以内の、未出・Referer なし・非静的ルート（hits = 非 404） |
| | `new_path_rate`, `path_diversity`, `referer_ratio`, `static_ratio` | パス多様性・新規率・Referer 率・静的率 |
| ペイロード | `payload_ratio`, `attack_requests`, `attack_ratio`, `attack_families` | 軽量攻撃マーカー（`payloads.attack_markers`。正式な署名検知は detect-web） |
| | `payload_uniqueness`, `payload_entropy_mean` | 一意率・文字エントロピー（bit/char） |
| | `nl_attack_payloads`, `nl_score_max` | 攻撃マーカーを含み自然言語スコア ≥ 0.55 の要求数 |
| | `semantic_token_ratio` | test/verify/probe 等の「意味のある値」の割合（説明用、重みなし） |
| 指紋 | `client_family`, `client_tool`, `ai_declared_client`, `header_anomalies`, `llm_sdk_headers`, `has_accept_language` | `aidetect/fingerprints.py` |
| 外部 | `canary_hits`, `decoy_hits`, `llm_app_prompts`, `ip_tool_fingerprints` | deception / llm_app イベント、同一 IP の非ブラウザ指紋数 |

**変種（variant）の定義**: ペイロード署名（パラメータ値をキー順に連結、256 文字まで）が異なり、パラメータ名の
Jaccard ≥ 0.5、かつ類似度 `max(trigram Jaccard, 0.85 × overlap 係数)` が 0.15 以上 0.97 未満。
overlap 係数を混ぜるのは、`laptop'` → `laptop' OR '1'='1' --` のような「追記型」の変異を Jaccard だけだと
無関係と誤判定するため。パス中の注入（`/users/1'`）は `{p}` に正規化しパラメータ `_pathN` として扱う。

**自然言語スコア**（`payloads.natural_language_score`）: 英語はコード語（SQL/JS/シェル）を除いた単語の機能語率
（4 語以上かつ 2 種以上の機能語が必要）、日本語は和文字数・ひらがな率・機能表現（です/ます/確認/かどうか…）。
コメント（`--`, `/* */`, `<!-- -->`, `#`）内は別途評価して +0.1。言語モデルではない。

## 5. スコアリング（`aidetect/scoring.py` — 調整箇所はこのファイルのみ）

特徴量 → 0..1 の **シグナル**（`signals()`）→ 3 つの重み付きロジスティック（`sigmoid(bias + Σ w·s)`）:

### AI ヘッド（`ai_score`）bias = −3.4
| シグナル | 重み | 根拠 |
|---|---:|---|
| `burst_think_rhythm` = 2·min(burst, think) × 充足率(間隔 8) | +1.7 | H1 |
| `regular_think_gaps` = 1 − CV/1.2（思考帯 ≥4 で満額, バーストが無いと半減） | +0.6 | H1' |
| `adaptive_mutation` = adaptive/3 | +2.4 | H2 |
| `discovery_then_use` = hits/4 × hit_rate | +1.8 | H3 |
| `spec_discovery` = spec/2 | +0.6 | H3 |
| `ai_ecosystem_probe` | +1.2 | H3 |
| `natural_language_payload` = nl_attack/2 | +1.6 | H4 |
| `ai_declared_client`（AI エージェント UA=1, AI クローラ=0.5） | +1.4 | H5（詐称容易なので弱め） |
| `llm_sdk_headers` | +1.0 | H5 |
| `automation_client`（ライブラリ/CLI/ヘッドレス/非標準 Mozilla/空 UA） | +0.7 | H5 |
| `browser_claim_mismatch` | +0.8 | H5 |
| `attack_payloads` = attack/3 | +0.5 | 攻撃意図（AI/人間は区別しない） |
| `multi_tool_source` =(同一 IP の非ブラウザ指紋数 −1)/2 | +0.5 | ARTEX の複数ワーカー/ツール |
| `ai_canary_followed` | +8.0 | H6（さらに `ai_score ≥ 0.99` に床上げ） |
| `sustained_high_rate` =(rps−2)/6 × (1−4·think) × 充足率(20) | −2.6 | スキャナ |
| `wordlist_enumeration` = 404 率と新規パス率の積 × 充足率(20) | −2.0 | スキャナ |
| `scanner_client` | −2.2 | スキャナ UA |
| `reflexive_fuzzing` = reflexive/6 | −1.2 | 応答非依存 |
| `browser_consistent`（ブラウザ・不整合なし: 0.5 + Referer + 静的） | −2.0 | 正常ブラウザ |
| `sparse_irregular_pacing` =(CV−1) × (1−3·burst) | −0.8 | 人間的間隔 |

### スキャナヘッド（bias −2.6）/ 敵対性ヘッド（bias −2.2）
`SCANNER_WEIGHTS` / `HOSTILE_WEIGHTS` を参照（同ファイル）。敵対性は攻撃ペイロード（+3.6）、デコイ接触（+4.0）、
ワードリスト（+2.4）等で上がり、ブラウザ一貫性（−0.8）で下がる。

### 分類規則（上から順に最初に一致）
カナリア追従 → `ai_agent` / 要求 < 5 → `unknown` / AI ≥ 閾値 → `ai_agent` / スキャナ ≥ 0.6 → `automated_scanner` /
敵対性 ≥ 0.5 → `human` / 敵対性 < 0.35 かつ（ブラウザ一貫 or 非自動化クライアント）→ `benign` / それ以外 `unknown`。

### 根拠（indicators）
`features.indicators` に寄与の大きい順で最大 10 件: `{key, ja, en, signal, weight, contribution, direction(for/against), evidence}`。
`evidence` は特徴量の実値の短い要約（例: `adaptive=3 reflexive=0 chain_max=4 think_gap_ms=5210`）。反証（負の寄与）も含む。
`features.scores = {ai, scanner, hostile}`、`features.signals`（>0 のもの）も保存。

## 6. 検知器カタログ

| id | 内容 | 重大度 | ai_score | fingerprint |
|---|---|---|---|---|
| `ai.agent_session` | セッションのピーク AI スコアが閾値到達時に 1 回、以後 +0.05 上昇ごと | MEDIUM / ≥0.9 HIGH / カナリア CRITICAL | セッションの値 | `ai.agent_session\|<session_id>` |
| `ai.adaptive_mutation` | エラー後の同一エンドポイント変種連鎖 ≥3、うち推論待ち付き ≥2（3 連鎖ごとに再通知） | MEDIUM / 連鎖 ≥6 または連鎖末尾が成功（回避成功の疑い）HIGH | 0.5 + 0.08×adaptive（≤0.9） | `…\|actor\|endpoint` |
| `ai.llm_client_fingerprint` | AI エージェント/クローラ UA、エージェント FW、`x-stainless-*`、MCP ヘッダ（アクター×ツールで 1 回） | クローラ INFO / その他 LOW / 攻撃ペイロード同伴 MEDIUM | 0.3〜0.8 | `…\|ip\|tool` |
| `ai.semantic_recon` | (a) AI エコシステム探索（MCP/ai-plugin/llms.txt/agent card）LOW、(b) 仕様取得後 300 s 以内に未出・Referer なし・実在ルート ≥3（robots/sitemap/Referer なし JS 後は ≥5）。新規ルートの非 404 率 ≥ 50% が条件 | (a) LOW (b) MEDIUM / 弱い源 LOW | 0.45〜0.6 | `…\|eco\|…` / `…\|enum\|…` |
| `ai.natural_language_payload` | 攻撃マーカー + 自然言語スコア ≥0.55（コメント・カスタムヘッダ含む、英/日）。LLM アプリパスは除外 | MEDIUM | 0.55 + 0.3×NL | `…\|ip\|template` |
| `llm_app.prompt_injection` | `detection.llm_app_paths` 宛て HTTP（JSON チャット本文、system/developer ロールは除外）または `EventKind.LLM_APP` | 1 系統 LOW〜MEDIUM / ≥3 系統・高影響（ツール濫用・外部送信・難読化）HIGH | なし | `…\|ip\|app\|families` |

全検知器が `entities.session_id`（セッション化済みの場合）を付けるので、correlate はセッション単位で束ねられる。
`llm_app.prompt_injection` の MITRE は ATLAS（AML.T0051 プロンプトインジェクション、AML.T0054 ジェイルブレイク）。
TODO(verify): システムプロンプト抽出・データ漏えいの ATLAS ID は未確認のため付与していない。

### プロンプトインジェクションの系統（`aidetect/prompt_injection.py`、英/日）
指示上書き / システムプロンプト抽出 / ロールプレイ脱獄（DAN・開発者モード・制限のない AI）/ 難読化指示（Base64 内の指示を
1 段デコードして再判定、Unicode タグ文字（ASCII smuggling）を復元して再判定、不可視・双方向制御文字の多用）/
ツール濫用誘導（メール送信・削除・コマンド実行・全履歴送信）/ Markdown・HTML 画像による外部送信（URL クエリにデータ・
`{conversation}` 等のプレースホルダ）/ 偽ロール区切り（`<|im_start|>`, `[INST]`, `</system>`）。
入力は NFKC 正規化・8 KB 上限・有界の正規表現（ReDoS 対策）。

## 7. 既知の限界（正直に）

1. **共有 IP（NAT / VPN / CGNAT / 企業プロキシ）**: キーは IP + 指紋なので、同じ UA の複数人が 1 セッションに混ざる
   （リズム特徴が壊れ、誤って burst/think に見えることも、逆に消えることもある）。`ip_tool_fingerprints` も膨らむ。
2. **1 つのエージェントが複数セッションに分かれる**: ARTEX のようにツールごとに UA が違う（curl / python / Playwright）と
   指紋が分かれ、各セッションの証拠が薄まる。`multi_tool_source` で一部補うが、IP 横断の「アクター」集約は未実装。
3. **遅い人間・速い人間**: Burp Repeater で丁寧に変異させる熟練者は H2 を満たしうる（ただしブラウザ一貫性・バースト
   欠如で抑制）。逆にスクリプト化した人間は「自動化」に見える。`human` は「AI/スキャナに帰属できない敵対的活動」の意味。
4. **LLM の高速化・並列化でリズムが変わる**: 推論が 1 s を切るモデルや、多数の並列ワーカーで要求が常時流れると
   思考帯が消え、スキャナ寄りに見える。逆に人間の思考時間に寄せたランダム遅延で H1 は回避できる。
5. **回避策への脆弱性**: UA/ヘッダ偽装（H5 は無力化される）、Referer 付与（H3 の Referer 条件を回避）、
   ペイロードからコメントを除く（H4）、エラー後に別エンドポイントへ切り替える（H2）。決定的なのは H6（カナリア）だけ。
6. **可視性**: ボディ・ヘッダ・ヘッダ順は Gate 経由でのみ取得できる。nginx 等のログでは UA とパスだけで、
   H4（ボディ）・ブラウザ詐称検知・ヘッダ欠落判定は働かない（欠落判定はヘッダ 3 個以上の捕捉時のみ）。
   HTTP（非 TLS）では Client Hints / Fetch Metadata の欠落を判定しない。新しい headless Chrome は通常 UA を使う。
7. **ヘッダ順序の不自然さ**: 仕様にある特徴だが、ブラウザ・HTTP バージョン別の正しい順序を確証できていないため
   **未実装**（`header_order` は保存されている）。TODO(verify)。
8. **ウィンドウ化**: 特徴量は直近 256 要求。極端に長いセッションの初期挙動は `peak` スコアと indicators にしか残らない。
   プロセス再起動でメモリ上の状態は失われる（DB の `actor_sessions` は残るが、再開後は新セッションになる）。
9. **自然言語ヒューリスティック**: 英語の機能語・日本語のひらがな率に依存。その他の言語、短い説明文、コード中心の
   ペイロードでは働かない。正規の問い合わせフォームに攻撃風文字列＋文章があれば誤検知しうる（攻撃マーカー必須で抑制）。
10. **プロンプトインジェクション**: パターン照合なので言い換えに弱く、攻撃について「論じる」文章で誤検知しうる。
    重大度を系統数・強度で段階化し、最終判断は LLM トリアージと人間に委ねる。
11. **重みは手設定**: 合成データで分離できることのみ確認（6 プロファイル × 5〜8 シードで 100%、AI スコアは AI 系 ≥0.98、
    他は < 0.03）。合成データは仮説どおりに作っているため **過大評価** である。

## 8. 調整ポイント（どこを触るか）

| 何を | どこで |
|---|---|
| 重み・バイアス・分類閾値 | `aidetect/scoring.py`（`AI_WEIGHTS`, `SCANNER_WEIGHTS`, `HOSTILE_WEIGHTS`, `*_BIAS`, `SCANNER_THRESHOLD`, `HOSTILE_THRESHOLD`, `BENIGN_MAX_HOSTILE`, `MIN_REQUESTS_FOR_VERDICT`） |
| シグナルの正規化（何件で満額か） | `aidetect/scoring.py` `signals()` |
| 時間帯の境界・変異/探索の窓 | `aidetect/features.py`（`BURST_GAP_S`, `THINK_MIN_S`, `THINK_MAX_S`, `MUTATION_*`, `ADAPTIVE_MIN_GAP_S`, `DISCOVERY_WINDOW_S`） |
| AI 判定の閾値・アイドル | `config.py` `detection.ai_agent_threshold`, `detection.session_idle_timeout_seconds`（env `TOKIWA_DETECTION__...`） |
| メモリ・永続化頻度 | `enrich/sessionizer.py` `Sessionizer.max_sessions / max_obs / flush_interval_seconds / flush_max_dirty` |
| UA / SDK ヘッダ / 探索パスの一覧 | `aidetect/fingerprints.py` `_UA_RULES`、`aidetect/recon.py` `_PATH_RULES` |
| 検知器のしきい値 | 各 `detect/detectors/ai_*.py` 冒頭の定数（`MIN_CHAIN`, `MIN_ENUM_STRONG`, `NL_THRESHOLD` …） |
| LLM アプリの保護パス | `config.py` `detection.llm_app_paths` |

推奨手順: lab-eval のデータセット（ラベル付き）で `tokiwa eval run` → AI アトリビューションの precision/recall/AUC を見て
重みを変更 → `backend/tests/aidetect/test_ai_scoring.py` が通ること（合成データでの退行防止）を確認。

## 9. 安全性

- 検知は純粋なルール計算で、LLM を呼ばない（トリアージ側が呼ぶ）。特徴量・indicators・スニペットは攻撃者制御の文字列を
  含みうるので、LLM へ渡す側は必ず `untrusted_block()` で包むこと（AGENTS.md §2-1）。
- スニペットは 160 文字までに切り詰め、ペイロード本体は永続化しない（観測窓には署名ハッシュのみ保持）。
