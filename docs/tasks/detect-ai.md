# タスク: detect-ai — 生成AI/LLM エージェント攻撃の振る舞い検知（TOKIWA の中核）

## 目的
ARTEX のような自律 AI ペンテストエージェントや LLM を使った攻撃者を、人間の攻撃者・従来型スキャナ・正常利用者
から区別する。単発の署名ではなく **アクターセッション単位の振る舞い特徴量** でアトリビューションし、
説明可能なスコア（0..1）と根拠（indicators）を出す。

## 担当範囲
- `backend/src/tokiwa/enrich/sessionizer.py`（Enricher: `event.session_id` 付与・特徴量更新・`actor_sessions` 永続化）
- `backend/src/tokiwa/aidetect/`（新規パッケージ: features.py, scoring.py, payloads.py, fingerprints.py）
- `backend/src/tokiwa/detect/detectors/ai_*.py`, `backend/src/tokiwa/detect/detectors/llm_app_*.py`
- `backend/src/tokiwa/api/routes/sessions.py`
- `backend/tests/aidetect/`、`docs/detection/ai-attacks.md`（設計根拠・特徴量・既知の限界を詳しく）

## 背景（設計の前提。推測を含むので docs に「仮説」として明記し、評価で検証すること）
AI エージェントの観測可能な特徴（仮説）:
- **思考待ちのリズム**: ツール呼び出しのバースト（並列リクエスト数件が数十 ms 内）→ LLM 推論待ちのギャップ
  （数秒〜数十秒）の反復。人間はより不規則、スキャナは一定高速。
- **応答条件付きの変異**: エラー（500/400/WAF 403）直後に同一エンドポイント・同一パラメータへの
  ペイロード変種（エンコード違い・構文修正）が続く。スキャナは応答に関係なく固定ワードリスト。
- **意味的に一貫した探索**: JS/HTML/OpenAPI から抽出した API ルートを、リンクされていないのに直後に叩く。
  robots.txt の Disallow → その直後にそのパス。GraphQL introspection → 具体的クエリ。
- **自然言語の痕跡**: ペイロード/ヘッダ/パラメータ内のコメントや説明文、LLM らしい丁寧な文、
  「test」「verify」等の命名、ランダムでない意味のある値。
- **ツール指紋**: python-httpx / aiohttp / Go-http-client / node-fetch / undici / curl / Playwright・HeadlessChrome、
  MCP クライアント、`Claude-User` `ChatGPT-User` `GPTBot` `PerplexityBot` 等の UA、ヘッダ順序の不自然さ、
  Accept-Language 欠落 + 高度な攻撃の組合せ。
- **AI カナリア追従**: デコイ内の隠し指示（deception モジュール）に従ったリクエスト → 決定的証拠。

## 要件
1. Sessionizer: キー = `source_ip` + クライアント指紋（UA + ヘッダ名集合のハッシュ）。アイドル
   `detection.session_idle_timeout_seconds` で分割。メモリ上の状態（上限・LRU）+ 一定間隔/閾値で
   `actor_sessions` に upsert。イベントに `session_id` を付与（DB の events 列にも入る）。
2. 特徴量（`aidetect/features.py`、純粋関数でテスト容易に）: 到着間隔の分布（中央値・CV・バースト率・
   ギャップの二峰性）、パス多様性・新規パス率、エラー率と「エラー後変異率」（連続リクエストの編集距離・
   同一パラメータ再試行）、ペイロード多様性（エントロピー）、発見→利用の遅延（リンク抽出が無いので
   近似: 静的アセット（.js）取得直後の未知 API パス初出）、ヘッダ指紋、自然言語スコア（英語/日本語の
   単語比率・文らしさのヒューリスティクス）。
3. スコアリング（`aidetect/scoring.py`）: 説明可能な重み付きロジスティック（係数はファイル定数、
   評価で調整できるよう 1 か所に集約）。`classification` = ai_agent / automated_scanner / human / benign / unknown。
   根拠 indicators（日本語/英語のキー）を features に保存。閾値は `detection.ai_agent_threshold`。
4. 検知器:
   - `ai.agent_session`（セッションのスコアが閾値を超えた時点で 1 回、以後スコア上昇時に更新。ai_score 付き）
   - `ai.adaptive_mutation`（エラー応答後の同一パラメータ変異連鎖）
   - `ai.llm_client_fingerprint`（AI/LLM 系 UA・ヘッダ指紋。単独では low）
   - `ai.semantic_recon`（OpenAPI/Swagger/GraphQL introspection/.well-known/ai-plugin/MCP 探索 + 直後の API 列挙）
   - `ai.natural_language_payload`（攻撃ペイロード中の自然言語説明文）
   - `llm_app.prompt_injection`（`detection.llm_app_paths` 宛て、または `EventKind.LLM_APP` の prompt に対する
     インジェクション/ジェイルブレイク検知: 指示上書き、システムプロンプト抽出、ロールプレイ脱獄、
     Base64/Unicode 難読化指示、ツール濫用誘導、Markdown 画像による外部送信）。日英両方の定型句。
5. API `routes/sessions.py`（docs/api-contract.md 参照）。timeline は到着間隔（gap_ms）を含め UI で
   リズムを可視化できる形にする。
6. テスト: 合成セッション（AI エージェント風・人間風・スキャナ風・正常ブラウザ風）を生成するヘルパで
   分類が期待どおりになること。lab-eval のシミュレータとは独立に、テスト内で決定的に生成する。

## 受け入れ基準
- 4 種の合成セッションで分類精度 100%（テスト）。各検知器の陽性/陰性テスト。
- `docs/detection/ai-attacks.md` に特徴量・重み・仮説・限界（VPN/NAT 共有 IP、遅い人間、LLM の高速化で
  リズムが変わる可能性、回避策への脆弱性）を記載。
