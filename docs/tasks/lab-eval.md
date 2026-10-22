# タスク: lab-eval — ラボ環境・トラフィックシミュレータ・評価ハーネス

## 目的
P0/P3 受け入れ基準: `docker compose up` でラボ（被監視アプリ + Gate + TOKIWA）が再現でき、評価セットで
検知率・誤検知率・LLM 一致率・1 件あたりコストを測れること。ARTEX と組み合わせたパープルチーム演習の土台。

## 担当範囲
- `lab/`（compose.yaml, victim/（被監視デモアプリ）, nginx/（JSON ログ設定は sensors と調整: `lab/nginx/` は
  sensors 担当が設定ファイルを置くので、compose からはそれを参照するだけにする）, README.md）
- `backend/src/tokiwa/eval/`（sim.py, profiles.py, dataset.py, harness.py, metrics.py, report.py, cli.py, sim_cli.py）
- `eval/datasets/`（生成したラベル付きデータセット: 小さいものだけコミット）, `eval/README.md`
- `backend/tests/eval/`、`docs/purple-team.md`（ARTEX との演習手順）

## 要件
1. victim（被監視アプリ）: 小さな FastAPI アプリ（Python, 依存は fastapi/uvicorn のみ）。ログイン、検索、商品 API、
   ファイルダウンロード風エンドポイント、簡易「AI チャット」エンドポイント（`/api/chat`: 固定応答。プロンプト
   インジェクション検知の対象）、OpenAPI 公開、JS バンドル（API ルートを含む）。**実際には脆弱でない**
   （入力は使わず定型応答）。ただしエラー応答は返す（500/400 を一定条件で）— AI エージェントの適応挙動を誘発するため。
2. compose: `tokiwa`（server, 8788）、`gate`（8080 → victim）、`victim`、`agent`（ホストセンサー、任意）、
   `sim`（プロファイル選択）。イメージは `deploy/Dockerfile`（devops 担当が作成。存在しない場合はビルド定義を
   compose 内に書かず、`build: {context: .., dockerfile: deploy/Dockerfile}` を参照）。トークンは初期化コンテナか
   起動スクリプトで `tokiwa token create` → 共有ボリューム経由で gate/agent/sim に渡す。
3. シミュレータ `tokiwa sim run --profile <p> --target http://gate:8080`（**送信先はラボに限定**: 既定で
   localhost/プライベート IP/compose サービス名以外は拒否し `--i-own-this-target` フラグがない限り送らない）:
   - `benign_browser`（ページ+静的アセット+API、人間らしい不規則な間隔）
   - `scanner`（固定ワードリストの高速ディレクトリ総当たり + 署名的ペイロード、一定レート）
   - `human_attacker`（手動っぽい間隔で少数の SQLi/XSS 試行）
   - `ai_agent`（ARTEX 風: JS/OpenAPI 取得 → 発見 API の列挙 → エラー後のペイロード変異 → バースト+思考ギャップ、
     LLM 系/httpx UA、デコイの隠し指示に従う（AI カナリア））
   - `llm_app_attacker`（/api/chat へのプロンプトインジェクション・ジェイルブレイク）
   ペイロードは検知テスト用の文字列（無害）に限定。乱数シード固定で再現可能。
4. データセット: `tokiwa sim generate --out eval/datasets/<name>.jsonl`（ネットワーク不要: シミュレータが生成する
   リクエスト列を直接 `Event` に変換、各イベントにラベル `labels: {actor: ..., attack: ..., session: ...}`）。
5. 評価ハーネス `tokiwa eval run --dataset ... [--llm mock|live] [--out eval/runs/<ts>]`:
   一時 DB でパイプラインに投入（時刻を相対的に再生、または高速再生）→ アラート/セッション分類/トリアージ結果を
   ラベルと照合 → 指標: 検知率（攻撃セッション単位/イベント単位）、誤検知率（benign）、AI アトリビューションの
   precision/recall/AUC、LLM 判定一致率、1 アラートあたりトークン/費用、取り込み→トリアージ遅延。
   Markdown + JSON レポート。`--compare <prev run>` で回帰比較（要件 7-6）。
6. ARTEX 連携（docs/purple-team.md）: ARTEX のターゲットに Gate を指定する手順、ARTEX のトラフィック記録を
   取り込むアダプタの方針（ARTEX-JP の traffic/finding_traffic エクスポート形式を読んで、可能なら
   `tokiwa eval import-artex <file>` を実装。形式が不明確なら設計のみ docs に）。ARTEX リポジトリは
   `/home/user/artex-jp`（読み取り専用参照。AGPL-3.0 のためコードは複製しない）。

## 受け入れ基準
- `tokiwa sim generate` で 5 プロファイルを含むデータセットを生成でき、`tokiwa eval run --llm mock` が完走して
  レポートを出す（テストで小規模データセットを使って実行）。
- シミュレータの送信先制限のテスト。victim アプリのテスト（定型応答・エラー誘発）。
