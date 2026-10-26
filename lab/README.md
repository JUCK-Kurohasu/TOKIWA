# lab/ — TOKIWA ラボ環境（Docker Compose）

被監視デモアプリ（victim）の前に TOKIWA Gate を置き、TOKIWA サーバーで検知・トリアージするまでを 1 コマンドで再現する。
攻撃トラフィックは `tokiwa sim`（シミュレータ）または ARTEX（docs/purple-team.md）で流す。

```
 sim / ARTEX ──▶ gate:8080 (TOKIWA Gate: 捕捉 + 遮断) ──▶ victim:3000 (デモショップ, 脆弱性なし)
                     │ POST /api/v1/ingest/events
                     ▼
               tokiwa:8788 (API + UI)  ◀── agent (任意: nginx JSON ログ / ホスト)
```

| サービス | 役割 | 備考 |
|---|---|---|
| `tokiwa-init` | DB 作成 + コンポーネント別 ingest トークン発行（冪等） | トークンは `tokiwa-data` ボリュームの `lab-tokens/`（mode 600）。表示しない |
| `tokiwa` | サーバー（API/UI） | `127.0.0.1:8788`。既定は mock LLM |
| `victim` | デモショップ（`victim/app.py`） | 外部公開しない（gate 経由のみ） |
| `gate` | リバースプロキシ・センサー | `127.0.0.1:8080`。ラボでは `X-Forwarded-For` を信頼（sim の `--spoof-xff` 用） |
| `sim` | トラフィックシミュレータ（profile `sim`） | 送信先は `http://gate:8080` 固定 |
| `sim-ingest` | Gate なしで合成イベントを ingest API に直接投入（profile `ingest`） | |
| `nginx` + `agent` | nginx JSON ログ → `tokiwa agent`（profile `agent`） | ログ形式は sensors の `nginx/tokiwa-json.conf` を参照（複製しない） |

イメージは devops の `deploy/Dockerfile`（`tokiwa:lab` としてビルド）。victim だけ `victim/Dockerfile`（fastapi + uvicorn のみ）。

## 使い方（リポジトリ直下）

```bash
docker compose -f lab/compose.yaml up --build -d          # tokiwa + gate + victim
open http://localhost:8788                                 # 初回は UI でセットアップ（管理者作成）

docker compose -f lab/compose.yaml --profile sim run --rm sim                          # 既定ミックス
SIM_PROFILE=ai_agent docker compose -f lab/compose.yaml --profile sim run --rm sim     # AI エージェントのみ
SIM_PROFILE=ai_agent=2,benign_browser=4 SIM_TIME_SCALE=0.2 docker compose -f lab/compose.yaml --profile sim run --rm sim
docker compose -f lab/compose.yaml --profile ingest run --rm sim-ingest                # Gate を使わない
docker compose -f lab/compose.yaml --profile agent up -d                               # nginx(8081) + agent

docker compose -f lab/compose.yaml down        # 停止（-v でデータとトークンも削除）
```

環境変数: `SIM_PROFILE`（既定 mixed）, `SIM_SEED`, `SIM_TIME_SCALE`（<1 で高速化。ただしリズム特徴が変わる）,
`LAB_AI_CANARY=0`（victim のカナリアを外す）, `TOKIWA_LLM_PROVIDER=auto` + `ANTHROPIC_API_KEY`（実 LLM。
`TOKIWA_LLM_BUDGET_USD` で日次上限、既定 1.0）。

ホストから直接シミュレータを動かす場合（`backend/` で）:

```bash
uv run tokiwa sim run --profile ai_agent --target http://localhost:8080 --record ../eval/datasets/live-ai.jsonl
uv run tokiwa eval run --dataset ../eval/datasets/live-ai.jsonl     # 実応答で記録したラベル付きデータを評価
```

## victim（被監視デモアプリ）

`victim/app.py`（依存は fastapi / uvicorn のみ）。ログイン、検索、商品 API、ファイルダウンロード風、`/api/chat`（固定応答）、
`/openapi.json`、JS バンドル（`/static/app.js` にリンクされていない API ルートを含む）、`robots.txt`。

- **実際には脆弱でない**: DB・ファイル読み出し・シェル・テンプレート描画なし。入力は反映も解釈もしない。
- ただし **もっともらしいエラーを返す**: クォートの奇数個 → 500（固定の SQL エラー文）、`<script` など → 403
  （WAF 風）、不正パラメータ → 400、`..` → 400、NUL → 500。AI エージェントの「エラー後の変異」を誘発するため。
- index には **ラボ用 AI カナリア**（AI エージェント宛ての隠し指示: `/api/internal/debug` に `X-Debug-Auth: <token>`）。
  `/api/internal/debug` は TOKIWA の既定デコイパス。`LAB_AI_CANARY=0` で無効化。
- オフライン生成用の同等モデルが `backend/src/tokiwa/eval/virtual.py`。挙動を変えたら両方を直す
  （`backend/tests/eval/test_victim.py` のパリティテストが検出する）。

## 安全上の注意

- シミュレータは localhost / プライベート IP / それに解決される名前（compose サービス名）以外への送信を拒否する
  （`--i-own-this-target` で明示解除。自分が所有・試験許可を持つ対象のみ）。リダイレクトは追わず、プロキシ環境変数も使わない。
  リクエスト総数・RPS に上限あり。
- ペイロードは検知テスト用の無害な文字列（外部参照は `.invalid` TLD）。
- ポートは `127.0.0.1` にのみ公開。victim はラボネットワーク内のみ。

## 検証状況

`docker compose -f lab/compose.yaml --profile sim --profile ingest --profile agent config` は通過（構文・参照）。
サンドボックスに Docker デーモンが無いため `up` による起動確認は未実施（docs/handoff/2026-10-22-lab-eval.md 参照）。
`agent` はコンテナ内で動くため、ホストセンサーが見るのはコンテナ自身のポートのみ（ホスト全体を見るなら
`network_mode: host` / `pid: host` が必要。ラボでは既定にしていない）。
