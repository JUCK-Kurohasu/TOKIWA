# パープルチーム演習: ARTEX × TOKIWA（FR-20）

ARTEX（AI 自律ペネトレーションテスト, Red）をラボの TOKIWA Gate に向けて走らせ、TOKIWA（Blue）が
「AI エージェントによる攻撃」として検知・アトリビューション・トリアージできるかを測る。
シミュレータ（`tokiwa sim` の `ai_agent` プロファイル）は仮説のモデルに過ぎないので、**実エージェントでの検証が本番**。

> ARTEX-JP は `/home/user/artex-jp` に読み取り専用で置いている（AGPL-3.0）。TOKIWA はトラフィック形式を読み取る
> だけで、コードは一切複製していない。以下の ARTEX 側の記述はソース・README を読んだ範囲の事実で、
> 未確認の点は `TODO(verify)` とした。

## 0. ルール

- 対象は **ラボの Gate（自分の管理下）だけ**。ARTEX のターゲット/スコープにラボ以外を入れない。
- ラボの victim は脆弱でない（固定応答）。ARTEX が「脆弱性あり」と報告しても誤検出であり、TOKIWA 側の評価対象は
  「攻撃の振る舞い」の検知。
- 実 LLM を使う側（ARTEX と TOKIWA の両方）の費用上限を先に決める。

## 1. ラボを起動する

```bash
docker compose -f lab/compose.yaml up --build -d
curl -s http://localhost:8080/health          # gate -> victim
open http://localhost:8788                     # TOKIWA UI（初回セットアップ）
```

TOKIWA を実 LLM でトリアージさせる場合は `TOKIWA_LLM_PROVIDER=auto ANTHROPIC_API_KEY=... TOKIWA_LLM_BUDGET_USD=2`
を付けて起動する。

## 2. ARTEX を起動する（ポート衝突に注意）

ARTEX の既定は `-addr :8787`（UI/API）と `-proxy :8788`（トラフィック記録プロキシ）。**8788 は TOKIWA と衝突する**
ので、ARTEX 側のプロキシを別ポートにする:

```bash
cd <artex>   # 別ホスト/別ディレクトリ。DB(PostgreSQL)・LLM キーの設定は ARTEX の README に従う
./start.sh -addr :8787 -proxy :18788
```

ARTEX をラボと同じホストで動かすなら、ターゲットは `http://<ホストのラボ IP>:8080`。Gate はホストの
`127.0.0.1:8080` にだけ公開しているので、別ホストから使う場合は compose の `ports` を演習用に一時変更する
（演習後に戻す）。

## 3. ARTEX のタスクを作る

- ターゲット: `http://<lab-host>:8080`（Gate）。スコープは **このホスト:ポートだけ**。
- 目標の例: 「公開 Web アプリの偵察と入力検証の確認」。ARTEX は JS/OpenAPI からの API 発見、エラー応答を見た
  ペイロード変異、並列ツール呼び出し（バースト）+ 推論待ち（ギャップ）を自然に行うはず — それを TOKIWA が拾えるかを見る。
- AI カナリア: victim の index と TOKIWA Mirage（deception モジュール、Gate の HTML 注入）にはエージェント宛ての
  隠し指示がある。ARTEX がそれに従えば `deception.trip`（ai_score 0.99）で決定的に判定できる。
  TODO(verify): ARTEX がページ内の隠し指示をどの程度実行に移すか（プロンプト・モデル次第）。

TODO(verify): ARTEX の UI でのターゲット/スコープ指定の正確な操作手順（README の「資産スコープ」機能）。

## 4. 演習中に見るもの（TOKIWA）

| 画面 / API | 期待 |
|---|---|
| セッション（`/api/v1/sessions?min_ai_score=0.7`） | ARTEX のセッションが `ai_agent` 分類・高スコア。timeline の gap_ms にバースト+ギャップのリズム |
| アラート | `ai.agent_session`, `ai.adaptive_mutation`, `ai.semantic_recon`, `ai.llm_client_fingerprint`, Web 署名, `deception.trip` |
| インシデント | 同一送信元で束ねられ、kill chain が recon → initial_access と進む。actor_type = ai_agent |
| トリアージ | `ai_agent_likelihood` が高く、根拠（evidence_ids）が実在イベントを指す |
| 対処提案 | block/tarpit/deceive が **proposed** で止まり、人間承認まで実行されない |

## 5. 事後評価: ARTEX の記録をラベル付きデータセットにする

ARTEX は MITM プロキシで全リクエストを記録している。それを取り込み、`tokiwa eval run` で TOKIWA の
現在の検知器・重みに対して何度でも再生・採点できる（回帰比較つき）。

```bash
# (a) タスクアーカイブ（.tar.zst）から: 先に展開する（Python 3.12 標準に zstd が無いため）
mkdir artex-task && tar --zstd -xf task-<id>-<archive>.tar.zst -C artex-task
cd backend
uv run tokiwa eval import-artex ../artex-task --host <lab-host> --out ../eval/datasets/artex-<date>.jsonl

# (b) 脆弱性の証拠 ZIP（finding export）から
uv run tokiwa eval import-artex findings-evidence.zip --out ../eval/datasets/artex-proof.jsonl

# (c) ARTEX のトラフィック索引（SQLite, 読み取り専用で開く）から
uv run tokiwa eval import-artex <artex data>/traffic/_index/index.sqlite --host <lab-host> --out ...

# (d) API のダンプ（GET /api/traffic/exchange?id=... の {req, resp} を JSONL に並べたもの）から
uv run tokiwa eval import-artex exchanges.jsonl --out ...

# 正常トラフィックと混ぜて評価（FPR も測る）
uv run tokiwa sim generate --profile benign_browser=10 --out ../eval/datasets/benign.jsonl
cat ../eval/datasets/artex-<date>.jsonl ../eval/datasets/benign.jsonl > ../eval/datasets/purple-<date>.jsonl
uv run tokiwa eval run --dataset ../eval/datasets/purple-<date>.jsonl --compare ../eval/runs/<前回>
```

### 取り込みアダプタの仕様（`backend/src/tokiwa/eval/artex.py`）

ARTEX-JP のソースで確認した形式:

| 入力 | 中身 | 対応 |
|---|---|---|
| タスクアーカイブの `traffic/traffic.json` | `{"version":1,"exchanges":[...],"blobs":[...]}`。各 exchange: `id`（`<unix秒>-<連番>`）, `ts`（unix 秒）, `host`, `method`, `url`, `status`, `content_type`, `req_len`, `resp_len`, `req_head`/`resp_head`（生ヘッダ）, `req_body`/`resp_body`（base64）, `req_blob`/`resp_blob`（大きい本文は `blobs/<sha256>.bin`） | ✔（ディレクトリ / json / tar / tar.gz。`.tar.zst` は要展開） |
| 証拠 ZIP | `evidence/<finding>/<binding>/manifest.json`（`snapshot`: url, method, status, captured_at, req_head ...）+ `request.http` | ✔ |
| 記録索引 | `<traffic>/_index/index.sqlite` の `exchanges` + `exchange_bodies` | ✔（`mode=ro`） |
| API | `GET /api/traffic`（一覧）, `GET /api/traffic/exchange?id=` → `{req, resp}`（生 HTTP） | ✔（JSON/JSONL ダンプ） |

生ヘッダの形: リクエスト `"GET /path?x HTTP/1.1\nHost: target\nUser-Agent: ...\n"`、レスポンス `"HTTP 200\nContent-Type: ...\n"`。

変換: `Event(kind=http, dataset="artex.traffic")`、ラベル `actor=ai_agent, profile=artex, session=artex:<host>, attack=artex`。

注意点（評価結果の読み方に影響する）:

- **時刻分解能が 1 秒**。同じ秒の exchange は連番順に 1 秒内へ等間隔に配置する（サブ秒のバースト特徴は近似）。
  TODO(verify): 新しい ARTEX でミリ秒精度の記録があるか。精度が必要なら演習中の **Gate 捕捉（live）** を正とする。
- ARTEX の記録は **平文（マスキングなし）**。取り込み時に `tokiwa.llm.redact` でヘッダ・クエリ・本文をマスクする。
- ARTEX は自分の送信元 IP を記録しない → `--source-ip`（既定 198.51.100.200）で合成。複数タスクを混ぜるときは
  `--session` / `--source-ip` を変えて別アクターにする。
- 1 タスク = 1 セッション扱い（`attack` はリクエスト単位の正解を持たない）。イベント単位の再現率はタスク全体を攻撃とみなした値。
- 記録はターゲット宛ての HTTP のみ。ARTEX の LLM 呼び出しや内部ツールは含まれない。

## 6. 演習の記録と次の一手

- 結果（`eval/runs/<ts>/report.md`）と所見を `docs/handoff/` に残す。特に取り逃したフェーズ（例: 「エラー後変異は
  検知、JS からの API 発見は未検知」）を detect-ai の特徴量・重み（`aidetect/scoring.py`）の調整にフィードバックする。
- シミュレータの `ai_agent` プロファイルと ARTEX 実トラフィックの差（間隔分布、バースト幅、UA、ヘッダ順）を比較し、
  プロファイルを実測に寄せる（`tokiwa/eval/profiles.py`）。
