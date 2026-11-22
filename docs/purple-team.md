# パープルチーム演習: ARTEX × TOKIWA（FR-20）

ARTEX（AI 自律ペネトレーションテスト, Red）をラボの TOKIWA Gate に向けて走らせ、TOKIWA（Blue）が
「AI エージェントによる攻撃」として検知・アトリビューション・トリアージできるかを測る。
シミュレータ（`tokiwa sim` の `ai_agent` プロファイル）は仮説のモデルに過ぎないので、**実エージェントでの検証が本番**。

> ARTEX-JP は `/home/user/artex-jp` に読み取り専用で置いていた（AGPL-3.0。環境によっては無い）。TOKIWA は
> トラフィック形式を読み取るだけで、コードは一切複製していない。以下の ARTEX 側の記述はソース・README を読んだ範囲と、
> 2026-11 監査（`docs/audit/2026-11/findings/L01-artex.jsonl` の L01-01 / L01-03 / L01-04）がソースで確認した範囲の
> 事実で、未確認の点（UI 上の表示名など）は `TODO(verify)` とした。新しい ARTEX では変わっている可能性がある。

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

### 2.1 トラフィック記録と LLM 記録を ON にする（タスクを作る前に必須）

ARTEX のトラフィック記録と LLM 記録は **既定で OFF**（監査 L01-01: システム設定 `traffic_capture` と `llm_record`、
どちらも既定 false）。OFF のまま演習すると、タスクアーカイブの `traffic/traffic.json` も記録索引も空になり、
§5 の事後評価ができない（`tokiwa eval import-artex` は 0 件で終了し、記録 OFF の可能性を表示する）。
LLM 記録も OFF だと「ARTEX の LLM がカナリアを読んだか」の正解（LLM の入出力記録）も残らない。

1. ARTEX のシステム設定で **トラフィック記録（`traffic_capture`）を ON**、**LLM 記録（`llm_record`）を ON** にする。
   TODO(verify): UI 上の項目名と場所（監査ではソースの設定キーまで確認。UI の表記は未確認）。
2. その後で §3 のタスクを作る。TODO(verify): 実行中のタスクに設定変更が途中から効くかは未確認なので、必ずタスク作成前に ON にする。

注意: 記録 ON は ARTEX の挙動そのものを変える。監査 L01-01 によれば、記録 OFF のときはエージェントに記録プロキシ・
traffic 系ツール・関連プロンプトが注入されない（ON のときだけ注入される）。つまり ON の演習は「記録プロキシ経由で
送信し、traffic 系ツールで過去の通信を参照できる ARTEX」の振る舞いになる。可能なら **ON と OFF で 1 回ずつ** 演習し、
OFF 回は Gate の live 捕捉だけで評価して、差を記録する。

### 2.2 演習前に対象ホストのトラフィックを消しておく

ARTEX のトラフィック索引とタスクアーカイブは **タスク単位ではなくホスト単位**（監査 L01-04: 索引にタスク ID 列が無く、
アーカイブは「そのタスクの資産ホストに一致する全 exchange」を書き出す）。同じホストへの過去の演習・チャットからの
手動操作・ARTEX 自身の enrich（HTTP プローブ。記録 ON なら同じプロキシを通る）が同じアーカイブに混ざり、
取り込むと全部 `actor=ai_agent` の 1 セッションになってしまう。

- 演習の前に、ARTEX 側で対象ホスト（ラボの Gate）の記録済みトラフィックをクリアする。
  TODO(verify): ARTEX UI の操作名（監査の提案では「すべてクリア」相当。正確な表記・範囲は未確認）。
- クリアできない場合や複数タスクを続けて実行した場合は、取り込み時に `--since` / `--until`（演習の時間帯）と
  `--split-gap-minutes`（無通信の間隔でセッションを分ける）を使う（§5）。
- 演習の開始・終了時刻（UTC）をメモしておく。`--since/--until` にそのまま使える。

## 3. ARTEX のタスクを作る

- 先に §2.1（記録 ON）と §2.2（対象ホストのトラフィックのクリア）を済ませる。
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

ARTEX は、トラフィック記録が ON のとき（§2.1）に MITM プロキシでターゲット宛ての HTTP を記録する。それを取り込み、
`tokiwa eval run` で TOKIWA の現在の検知器・重みに対して何度でも再生・採点できる（回帰比較つき）。

```bash
# (a) タスクアーカイブ（.tar.zst）から: 先に展開する（Python 3.12 標準に zstd が無いため）
mkdir artex-task && tar --zstd -xf task-<id>-<archive>.tar.zst -C artex-task
cd backend
uv run tokiwa eval import-artex ../artex-task --host <lab-host> --out ../eval/datasets/artex-<date>.jsonl \
  --since 2026-11-21T09:00:00Z --until 2026-11-21T10:30:00Z --split-gap-minutes 30

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

変換: `Event(kind=http, dataset="artex.traffic")`、ラベル `actor=ai_agent, profile=artex, session=artex:<host>, attack=artex,
timing=approx`。

| オプション | 意味 |
|---|---|
| `--host` | このターゲットホストの exchange だけ |
| `--since` / `--until` | この時間帯だけ（unix 秒または ISO 8601。オフセットなしは UTC）。ARTEX の `ts` は応答完了時刻なので、境界は数秒の余裕を持たせる |
| `--split-gap-minutes N` | ホストごとに、N 分以上記録が途切れたところで別セッションにする（`artex:<host>#1`, `#2`, …）。セッションごとに送信元 IP も `--source-ip` から 1 ずつずらす（セッション化・IP 帰属で再結合されないように）。既定は分割しない |
| `--session` / `--source-ip` | セッションのラベル / 合成する送信元 IP |

0 件のときの表示: 入力自体が 0 件なら「ARTEX 側で `traffic_capture` が OFF だった可能性」、`--host` で全部落ちたなら
入力に含まれるホスト一覧、`--since/--until` で全部落ちたなら入力の時刻範囲を表示する。

注意点（評価結果の読み方に影響する）:

- **時刻は応答完了時刻・1 秒精度**（監査 L01-03: ARTEX はプロキシの応答フックで `time.Now()` から `ts` と ID を作る）。
  送信時刻ではないので、遅い応答ほど後ろにずれる。同じ秒の exchange は連番順に 1 秒内へ等間隔に配置するので、
  **gap_ms・バーストなどのリズム特徴は取り込みアルゴリズムの産物**。取り込んだイベントには `labels.timing=approx` を付け、
  `tokiwa eval run` はその件数を note に出す。リズム系の評価・重み調整は演習中の **Gate 捕捉（live, ms 精度・送信時刻）** を正とする。
  TODO(verify): 新しい ARTEX でミリ秒精度・送信時刻の記録があるか。
- **ID の連番は全タスク・全ホスト共通のカウンタを 10000 で割った余り**（ARTEX プロセスの再起動で 0 に戻る）。同じ秒の
  中の順序にしか使えない。9999 → 0000 の巻き戻りは取り込み側で考慮する（同じ秒に 9999 付近と 0 付近が混在したら小さい方が後）。
- **ヘッダの順序は無意味**。ARTEX は記録時にヘッダを Go の map から出力する（`Host` だけ先頭）ため、行の順番はランダム。
  ARTEX の記録からヘッダ順の指紋を学習・調整しない（TOKIWA の現行の指紋はヘッダ名を集合として扱うので影響はない）。
- ARTEX の記録は **平文（マスキングなし）**。取り込み時に `tokiwa.llm.redact` でヘッダ・クエリ・本文をマスクする。
- ARTEX は自分の送信元 IP を記録しない → `--source-ip`（既定 198.51.100.200）で合成。複数タスクを混ぜるときは
  `--session` / `--source-ip` を変えて別アクターにする。
- 既定は 1 ホスト = 1 セッション扱い（`attack` はリクエスト単位の正解を持たない）。イベント単位の再現率はタスク全体を
  攻撃とみなした値。アーカイブはホスト単位なので、別タスク・手動操作・enrich のプローブが混ざり得る（§2.2）。
  TODO(verify): enrich のリクエストを UA などで判別できるか（できれば `labels.component=enrich` で区別したい）。
- 記録はターゲット宛ての HTTP のみ。ARTEX の LLM 呼び出しや内部ツールは含まれない。

## 6. 演習の記録と次の一手

- 結果（`eval/runs/<ts>/report.md`）と所見を `docs/handoff/` に残す。特に取り逃したフェーズ（例: 「エラー後変異は
  検知、JS からの API 発見は未検知」）を detect-ai の特徴量・重み（`aidetect/scoring.py`）の調整にフィードバックする。
- シミュレータの `ai_agent` プロファイルと ARTEX 実トラフィックの差（UA、パス・パラメータの選び方、エラー後の変異）を
  比較し、プロファイルを実測に寄せる（`tokiwa/eval/profiles.py`）。間隔分布・バースト幅は ARTEX 記録では近似なので
  Gate の live 捕捉で比べる。ヘッダ順は ARTEX 記録からは分からない（§5 注意点）。
