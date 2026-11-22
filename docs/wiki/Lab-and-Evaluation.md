> 🌐 **日本語** · [English](Lab-and-Evaluation-en) · [中文](Lab-and-Evaluation-zh) · [Español](Lab-and-Evaluation-es)

# ラボと評価

TOKIWA には、検知を試すための **ラボ環境**・**攻撃トラフィックのシミュレータ**・**評価ハーネス** が付属しています。
さらに、攻撃側の ARTEX を相手にした **パープルチーム演習** の手順も用意しています。

> ⚠️ シミュレータと ARTEX は、**自分が管理し、試験の許可を持つ対象** にだけ向けてください。

## ラボの構成

```
 シミュレータ / ARTEX ──▶ Gate :8080（捕捉 + 遮断）──▶ 被害役アプリ :3000（デモショップ。脆弱性なし）
                              │
                              ▼
                       TOKIWA :8788（API + UI） ◀── Agent（任意: nginx JSON ログ / ホスト）
```

**被害役アプリ**（`lab/victim/app.py`）は、ログイン・検索・商品 API・チャット（`/api/chat`）・OpenAPI などを持つ
デモショップに見えますが、**実際には脆弱ではありません**。DB もファイル読み出しもシェルもなく、応答はすべて固定です。
ただし、AI エージェントの「エラー後の適応」を引き出すため、もっともらしいエラーを返します
（クォートが奇数個 → SQL エラー風の 500、`<script` → WAF 風の 403 など）。トップページにはラボ用の AI カナリアがあります
（`LAB_AI_CANARY=0` で無効化）。

### Docker なしで動かす（確認済み）

[クイックスタート](Quick-Start) の「3. ミニラボを組んで攻撃を流す」の手順です。

### Docker Compose で動かす

```bash
docker compose -f lab/compose.yaml up --build -d            # tokiwa + gate + victim
# http://localhost:8788 を開き、初回は管理者を作成

docker compose -f lab/compose.yaml --profile sim run --rm sim                          # 既定のミックス
SIM_PROFILE=ai_agent docker compose -f lab/compose.yaml --profile sim run --rm sim     # AI エージェントだけ
SIM_PROFILE=ai_agent=2,benign_browser=4 SIM_TIME_SCALE=0.2 docker compose -f lab/compose.yaml --profile sim run --rm sim
docker compose -f lab/compose.yaml --profile ingest run --rm sim-ingest                # Gate を使わず直接投入
docker compose -f lab/compose.yaml --profile agent up -d                               # nginx(:8081) + agent
docker compose -f lab/compose.yaml down                                                # 停止（-v でデータも削除）
```

実 LLM で動かす場合は `TOKIWA_LLM_PROVIDER=auto ANTHROPIC_API_KEY=... TOKIWA_LLM_BUDGET_USD=2` のように付けて起動します
（ラボの既定の日次予算は $1）。

> ✅ **確認済み（2026-11-10、監査 L14、サンドボックス。Docker / Compose のバージョンは未記録）**: `up -d` で
> `tokiwa-init` が正常終了し `tokiwa` / `gate` / `victim` が healthy、UI で初回セットアップ、`--profile sim` の `sim` から
> アラート → インシデント → 対処提案 → 承認 → Gate での遮断（403）まで。承認から遮断の反映には約 4〜8 秒かかりました。
>
> ⚠️ その環境では Docker Hub のレート制限（429）・ghcr.io の 403・TLS を傍受するプロキシのため、素の `up --build` は失敗し、
> ベースイメージをビルド引数（`NODE_IMAGE` / `PYTHON_IMAGE` / `UV_IMAGE`）で差し替え、victim のベースイメージは手で再タグして
> 起動しました（詳細は `lab/README.md` の「検証状況」）。**未確認**: `--profile ingest` と `--profile agent`、実 LLM での実行。

## シミュレータ（`tokiwa sim`）

| プロファイル | 正解ラベル | 振る舞い |
|---|---|---|
| `benign_browser` | 正常 | ブラウザで買い物をする普通の利用者 |
| `scanner` | 自動スキャナ | 単語リスト + 署名ベースの機械的なスキャン（一定の速度） |
| `human_attacker` | 人間 | 人間のペースで SQLi / XSS を手で試す |
| `ai_agent` | AI エージェント | ARTEX のような自律エージェント（JS / OpenAPI からの API 発見、エラー後の変異、バーストと思考待ち、カナリアへの追従） |
| `llm_app_attacker` | 人間 | `/api/chat` へのプロンプトインジェクション・ジェイルブレイク |
| `api_only_agent` | AI エージェント（保留） | API だけを叩く LLM ツールループ（OpenAPI から開始、HTML・robots・カナリアに触れない、1 ターン 1 リクエスト、汎用 HTTP クライアントの UA） |
| `slow_rotating_agent` | AI エージェント（保留） | ブラウザ駆動のエージェント（Chrome のヘッダ一式）、中央値約 20 秒の推論待ち、数リクエストごとに送信元 IP が変わる |

**保留（holdout）プロファイル** は検知器の設計・調整に使っていない形で、既定のミックスには入りません。`--profile api_only_agent=2,...` のように明示するか、`--profile all --sessions N` で含めます。評価結果では台本どおりのプロファイルと分けて表示されます。IP の回転が Gate から見えるのは `--spoof-xff` を付けたときだけです。

```bash
cd backend
uv run tokiwa sim profiles
uv run tokiwa sim run --profile ai_agent --target http://localhost:8080
uv run tokiwa sim run --profile ai_agent=2,benign_browser=5 --seed 7 --record ../eval/datasets/live.jsonl
```

安全のための制限:

- 送信先は localhost・プライベート IP・それに解決される名前だけです。それ以外は `--i-own-this-target` を付けない限り拒否します
  （自分が所有し、試験の許可を持つ対象に限ってください）。
- リダイレクトは追わず、プロキシの環境変数も使いません。リクエスト総数（既定 2,000）と速度（既定 50 rps）に上限があります。
- ペイロードは検知テスト用の無害な文字列です（外部参照には `.invalid` ドメインを使います）。

## 評価ハーネス（`tokiwa eval`）

ラベル付きのデータセットを TOKIWA の処理（取り込み → 検知 → 相関 → トリアージ）に流し、指標を計算します。
評価は使い捨ての DB で行うので、稼働中のサーバーには影響しません。検知器や LLM には正解ラベルを見せません。

```bash
cd backend
uv run tokiwa sim generate --out ../eval/datasets/mix.jsonl                  # オフラインで生成（同じ seed なら同一ファイル）
uv run tokiwa eval run --dataset ../eval/datasets/lab-mini.jsonl             # モック LLM（無料・オフライン）
uv run tokiwa eval run --dataset ../eval/datasets/mix.jsonl --compare ../eval/runs/<前回> --fail-on-regression
uv run tokiwa eval run --dataset ../eval/datasets/mix.jsonl --llm live --budget-usd 0.50   # 実 LLM（費用が発生）
uv run tokiwa eval compare ../eval/runs/<今回> ../eval/runs/<前回>
```

結果は `eval/runs/<UTC 時刻>/` に `metrics.json` と `report.md` として出力されます。

| 指標 | 意味 |
|---|---|
| 攻撃セッション検知率（medium 以上） | **主指標**。medium 以上のアラートが 1 件以上付いた攻撃セッションの割合 |
| 攻撃セッション検知率（重大度を問わない） | 副指標。info / low のアラート 1 件でも検知とみなした割合 |
| 正常セッションの誤検知率 | アラートが付いてしまった正常セッションの割合 |
| アラート適合率 | 攻撃セッションだけに帰属したアラートの割合（検知器別にも出る） |
| AI アトリビューション P / R / F1 / AUC | セッションを「AI エージェントか」で判定したときの精度 |
| LLM 一致率 | トリアージの判定（アクター種別・悪性・AI）が正解と一致した割合 |
| コスト・遅延 | LLM の費用、取り込み → アラート、アラート → トリアージの遅延 |

率はすべて分子 / 分母と 95% 区間（Clopper–Pearson）付きで出力され、試行が 30 未満の値は `report.md` で **参考値** と表示されます
（付属の lab-mini では正常 3・AI 2 セッションなので、「誤検知 0/3」の区間は 0〜70.8% です）。
`--llm mock` の「LLM 一致率」はルールによる代替判定の自己一致で、**LLM の品質ではありません**。費用は実費 $0 と、
推定トークン × 料金表の想定費用を分けて表示します。`--compare` は 2 つの実行の条件（データセットの sha256・LLM プロバイダ・
有効な検知器・読み込んだ Sigma ルール数・しきい値）が違うと「比較不能」と警告し、`--fail-on-regression` では終了コード 3 に
なります（意図した比較なら `--allow-mismatch`）。アラート総数と検知器別の件数も比較します。

> 付属のデータセット（`eval/datasets/lab-mini.jsonl`）は、検知器と同じ仮説から合成したものです。ここでの数値は
> **実環境より高く出る** と考えてください。

## ARTEX とのパープルチーム演習

シミュレータの `ai_agent` は仮説のモデルにすぎないので、**実際の AI エージェントでの検証が本番** です。

1. ラボを起動します（上記）。
2. ARTEX を起動します。ARTEX の既定ではトラフィック記録プロキシが **:8788 を使い、TOKIWA と衝突** するので、
   ARTEX 側を別のポートにします（例: `./start.sh -addr :8787 -proxy :18788`）。
3. **タスクを作る前に**、ARTEX のシステム設定でトラフィック記録（設定キー `traffic_capture`）と LLM 記録（`llm_record`）を
   ON にし、対象ホストの過去の記録を消しておきます。どちらの記録も既定は OFF で、OFF のままでは事後評価のデータが残りません。
   ARTEX の記録はタスク単位ではなくホスト単位です（詳細は `docs/purple-team.md` §2）。
4. ARTEX のタスクのターゲットを **ラボの Gate（`http://<ラボのホスト>:8080`）だけ** にします。
5. 演習中に TOKIWA で見るもの:
   - **AI セッション**: ARTEX のセッションが AI エージェントと分類され、高いスコアになるか
   - **アラート**: `ai.agent_session`、`ai.adaptive_mutation`、`ai.semantic_recon`、`ai.llm_client_fingerprint`、`deception.trip` など
   - **インシデント**: アクター判定が AI エージェントになり、攻撃の段階が進んでいくか
   - **対処**: 遮断などが **提案で止まり**、承認するまで実行されないか
6. 事後に ARTEX の記録をデータセットに変換し、何度でも再評価できます。

```bash
cd backend
uv run tokiwa eval import-artex <ARTEX のタスクアーカイブを展開したディレクトリ> --host <ラボのホスト> \
  --since <演習開始 UTC> --until <演習終了 UTC> --split-gap-minutes 30 --out ../eval/datasets/artex-<日付>.jsonl
uv run tokiwa sim generate --profile benign_browser=10 --out ../eval/datasets/benign.jsonl
cat ../eval/datasets/artex-<日付>.jsonl ../eval/datasets/benign.jsonl > ../eval/datasets/purple-<日付>.jsonl
uv run tokiwa eval run --dataset ../eval/datasets/purple-<日付>.jsonl
```

`import-artex` は、タスクアーカイブ（`traffic/traffic.json`）・証拠 ZIP・記録の索引（SQLite）・API のダンプを読めます。
ARTEX の記録の時刻は **応答完了時刻・1 秒精度** で、送信元 IP を含みません（`--source-ip` で補う）。取り込んだイベントの
間隔・バーストは近似なので、リズムの評価は演習中の Gate の捕捉を正としてください。ヘッダの順序も意味を持ちません。
`--since` / `--until` で時間帯を絞り、`--split-gap-minutes` で無通信の間隔ごとに別セッションに分けられます。
0 件のときは、記録が OFF だった可能性・含まれていたホスト・時刻範囲を表示します。
TOKIWA は ARTEX の記録形式を読むだけで、ARTEX のコードは含んでいません。
