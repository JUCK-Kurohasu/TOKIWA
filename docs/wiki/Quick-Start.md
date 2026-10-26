> 🌐 **日本語** · [English](Quick-Start-en) · [中文](Quick-Start-zh) · [Español](Quick-Start-es)

# クイックスタート

手元のマシンで TOKIWA を起動し、付属の攻撃シミュレータで「AI エージェントの攻撃を検知 → 人間が承認 → 遮断」までを
体験する手順です。Docker は使いません。所要時間は 10〜15 分ほどです。

> 本番寄りの常用構成（Docker Compose）は [インストールと運用](Installation) を参照してください。

## 必要なもの

| ソフトウェア | バージョン | 用途 |
|---|---|---|
| Python | 3.12 以上 | バックエンド |
| [uv](https://docs.astral.sh/uv/) | 最新 | Python の依存管理 |
| Node.js / npm | 22 系 | Web UI のビルド |
| git | — | 取得 |

動作確認は Linux で行っています。macOS も同じ手順で動く想定ですが未確認です。Windows は未検証です。
LLM の API キーは **なくても動きます**（その場合はモック LLM とルールベースの判定で動作します）。

## 1. 取得とインストール

```bash
git clone https://github.com/JUCK-Kurohasu/TOKIWA.git
cd TOKIWA

cd frontend && npm install && npm run build && cd ..   # Web UI をビルド（frontend/dist）
cd backend && uv sync                                   # バックエンドの依存をインストール
```

## 2. サーバーを起動する

```bash
# backend/ で実行
TOKIWA_SERVER__STATIC_DIR=../frontend/dist uv run tokiwa serve
```

ブラウザで <http://localhost:8788> を開きます。初回は **セットアップ画面（/setup）** になるので、最初の管理者を作成します。

- ユーザー名: 3〜64 文字（英数字と `_` `.` `-`）
- パスワード: 10 文字以上

データ（SQLite の DB と署名鍵）は `backend/data/` に保存されます。

> 💡 UI を改造しながら使う場合は、リポジトリ直下で `make dev` を実行すると、API（:8788、自動リロード）と
> UI の開発サーバー（:5173）が同時に起動します。

### LLM を使う場合（任意）

サーバー起動前に API キーを環境変数で渡します。

```bash
export ANTHROPIC_API_KEY=sk-ant-...      # 設定するとプロバイダが自動で Anthropic になる
```

既定の日次予算は **$5** です。超えた分はルールベースの判定に切り替わります。詳しくは [LLM の設定とコスト](LLM) を参照してください。

## 3. ミニラボを組んで攻撃を流す

付属の「被害役」デモアプリの前に TOKIWA Gate を置き、シミュレータで攻撃トラフィックを流します。
**ターミナルを 3 つ** 使います（サーバー用と合わせて計 4 つ）。

```
 シミュレータ ──▶ Gate :8080 ──▶ 被害役アプリ :3000（脆弱性のないデモショップ）
                    │
                    ▼
            TOKIWA Server :8788
```

**ターミナル A — 被害役アプリ**（応答はすべて固定で、実際には脆弱ではありません）

```bash
cd lab/victim
../../backend/.venv/bin/uvicorn app:app --host 127.0.0.1 --port 3000
```

**ターミナル B — Gate 用の API トークンを作り、Gate を起動**

```bash
cd backend
uv run tokiwa token create gate-1        # tkw_... が一度だけ表示されるので控える
export TOKIWA_GATE__INGEST_TOKEN=tkw_...  # コマンドライン引数より安全（ps に出ない）
uv run tokiwa gate run --upstream http://127.0.0.1:3000 --listen 127.0.0.1:8080 \
  --server http://127.0.0.1:8788 --trust-forwarded-for
```

> ⚠️ `tokiwa token create` はサーバーと **同じディレクトリ（`backend/`）・同じ環境変数** で実行してください。
> DB の場所（既定 `./data/tokiwa.db`）は実行時のカレントディレクトリからの相対パスです。

`--trust-forwarded-for` は、シミュレータが送信元 IP を `X-Forwarded-For` で名乗るためのラボ専用の設定です。
本番では「信頼できるロードバランサの背後にいるとき」以外は付けないでください。

**ターミナル C — シミュレータで攻撃を流す**

```bash
cd backend
uv run tokiwa sim run --target http://127.0.0.1:8080 --time-scale 0.1 --spread 10 --spoof-xff
```

正常利用者・スキャナ・人間の攻撃者・AI エージェント・LLM アプリへの攻撃者の 5 種類が混ざったトラフィックが流れます
（数分で終わります）。送信先はローカル／プライベートなアドレスに制限され、ペイロードは検知テスト用の無害な文字列だけです。

> `--time-scale 0.1` は待ち時間を 1/10 にして早く終わらせる設定です。リクエストの「リズム」が実際とは変わるので、
> 判定を厳密に見たいときは省略してください（既定 1.0）。

## 4. 結果を見る

Web UI で次の画面を開きます。

| 画面 | 見どころ |
|---|---|
| ダッシュボード | アラート件数・オープンなインシデント・AI セッション数・承認待ちの対処 |
| AI セッション | 送信元ごとの AI スコア。AI エージェントのセッションが紫色の「AI エージェント」として上位に並ぶ |
| インシデント | 同じ送信元のアラートが束ねられ、攻撃の段階（偵察 → 初期侵入など）と LLM のトリアージ結果が付く |
| アラート | 個々の検知（SQL インジェクション、スキャナ、デコイへのアクセス、AI カナリアへの追従など） |

## 5. 承認して遮断する

1. **対処** 画面の「承認待ち」タブを開きます。LLM（またはルール）が提案した `block_ip` などが並んでいます。
2. AI エージェントの送信元 IP に対する `block_ip` を **承認** します。
3. 数秒以内（Gate のポリシー取得間隔は既定 5 秒）に、Gate がその IP からのリクエストに **403** を返すようになります。

```bash
# 承認後に確認（<IP> は承認した送信元）
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: <IP>" http://127.0.0.1:8080/   # → 403
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: 192.0.2.1" http://127.0.0.1:8080/  # → 200（他の IP は通る）
```

4. 「有効」タブから **取り消し** を押すと、遮断は解除されます（何もしなくても TTL＝既定 60 分で自動的に期限切れになります）。

承認しない限り、提案された対処は **一切実行されません**。

## 6. 片付け

各ターミナルで Ctrl-C を押して止めます。データを消して最初からやり直す場合は `backend/data/` を削除します。

## 次に読むページ

- 自分のアプリを守る: [センサーの接続](Sensors)
- 画面の詳しい見方: [Web UI ガイド](Web-UI)
- 常用構成: [インストールと運用](Installation)
