> 🌐 **日本語** · [English](Troubleshooting-en) · [中文](Troubleshooting-zh) · [Español](Troubleshooting-es)

# トラブルシューティング

## 起動・ログイン

**ブラウザで開くと 404 になる / API しか見えない**
UI がビルドされていないか、配信先が設定されていません。`cd frontend && npm run build` のあと、
`TOKIWA_SERVER__STATIC_DIR=../frontend/dist` を付けてサーバーを起動します。開発中は `make dev`（UI は :5173）でも構いません。
Docker イメージでは `TOKIWA_SERVER__STATIC_DIR` を上書きしていないか確認してください（既定 `/app/frontend/dist`）。

**管理者のパスワードを忘れた**
サーバーと同じ設定で `uv run tokiwa user create <新しい名前> --role admin` を実行して別の管理者を作り、
**設定 → ユーザー** の「パスワード再設定」で元のアカウントのパスワードを変更します。

**再起動したらログアウトされた**
署名鍵（`data/secret.key`）が失われた可能性があります。データディレクトリが永続化されているか確認してください。

## センサー・取り込み

**Gate を経由しているのにイベントが届かない**
1. Gate のログで、取り込みの 401 / 403 エラーが出ていないか確認します（トークンの誤り、スコープ不足、失効）。
   トークンにはスコープ `ingest` と `gate` の両方が必要です。
2. `--server` が TOKIWA サーバーに届く URL になっているか確認します。
3. Gate を動かしているホストから `curl http://127.0.0.1:8080/__tokiwa/health` を実行すると、送信の統計
   （送信済み・破棄など）が見られます。

**`tokiwa token create` で作ったトークンが「invalid token」になる**
コマンドとサーバーが別の DB を見ている可能性があります。既定の DB パス（`./data/tokiwa.db`）は相対パスなので、
サーバーと同じディレクトリ（`backend/`）・同じ環境変数で実行してください。Docker では
`docker compose ... exec tokiwa tokiwa token create ...` を使います。

**すべてのアクセスが同じ IP（ロードバランサの IP）に見える**
Gate がロードバランサの背後にある場合は、`--trust-forwarded-for`（`TOKIWA_GATE__TRUST_FORWARDED_FOR=true`）を設定します。
**信頼できるロードバランサの背後でだけ** 使ってください。そうでない環境では、送信元 IP を偽装されます。

**WebSocket が使えなくなった**
Gate v0.1 は WebSocket に対応していません（501 を返します）。WebSocket のパスは Gate を通さずにルーティングしてください。

## 対処

**承認したのに遮断されない**
- Gate がポリシーを取りに行く間隔は既定で 5 秒です。少し待ってから確認します。
- 対処の状態が `failed` になっていないか確認します。保護対象（`response.protected_cidrs`）やサーバー自身の IP と
  重なる場合は、実行直前の再検証で失敗します。
- 遮断対象の IP が、Gate から見える送信元 IP と一致しているか確認します（ロードバランサ配下の場合は上の項目を参照）。

**承認待ちの対処が多すぎる**
同じ種類・同じ対象の提案は 1 つにまとめられますが、送信元ごとには作られます。LLM に回す最低重大度
（`triage.min_severity_for_llm`）を上げるか、明らかに不要な提案は却下してください。誤検知の多い検知器は
**検知ルール → 検知器** で無効にできます。

## LLM

**LLM が使われていない（モックの応答になる）**
**LLM → 設定** の「現在の状態」で、プロバイダと利用可否を確認します。`auto` のときは、Anthropic の API キーが無いと `mock` になります。
サーバーの起動前に `ANTHROPIC_API_KEY` を設定したか、UI でキーを入力したかを確認し、**接続テスト** を実行してください。

**途中から LLM のトリアージが止まった**
日次予算（`llm.daily_budget_usd`、既定 $5）を使い切った可能性があります。その日はルールベースの判定に切り替わります。
**LLM → 使用量** で確認してください。

**LLM が応答を拒否した（refusal）**
モデルの安全機能による拒否は、正常な動作として扱われます。そのアラートはルールベースの判定にフォールバックします。
**LLM → 呼び出し履歴** で状態を確認できます。

## 脆弱性インテリジェンス

**同期が失敗する**
TOKIWA を動かしている環境から、各サービス（NVD・CISA・FIRST・OSV・JVN・GitHub など）への外向きの通信が必要です。
NVD は API キーがないと取得速度の制限が厳しく、GitHub もトークンがある方が安定します。
JVN は提供側の刷新により、取得できない可能性があります（未確認）。

## Docker

**`PermissionError: /data/...` や「/data is not writable」**
コンテナは uid 10001 で動きます。bind mount を使う場合は、ホスト側のディレクトリを
`sudo chown -R 10001:10001 <dir>` で変更してください（名前付きボリュームなら自動で正しくなります）。

**コンテナが `unhealthy` になる**
`docker inspect --format '{{json .State.Health}}' <container>` で原因を確認します。HTTP を持たないロール（agent / sim）では
`TOKIWA_HEALTHCHECK_URL=none`、Gate では `http://127.0.0.1:8080/__tokiwa/health` を設定します。

**リバースプロキシの背後でリアルタイム更新が止まる**
SSE（`/api/v1/stream`）のバッファリングを切り、読み取りタイムアウトを長くしてください（[インストールと運用](Installation) の nginx の例を参照）。

## データ

**最初からやり直したい**
サーバーを止めて、データディレクトリ（ソースから動かしている場合は `backend/data/`、Docker ではボリューム）を削除します。

**アップグレード後にエラーが出る**
v0.1 にはスキーマの自動移行がありません。リリースノートや `HANDOFF.md` でスキーマの変更を確認し、
必要ならバックアップから戻してください。

---

解決しない場合は、[Issue](https://github.com/JUCK-Kurohasu/TOKIWA/issues) で、実行したコマンド・ログ（**秘密情報は伏せて**）・環境を添えて知らせてください。
