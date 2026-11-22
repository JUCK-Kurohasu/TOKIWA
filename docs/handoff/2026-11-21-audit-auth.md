# 2026-11 監査対応: auth レーン（ログイン・初期セットアップ・管理者・鍵ファイル・JWT）

担当 Issue: #92 + #170, #95, #56, #34, #163 (c)(d), #102。指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`
（#92=L07-07, #170=L18-05, #95=L07-10, #56=L07-03, #34=L07-02, #163=L18-04, #102=L13-03）。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #92 + #170 | 完全 | `tokiwa.auth.accounts.lock_accounts()` で降格・削除・セットアップを 1 トランザクション内で直列化（SQLite は no-op UPDATE で書き込みロック＝BEGIN IMMEDIATE 相当、PostgreSQL は admin 行を `FOR UPDATE`）。ロック後に対象と操作者を読み直し、操作者がもう admin でなければ 403。セットアップ済みフラグ（新テーブル `auth_state`）を導入し、ユーザーが 0 人になっても `/auth/setup` を再開しない。旧 DB は起動時にフラグを補完し、admin が 0 人なら起動ログに復旧手順を警告。並行テスト（`asyncio.gather` + 認証直後のバリア）は修正前のコードで赤になることを確認済み | 24fafb1 |
| #95 | 完全 | 初回セットアップに 1 回限りのセットアップコード（80 bit、`ABCD-EFGH-JKLM-NPQR` 形式）を必須化（`auth.setup_code_required`、既定 true）。サーバー起動時に `data_dir/setup-code`（0600、原子的に作成）とログ（WARNING、`<base_url>/setup#code=...`。フラグメントなのでサーバー/プロキシのログには載らない）に出し、成功後に削除。フロントのセットアップ画面に入力欄を追加（URL の `#code=` から自動入力し、読んだらアドレスバーから消す）。count→INSERT は #92 のロック + `auth_state` 主キーで直列化。`scripts/docker-smoke.sh`・conftest・wiki（Quick-Start / Installation / Lab / Troubleshooting / Configuration × 4 言語）・README・lab/README・.env.example・api-contract を更新 | d8ce2c1 |
| #56 | 完全 | (1) ユーザー名+送信元 IP（既定 5 回）と送信元 IP（既定 30 回、スプレー対策）の失敗をスライディング窓（既定 15 分）で数え、超えたら 429 + `Retry-After`（`auth.login_*` で設定可、0 で無効）。状態は DB の新テーブル `auth_login_failures`（キーは SHA-256。入力されたユーザー名は残さない）なので複数ワーカー・再起動でも共有。試行を **パスワード検証前に失敗として記録・コミット** し、数えてから検証、成功・拒否時に取り消す方式で、並列 12 本でも検証は上限回数まで（テスト済み）。(2) 存在しないユーザーでも定数のダミーハッシュで scrypt を 1 回実行。(3) `auth.login.success` / `auth.login.failure`（client_ip, known_user, locked。パスワードは記録しない）、`auth.setup` / `auth.setup.failure` を監査記録。セットアップコードの誤りも送信元 IP 単位で同じ制限。(4) scrypt を `asyncio.to_thread` + イベントループごとのセマフォ（`auth.password_hash_concurrency`、既定 4）で実行（ハッシュ中も /health が応答することをテスト）。`LoginRequest` に長さ上限 | bf91418 |
| #34 | 完全 | `users.token_version`（`server_default="0"`、起動時に既存 DB へ追加）を JWT のクレーム `ver` に入れ、`deps.user_from_token` で照合（不一致は 401 `token revoked`。`ver` の無い旧 JWT は 0 扱いで互換）。パスワード変更・ロール変更（PATCH /users）、`POST /auth/logout`（自分の全セッション）、`POST /users/{id}/revoke-sessions`（管理者が他ユーザーを全端末からログアウト）で版数を原子的に +1。監査 `auth.logout` / `user.sessions_revoked`、`user.update` に `sessions_revoked`。フロント: ログアウトボタンが `/auth/logout` を呼ぶ（失敗してもローカルは消す。`authStore.logout()` 自体は API を呼ばない＝401 ループ回避）、ユーザー一覧に「セッション失効」ボタン。TTL 既定 12 時間は不変 | (このコミット) |
| #163 (c)(d) | 未着手 | | |
| #102 | 未着手 | | |

## 要判断

- **#95 セットアップコードを既定で必須にした（後方互換の扱い: (b) 既定を変えて利用者側の手順を同時に直す）**。UI からの初回セットアップは
  「ログ（または `data_dir/setup-code`）のコードを入力する」1 手間が増える。ログに出る URL を開けば自動入力されるので、Quick-Start の流れは
  ほぼ同じ。`/auth/setup` を直接叩く自動化（CI の docker-smoke.sh など）はコードの読み取りが必要（smoke は修正済み）。
  無効化は `TOKIWA_AUTH__SETUP_CODE_REQUIRED=false`。CLI で最初の管理者を作る運用（`tokiwa user create --role admin`）は従来どおり。
- **セットアップコードをログに出している**（Jupyter 方式。指示どおり）。AGENTS.md §2-5 の「秘密をログに書かない」との兼ね合い:
  セットアップ完了までしか使えない 1 回限りのコードで、ログを読める者はそもそもサーバー側にいる、という判断。ログ収集基盤に送っている場合は
  セットアップ完了まで（または `setup-code` ファイルだけで運用するなら）気にする余地がある。ログ出力を止める設定は作っていない。
- 「setup_required 中は 127.0.0.1 からのみ受け付ける」案は採らなかった（Docker のポート公開では接続元がブリッジの IP になり、同一ホストの
  リバースプロキシ配下では全員が 127.0.0.1 に見えるため、どちらでも誤動作する）。

- **#56 ログイン失敗の状態は DB に置いた**（プロセス内ではなく）。理由: 複数ワーカーで上限が N 倍になる・再起動でリセットされる・テスト間で
  状態が漏れる。代償は失敗 1 回ごとに 1 行の INSERT と、ログインごとに 2〜3 回のコミット（成功時は記録した行を削除）。行は窓（15 分）より古いものを
  失敗記録のたびに削除する。
- **リバースプロキシの背後では送信元 IP が全員プロキシの IP になる**（uvicorn の `--forwarded-allow-ips` / `FORWARDED_ALLOW_IPS` を設定していない場合）。
  そのとき (a) 攻撃者が admin を 5 回失敗させると、全員が admin でログインできなくなる（ロックアウトによる DoS）、(b) 送信元 IP 単位の上限 30 回が
  全利用者の合算になる。`.env.example` には `FORWARDED_ALLOW_IPS` の記載がある。既定値（5 / 30 / 15 分）を緩めるか、ユーザー名単位の
  ロックをやめて遅延（指数バックオフ）にするかは運用判断。現状はユーザー名+IP 単位なので、正しく IP が見えていれば他の端末からはログインできる。
- 429 の応答はロック中であることを明かすが、存在しないユーザー名でも同じ条件でロックされるので、ユーザー名の存在は判別できない。

- **#34 ログアウトは「そのユーザーの全端末」を失効させる**（指示どおり版数方式）。端末単位のログアウトには jti の失効リスト（毎リクエスト 1 回の参照）が要る。管理者が **自分の** パスワード・ロールを変えた場合も自分のログインが切れ、再ログインが必要になる（盗まれたトークンも切るため、例外にしていない）。
- **#34 TTL 12 時間は変えていない**（後方互換）。短縮（例 1 時間 + リフレッシュ）や HttpOnly Cookie への移行（localStorage の JWT は XSS で読める）は要判断。

## 失敗した試み

- #56: 最初は「ロック確認 → 検証 → 失敗なら記録」の順にしたが、`asyncio.gather` で 12 本並列に投げると 12 本とも検証まで進んだ
  （全員が記録前の 0 件を見る）。「先に記録してコミット → 自分の行を含めて数える」に変えて上限内に収まった。

- 並行テストを `asyncio.gather` だけで書くと、修正前のコードでも 2 本目が 409 になり競合が再現しなかった（1 本目が先にコミットまで
  進む）。`deps.user_from_token` を包んで「2 本とも認証を通過するまで待つ」バリアを入れると修正前は 200/200（管理者 0 人）で赤になる。

## 担当外の変更

- `backend/src/tokiwa/api/deps.py`: `user_from_token` に版数照合を追加（JWT 検証部分のみ。所有範囲）。
- `backend/tests/api/test_users_tokens.py::test_demote_and_promote_take_effect_immediately`: ロール変更で旧 JWT が 401 になるため、再ログインしてから 403 / 200 を確認するよう変更。
- `frontend/src/components/layout/AppShell.tsx`（ログアウトボタン）と `frontend/src/pages/settings/UsersTab.tsx`（セッション失効ボタン）: 最小差分。

- `backend/src/tokiwa/config.py`: `AuthSettings` を新設し `Settings.auth` を 1 行追加（自レーンの設定セクション）。
- `backend/src/tokiwa/schemas/system.py`: `AuthStatus.setup_code_required: bool = False` を追加（default 付き・互換）。
- `backend/tests/conftest.py` の `admin_headers` と `tests/test_skeleton.py`: `/auth/setup` にセットアップコードを渡す（最小差分）。
- `scripts/docker-smoke.sh`（CI の Docker スモーク）: `/data/setup-code` を `docker exec` で読んで渡し、セットアップ後に消えていることを確認。
  この環境に Docker が無いため **未実行**（`bash -n` のみ。shellcheck も未導入）。
- `frontend/src/pages/auth/route.tsx` / `frontend/src/lib/authGate.ts`: セットアップコード入力欄と型（frontend レーンと競合しうる最小差分）。
- `README.md` / `lab/README.md` / `.env.example`: セットアップコードの案内を 1〜4 行。

- `backend/tests/api/test_system_audit.py`: セットアップが `auth.setup` を監査に記録するようになったため、actor=admin の件数と
  一覧の期待値を 3 → 4 件に更新（最小差分）。

## 他レーンへの依頼

- **stream（SSE）**: JWT の失効は接続時にしか見ないので、失効前に開いた `/api/v1/stream` はつながったまま（#34 の残り）。定期的に `token_version` を再確認して切断するか、失効時に bus で通知して該当ユーザーのストリームを閉じる対応が必要。

- **http-hardening（#91）**: `/auth/login` と `/auth/setup` の失敗経路はハンドラ内で `await session.commit()` してから 401/403/429 を
  raise する（拒否時もロールバックされずに失敗記録・監査を残すため）。get_session を変えるときに、ハンドラ内コミット後もセッションが
  使い続けられること（`expire_on_commit=False`）を保ってほしい。
- **detect（自己監視）**: #56 の推奨 (3) の「TOKIWA 自身への連続ログイン失敗を検知ルールにする」は未実装。監査ログの `auth.login.failure`
  （details.client_ip / known_user / locked）を入力にできる。

## 未検証事項

- PostgreSQL での直列化（`SELECT ... FOR UPDATE` の READ COMMITTED での再評価、`auth_state` の主キー競合で 2 本目の setup が
  IntegrityError → 409 になること）は、この環境に PostgreSQL が無いため未実行。コードに `TODO(verify)` を残した。
- コミットが応答後に行われる問題（#91 / L07-04、http-hardening レーン）とは独立に正しい: ロックはコミットまで保持される。
