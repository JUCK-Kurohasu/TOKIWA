# 2026-11 監査対応: auth レーン（ログイン・初期セットアップ・管理者・鍵ファイル・JWT）

担当 Issue: #92 + #170, #95, #56, #34, #163 (c)(d), #102。指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`
（#92=L07-07, #170=L18-05, #95=L07-10, #56=L07-03, #34=L07-02, #163=L18-04, #102=L13-03）。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #92 + #170 | 完全 | `tokiwa.auth.accounts.lock_accounts()` で降格・削除・セットアップを 1 トランザクション内で直列化（SQLite は no-op UPDATE で書き込みロック＝BEGIN IMMEDIATE 相当、PostgreSQL は admin 行を `FOR UPDATE`）。ロック後に対象と操作者を読み直し、操作者がもう admin でなければ 403。セットアップ済みフラグ（新テーブル `auth_state`）を導入し、ユーザーが 0 人になっても `/auth/setup` を再開しない。旧 DB は起動時にフラグを補完し、admin が 0 人なら起動ログに復旧手順を警告。並行テスト（`asyncio.gather` + 認証直後のバリア）は修正前のコードで赤になることを確認済み | 24fafb1 |
| #95 | 完全 | 初回セットアップに 1 回限りのセットアップコード（80 bit、`ABCD-EFGH-JKLM-NPQR` 形式）を必須化（`auth.setup_code_required`、既定 true）。サーバー起動時に `data_dir/setup-code`（0600、原子的に作成）とログ（WARNING、`<base_url>/setup#code=...`。フラグメントなのでサーバー/プロキシのログには載らない）に出し、成功後に削除。フロントのセットアップ画面に入力欄を追加（URL の `#code=` から自動入力し、読んだらアドレスバーから消す）。count→INSERT は #92 のロック + `auth_state` 主キーで直列化。`scripts/docker-smoke.sh`・conftest・wiki（Quick-Start / Installation / Lab / Troubleshooting / Configuration × 4 言語）・README・lab/README・.env.example・api-contract を更新 | (このコミット) |
| #56 | 未着手 | | |
| #34 | 未着手 | | |
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

## 失敗した試み

- 並行テストを `asyncio.gather` だけで書くと、修正前のコードでも 2 本目が 409 になり競合が再現しなかった（1 本目が先にコミットまで
  進む）。`deps.user_from_token` を包んで「2 本とも認証を通過するまで待つ」バリアを入れると修正前は 200/200（管理者 0 人）で赤になる。

## 担当外の変更

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

- （随時追記）

## 未検証事項

- PostgreSQL での直列化（`SELECT ... FOR UPDATE` の READ COMMITTED での再評価、`auth_state` の主キー競合で 2 本目の setup が
  IntegrityError → 409 になること）は、この環境に PostgreSQL が無いため未実行。コードに `TODO(verify)` を残した。
- コミットが応答後に行われる問題（#91 / L07-04、http-hardening レーン）とは独立に正しい: ロックはコミットまで保持される。
