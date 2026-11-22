# 2026-11-22 監査対応レーン: respond-notify（系統 E「対処・通知」の工数 S）

担当 Issue（この順）: #63 → #64 → #118 → #128 + #168 → #130。
指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`（#63=L09-02, #64=L09-04, #118=L09-09, #128=L09-08,
#168=L17-06, #130=L09-12）。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #63 | 完全 | backend: 新テーブル `response_suppressions`（`db/models/response_suppression.py`）と `respond/suppress.py`。却下・取り消しで抑止を記録（指定時 `suppress`＝自動提案を破棄、無指定でも `manual_only`＝`response.auto_approve_cooldown_minutes` 既定 24 時間は自動承認しない）。`create_proposal` が同じトランザクションで照合（IP/CIDR は重なり）。API: reject/revert の `suppress_hours`/`suppress_permanent`/`reason`、`GET/POST /response/suppressions`、`POST .../{id}/lift`。テスト `tests/respond/test_respond_suppression.py`（取り消し後の再提案が自動承認されない・破棄される・期限切れ/解除で戻る・CIDR 重なり・人間の提案・API）。UI: 却下/取り消しダイアログに「同じ対象への再提案」（抑止しない / N 時間 / 恒久）と取り消し理由、カードに「抑止中のため自動承認しない」、対処画面に「抑止」タブ（一覧・解除）。docs/response.md §1.1、api-contract、wiki Response・Configuration・Web-UI ×4 | d1aa482, e56b955 |
| #64 | 完全 | `respond/policy.py`: `refused_by_settings` / `enforceable_gate_rows` で active 行を現在の設定（protected_cidrs・サーバー自身・min_prefix・block_private_targets）で再検証し、不合格は Gate ポリシーから除外（`GET /gate/status` も同じ集合で数える）。`service.revoke_disallowed_actions`: 不合格の active ネットワーク対処（gate 系 + nftables_block）を `reverted` にし監査 `response.auto_revert`（actor `system:settings`）・`result.auto_reverted`・executor の revert（nft 要素も削除）。期限切れジョブ（30 秒）と起動時に実行。`GatePolicy.entry_expires_at`（セクション別のエントリ期限。統合エントリは最も遅い期限、期限なしが混ざれば省略。version に含む）と Gate 側の適用（`gate/policy.py` の `PolicyManager`: 受信時の単調時計 + (expires_at - generated_at) を過ぎたエントリを外して再コンパイル。fail-static 中も有効、Gate の時計ずれに非依存）。推奨の「一括取り消し管理 API」は自動取り消しで代替。テスト `tests/respond/test_respond_revalidate.py`。docs/response.md・docs/gate.md・api-contract・wiki Response/Sensors ×4 | feacf5b |
| #118 | 部分（(b) の接続固定のみ未） | (a) `password_env` 許可リスト（`TOKIWA_NOTIFY_SMTP_*` / `TOKIWA_SMTP_PASSWORD*` + 設定 `notify.smtp_password_envs` の完全一致）と拒否リスト（`TOKIWA_<SECTION>__*`、`ANTHROPIC_`・`OPENAI_`・`AWS_`・`AZURE_`・`GOOGLE_`・`GCP_`・`GITHUB_`・`GH_`・`HF_`・`HUGGING`・`NVD_`・`DATABASE_`・`POSTGRES`・`PG`。設定で列挙しても拒否）。保存時 422、既存チャネルは送信時に理由付き DeliveryError（接続・ログインしない）。(b) `notify.smtp_allowed_hosts` / `notify.smtp_block_private`（`outbound.check_host` を共用）。(c) 認証付きは starttls/ssl 必須（`notify.smtp_allow_plaintext_auth` で解除）。(d) `merge_masked`: メールは host/port/username、webhook は url が変わったらマスク値の秘密を引き継がず 422。(e) 監査 details に `destination`（作成・削除）と `destination: {before, after}`（更新）。(f) SMTP エラーは `SMTP connection failed` / `SMTP authentication failed` / `SMTP error` に丸める。UI のヒント文言、docs/response.md §6、wiki Response・Configuration ×4。テスト `tests/notify/test_notify_email_policy.py`（監査の再現: ANTHROPIC_API_KEY・ホスト書き換え） | cc8f2d6 |
| #128 + #168 | 部分（#168 の「要約プロンプトに個人名を書かない指示」は llm-triage レーンへ依頼） | 非信頼テキストの無害化（`notify/channels.py`）: Slack/Discord/メールで本文中の URL を `hxxps://` に（自動リンク防止）、Discord は title・description・field 値の Markdown 特殊文字（`\ * _ ~` バッククォート `| > # [ ] ( ) -`）をバックスラッシュでエスケープ（エスケープ後に切り詰め、末尾の孤立したバックスラッシュを除去。field 名は TOKIWA のキーなのでそのまま）、Slack は header/section/fields を `plain_text`＋最上位 `mrkdwn:false`、TOKIWA 自身の UI リンクだけリンクのまま。`clean()` で双方向制御文字・ゼロ幅文字を除去。`notify.include_summary`（既定 false: インシデント要約と対処の reason＝`render_action` の LLM 理由を外部へ送らない）と `notify.include_source_ip`（既定 true。false で送信元 IP と IP/CIDR の対処対象を `(hidden)`、webhook の data からも除外）。テスト `tests/notify/test_notify_untrusted_text.py`。docs/response.md §6、wiki Response・Configuration・Data-Handling ×4 | 229eb9e |
| #130 | 完全 | (a) approved / active 行には reason を追記せず、incident_id/alert_id も補完しない。後続の提案は新しい nullable 列 `notes`（`[{at, proposed_by, by, reason, incident_id, alert_id}]`、同文・承認済み reason と同じ文は積まない、最新 50 件・各 2000 文字）。proposed 行は従来どおり追記。(b) 承認時に `result.approval_snapshot`（type・target・params・TTL・reason・incident/alert ID・提案元・proposed_by_user・承認者・時刻・self_approval）を同じトランザクションで保存し、監査 `response.approve` の details にも（reason は 1000 文字まで）。(c) 新しい nullable 列 `proposed_by_user`（API 提案のユーザー名）。UI: カードに提案者名・「自己承認」バッジ・承認後に届いた提案の一覧、承認ダイアログで自分の提案なら警告、履歴表にも自己承認バッジ。`ResponseAction` に `proposed_by_user` / `notes`（default 付き）、`frontend/src/api/types.ts` 更新。テスト `tests/respond/test_respond_approval_record.py`。docs/response.md・api-contract・wiki Response ×4 | 7021286, (ui) |

## 要判断

- **#130**: 承認ダイアログを開いてから承認ボタンを押すまでの間に、同じ対象への提案が `proposed` 行の reason に追記されうる
  （承認者が見ていない文が承認される）。スナップショットは承認時点の行を保存するので後から確認はできるが、防ぐには承認 API に
  `expected_updated_at` を渡して不一致なら 409 にする必要がある（未実装）。二人承認の強制も未実装（表示のみ）。

- **#128 / #168**: `include_summary` の既定を false にした（監査の推奨「承認依頼は構造化フィールドのみを既定」と、要約が第三者 SaaS に
  個人項目を運ぶ懸念のため）。人間（analyst）が書いた理由も同じスイッチで落ちる。人間の理由だけは常に載せる案もある。
  `include_source_ip` は後方互換を優先して既定 true（SOC 運用で IP は主要情報のため）。アラートのタイトル・説明（検知器の文）は
  LLM 文ではないので常に載せる（エスケープ・URL 無害化はする）。

- **#118 後方互換**: 以前は `password_env` に任意の名前を書けた（文書・UI に推奨名は無く、UI の placeholder だけが
  `TOKIWA_SMTP_PASSWORD`＝許可される名前）。それ以外の名前（例 `SMTP_PASSWORD`）を使っている既存チャネルは **送信が止まる**
  （テスト送信・ログに「password_env X is not allowed: use a TOKIWA_NOTIFY_SMTP_* ... or list the name in notify.smtp_password_envs」）。
  移行: 環境変数名を変えるか、`notify.smtp_password_envs: [SMTP_PASSWORD]` をサーバー設定（YAML / `TOKIWA_NOTIFY__SMTP_PASSWORD_ENVS`）に足す。
  拒否リストに当たる名前（`TOKIWA_*__*`・`ANTHROPIC_*` 等）は救済しない。リリースノートに書くこと。
- **#118**: 平文 AUTH（starttls=false・ssl=false でユーザー名あり）を既定で拒否。社内の 25 番ポートで認証付き平文リレーを使っている
  構成は保存・送信が止まる（`notify.smtp_allow_plaintext_auth=true` で旧動作）。
- **#118**: `notify.smtp_block_private` は既定 false（社内リレーが一般的で、docs も「SMTP にはプライベート宛先拒否を適用しない」と
  していたため）。外向き SMTP だけの組織は true + `smtp_allowed_hosts` を推奨。
- **#118 (f)**: SMTP のエラーだけ丸めた。Webhook 系のテスト送信は `request failed: ConnectError` 等の型名を返したまま
  （既定で private 宛は SSRF ガードで拒否されるので探索面は小さい）。必要なら同じ丸めを `outbound.post_json` に。

- **#63**: 人間が API から提案したものは `suppress` 中でも作成する（自動承認だけ禁止）。人間の明示的な提案を黙って捨てない
  ため。抑止を優先して 409 にする案もある。
- **#63**: 照合は「型 + 対象」。block_ip を抑止しても同じ IP の rate_limit / tarpit は提案される（指摘の推奨どおり）。
  「全種別を抑止」が要るなら `action_type` を任意にする拡張が必要。

## 既定動作の変更

- **#128 / #168**: 通知（承認依頼・インシデント）に LLM の自由文（対処の理由・インシデント要約）を **既定で載せない**
  （`notify.include_summary=true` で旧動作）。Slack は本文・フィールドが plain_text になり太字等の装飾が消える、Discord は
  特殊文字がエスケープされる、本文中の URL は `hxxps://` 表記になる（UI リンクは従来どおり）。Webhook の JSON の形は不変
  （`text` から要約・理由が消えるだけ）。

- **#118**: メールの `password_env` は許可された名前だけ（上記「要判断」の後方互換を参照）。認証付きは STARTTLS/SSL 必須。
  宛先（host/port/username、webhook の url）を変える PATCH はマスク値の秘密を引き継がず 422。SMTP エラー文言が種類だけになった。

- **#64**: `response.protected_cidrs` 等の安全設定を変えると、既に active な対処も次の Gate 取得で外れ、30 秒以内か起動時に
  `reverted` になる（以前は TTL 切れか個別取り消しまで有効）。Gate はサーバー不達中もエントリの期限を過ぎたら外す
  （以前は不達の間ずっと保持）。期限のないエントリ（`max_ttl` 未設定などで expires_at が無い行）は従来どおり保持。

- **#63**: 人間が却下・取り消した (型, 対象) は、その後 24 時間（`response.auto_approve_cooldown_minutes`）自動承認されない
  （提案は作られ、人間の承認を待つ）。以前は取り消した直後の次のアラートで同じ遮断が自動承認され再適用されていた。
  0 にすると旧動作。自動承認を使っていない構成では見た目の変化なし（抑止一覧に `manual_only` 行が増えるだけ）。

## 失敗した試み

## 担当外の変更

- `frontend/src/components/common/ResponseActions.tsx`（対処カード・承認/却下/取り消しダイアログ。対処画面の共通部品）: #63 の抑止選択・取り消し理由・抑止バッジ。
- `frontend/src/api/types.ts`（共有）: #130 で `ResponseAction` に任意項目 `proposed_by_user` / `notes` と `ActionNote` 型を追加のみ。
- `backend/src/tokiwa/db/models/response.py`: `ResponseActionRow` に nullable 列 `proposed_by_user` / `notes`（#130。schema_sync で既存 DB に追加）。
- `frontend/src/api/types-ops.ts`: `SuppressOptions` / `ActionRevertBody` / `ResponseSuppression` を追加（既存型は `ActionRejectBody` に任意項目を足しただけ）。
- `docs/api-contract.md`: 対処の表に抑止 API を追記。#64 で GatePolicy の説明を追記。
- `backend/src/tokiwa/gate/policy.py`（Gate 側。tokens レーンが第 1 波でトークン再読込を入れたファイル）: #64 のエントリ期限の適用のみ
  （`PolicyManager.__init__` に `clock` 引数、`current` プロパティで期限確認、`apply` で期限表を作る、`_without`/`_expire_entries`、stats に `expired_locally`）。
  `refresh` / トークン処理は触っていない。
- `backend/src/tokiwa/schemas/response.py`: `GatePolicy.entry_expires_at`（default 付きの追加のみ。古い Gate は無視する）。
- `backend/src/tokiwa/api/routes/gate.py`: `gate_status` の active 行取得を `enforceable_gate_rows` に置き換え（担当の #64 部分）。
- `docs/gate.md`・wiki `Sensors*.md`: fail-static の説明にエントリ期限を追記。
- `config.py` は `ResponseSettings` / `NotifySettings` のみ（担当内）。

## 他レーンへの依頼

- **llm-triage レーン（#168 の残り）**: インシデント要約・対処理由を生成するトリアージのプロンプトに「個人名・連絡先・メールアドレスを
  書かない（IP・パス・ルール名で記述する）」指示を足す。通知側は `notify.include_summary` 既定 false で外部送信を止めたが、
  UI・DB・`include_summary=true` の構成には残る。

## 未検証事項

- **#128**: Discord の embed タイトルで Markdown が描画されるか（されなければエスケープのバックスラッシュが見える）、Slack の
  plain_text で `&amp;` が復号されるか・スキーム無しドメインが自動リンクされるか、Incoming Webhook が最上位 `mrkdwn:false` を
  解釈するか（いずれもコード内 `TODO(verify)`。ネットワーク不可のため実機未確認）。

- **#118 (b)**: SMTP ホストは名前解決して検査するだけで、smtplib の接続をその IP に固定していない（`_get_socket` の差し替えが
  必要で、typeshed 上も非公開 API）。webhook と同じく検査と接続の間の DNS リバインディングは残存リスク。厳格な環境は
  `notify.smtp_allowed_hosts` を使う。
