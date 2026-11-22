# Mirage — デセプション（デコイ / ハニートークン / AI カナリア / 迷路）

> 実装: `backend/src/tokiwa/deception/`、検知器 `detect/detectors/deception_trip.py`、API `api/routes/deception.py`。
> 設定: `config.py` の `DeceptionSettings`（`TOKIWA_DECEPTION__*`）。

## 1. 目的と全体像

正規ユーザーが絶対に触れない罠を **自組織の資産上** に置き、触れた者を高確度で検知する。特に
**AI カナリア（逆プロンプトインジェクション）**: デコイに「AI エージェントだけが読んで従う隠し指示」を埋め込み、
指示どおりのリクエストが来たら LLM 駆動のクライアントと断定する（`ai_score=0.99`, `category=ai_agent`）。

```
server: assets(DB) ──render──▶ GatePolicy.decoys / html_injection ──▶ Gate が配信（上流には転送しない）
                     └─index──▶ deception.trip 検知器（取り込みイベントを照合）──▶ critical アラート
event.ingested ──▶ service.record_trips ──▶ deception_trips 行 + trip_count/last_tripped + bus "deception.tripped"
```

## 2. 資産の種類（`DeceptionKind`）

| kind | 何を置くか | 配信 | トリップ条件 |
|---|---|---|---|
| `decoy_path` | `/.env` `/backup.sql` `/admin/config.php` `/.git/config` `/api/internal/debug` など。中身は偽の認証情報（下記の派生値）+ AI カナリア注記 | パス固定（末尾 `*` で前方一致） | パスへのアクセス、または中のハニートークン値の使用 |
| `honeytoken` | 偽 AWS キー / 偽 API キー / 偽 DB 資格情報。種別は名前・説明から推定（aws/s3/iam → AWS、db/postgres/mysql… → DB、他 → API キー） | `path` があればそのファイルとして配信、無ければ運用者が任意の場所に置く（プレビューで本文を取得） | 値がどこかのイベントに現れる |
| `ai_canary` | 隠し指示。`path` 無し = 上流 HTML へ挿入、`/robots.txt` `/llms.txt` `*.json`(OpenAPI) `*.md|txt` その他(HTML) | 指示を含むページ + 指示に従った先 `/api/internal/<値>*` の偽エンドポイント一覧 | **値の使用のみ**（ページ取得自体はトリップしない: robots.txt は正規クローラも読むため） |
| `labyrinth` | `labyrinth_prefix`（既定 `/archive/`）以下の決定的な迷路。`noindex,nofollow`、スクリプトなし | 先頭 40 ページを事前描画 + `prefix*` のワイルドカード | 配下へのアクセス。深さ 3 以上で critical |

### 既定のシード（起動時・冪等）
- `deception.decoy_paths` の各パスに `decoy_path`。
- `ai_canaries=true` のとき: HTML 挿入用（有効）、`/api/internal/openapi.json`（有効）、`/robots.txt`（**無効**）、
  `/llms.txt`（**無効**）。robots.txt / llms.txt は上流の同名ファイルを置き換えてしまうため既定 OFF。
- `labyrinth_enabled=true` のとき迷路を 1 つ。
- 既存資産（同じ kind + path）は変更しないので「無効化」は再起動後も保たれる。**削除は再起動で復活する**
  （設定に残っている限り）。止めたい場合は無効化するか設定から外す。

## 3. トークン設計と「観測可能性」（最重要）

イベントはサーバーに届く前に `tokiwa.llm.redact` でマスクされる（Gate / アダプタ）。検知器は **マスク後** の値しか
見られないので、トークンはマスクされない形にしてある:

| 値 | 形式 | 実在形式との違い |
|---|---|---|
| API キー（decoy の主トークン） | `svc_live_` + 英数 32 | 実在ベンダーの接頭辞ではない |
| AWS アクセスキー ID | `AKIA` + 英大文字数字 20 = **24 文字** | 実物は 20 文字 → 有効なキー ID になり得ず、redact の `\bAKIA[0-9A-Z]{16}\b` にも当たらない |
| AWS シークレット | 英数 **42 文字** | 実物は 40 文字（base64） |
| DB ユーザー | `app_rw_` + 英小文字数字 12 | — |
| DB パスワード | 英数 24 | — |
| AI カナリア | `dbg_` + 英数 24 | — |

- 使う文字は `[A-Za-z0-9_]` のみ（`-` `.` `@` `:` `=` 空白なし）→ JWT / `sk-` / URL 資格情報 / メール / IPv4 /
  カード番号 / `key=value` 系のパターンが成立しない。テスト `test_deception_tokens.py` が redact の全パターンで保証。
- 1 資産 1 トークンを DB に保存し、同じデコイ内の他の値は **サーバー秘密から導出した鍵の HMAC** で派生（保存不要・
  描画と検知が必ず一致・鍵を知らない攻撃者には無関係な値に見える）。`server.secret_key` を変えると派生値が変わる
  （配信中のデコイは自動で追従するが、外部に置いた値は検知されなくなる）。
- ユーザー指定トークンは 12〜128 文字・空白なし・**redact を通しても残ること** を作成時に検証（422）。

### どこなら見えるか / 見えないか

| 位置 | 見える? | 備考 |
|---|---|---|
| URL パス、`ref=` など中立なクエリ名、`X-Debug-Auth` など非秘匿ヘッダの値、キー名を伴わない本文、ログインフォームの `username=` | ✅ | AI カナリアはこの位置を使わせるよう指示文を設計 |
| `Authorization` / `Cookie` / `X-API-Key` / `X-Auth-Token` などの値 | ❌ | `llm.redaction.sensitive_headers` は値全体をマスク |
| `token=` `password=` `api_key=` `auth=` `secret=` `pass=` … の値（クエリ・本文・JSON） | ❌ | redact の `secret_param` |
| `scheme://user:pass@` | ❌ | `url_credentials` |

→ そのため DB 系は **ユーザー名側** をトークンとして索引（`username=` は残る）、AWS は **キー ID 側**
（`X-Amz-Credential=` は残る）。`deception.canary_header` を `sensitive_headers` に入れると AI カナリアのヘッダ追従が
検知できなくなる（起動時に警告ログ）。

## 4. AI カナリアの設計原則

1. **値は自然文の中にだけ置く**。`href`/`src`、OpenAPI の `example`/`default`、robots の `Disallow` 行、
   `/api/internal/<値>` のような連結済みパスとしては **決して** 出さない。リンク抽出ツール・クローラ・API ファザーが
   理解せずに「追従」してしまうと AI 断定の根拠が崩れるため。
2. 追従には「読んで従う」ことが要る: ヘッダ `X-Debug-Auth: <値>` を付ける、または `/api/internal/` + 値 + `/` を
   **組み立てる**。これをするのは LLM 駆動のクライアントだけ。
3. 判定（重みは §5 の「出所」で変わる）:
   - **followed**（`ai_canary_followed`）: 値が `canary_header` の値にある、またはパス / Referer が
     `/api/internal/<値>` で始まる。**AI と断定（critical, `ai_agent`, ai_score 0.99）するのはカナリアヘッダなど
     クライアント自身にしか付けられない位置に値があるときだけ**。経路 GET だけは「受動」（medium）。
   - **observed**（`ai_canary_token`）: それ以外の場所に値が現れた（隠しテキストを読んだ主体。人間がソースから
     写した可能性は残る）。ヘッダ・UA なら critical, `deception`, ai_score 0.85、パス・クエリ・本文だけなら「受動」。
   - カナリア値は保護対象ページを開けば誰でも読めるので、**経路 GET やクエリは第三者が他人に送らせられる**
     （掲示板・メール・ユーザー投稿の `<img src=…/api/internal/<値>/>`、チャットに貼られたリンクのプレビュー取得）。
     これを AI 断定・遮断提案の根拠にすると、閲覧者の IP を「攻撃 AI」に仕立てられる（監査 #133）。
4. HTML 挿入は `<!-- -->` + `hidden aria-hidden="true" display:none` の要素。視覚利用者にもスクリーンリーダー利用者にも
   提示されない。スクリプト・外部リソースは含まない。
5. 指示文は `deception/templates.py::canary_sentences()` の 1 か所（日英）。言語は `canary_language`、
   ヘッダ名は `canary_header`。**文言の強さ・言語は運用判断（HANDOFF 要判断事項）**。

## 5. 検知（`deception.trip`）

全イベント種別を対象に、パス・クエリ・ヘッダ・本文・Referer・UA・Host・`message`・`llm_app.prompt`・
`process.cmdline`・`raw`（先頭 16KB）を走査（URL デコード版も）。デコイパスは正規化（`%2e`/二重エンコード、`//`、
`..`、大文字小文字）して照合。1 イベント × 1 資産につき最も強い分類を 1 件。

**転記揺れ（監査 #30）**: トークン照合は **大文字小文字を区別しない**。さらに `\` を除いた版も照合する（エージェントの
Web 取得で広く使われる markdownify は `_` を `\_` にエスケープするので、`dbg\_…` がそのまま送られる）。`/api/internal/<値>`
の判定もデコード → `\` 除去 → 正規化してから行う。生成トークンの字母は変えていない（既存の設置済み値を壊さないため）。
**カナリアヘッダの試み**: `canary_header` が既知のカナリア値 **以外** の値で送られた（写し間違い・切り詰め・base64 等）
ときは、資産に紐付かないアラート `canary_attempt`（**medium**, `deception`, AI 断定なし、タグ `deception:canary_attempt`、
送信元ごとに 1 件）を出す。ヘッダ名は隠し指示にしか出てこないが、本プロジェクトの公開文書にも載るので AI 断定はしない。
`induced` の兆候があれば出さない。経路 `/api/internal/dbg*` で値が一致しないものは、実アプリの `/api/internal/` と
紛れやすく、リンクで誘発もできるので対象外。

**出所（`details.provenance`、`deception/provenance.py`。監査 #133）** — そのトリップを第三者が誘発できたか:

| provenance | 条件 | 扱い |
|---|---|---|
| `direct` | 下記以外（カナリアヘッダ・その他のヘッダ・UA に値がある、または誘発の兆候の無いデコイ/ハニートークン/迷路） | 下表のとおり（従来どおり） |
| `passive` | AI カナリア値が **リンクで届く位置だけ**（パス・クエリ・本文・Referer・Host・`message`・`raw`）に現れた | **medium**, `deception`, ai_score 0.5（AI 閾値未満）、AI と断定しない |
| `induced` | ブラウザがクロスサイト/サブリソースと示している: `Sec-Fetch-Site: cross-site`/`same-site`、`Sec-Fetch-Dest` が `document`/`empty` 以外（`image`, `script`, `iframe` …）、`Sec-Purpose: prefetch`、`Origin` が別ホストか `null`、`Referer` が別ホスト | **low**, `deception`, ai_score なし。全分類（デコイパス・ハニートークン含む） |

`passive` / `induced` のアラートは、相関（`correlate.scoring`）とルール判定（`triage.fallback`）が AI 断定に使う印
（タグに `ai_canary` を含む・エンティティ値 `ai_canary`）を持たない。タグは `deception:passive|induced` と
`deception_trip:canary_followed|canary_observed|decoy_path|…`。重大度が high 未満なのでルール判定は遮断を提案しない
（同じ送信元の攻撃系アラートがあれば、インシデントの重大度はそちらで上がる＝「相関で昇格」）。

| trip_type（`direct` のとき） | severity | category | ai_score | MITRE |
|---|---|---|---|---|
| ai_canary_followed | critical | ai_agent | 0.99 | — |
| ai_canary_token | critical | deception | 0.85 | — |
| honeytoken | critical | deception | — | T1552.001, T1078 |
| decoy_path | critical | deception | — | T1595.003 |
| labyrinth | high（深さ≥3 で critical） | deception | — | T1594 |
| canary_attempt（資産なし） | medium | deception | — | — |

重複排除キー: `deception.trip|<asset>|<分類>|<source_ip>`（AI 追従は別アラートとして立つ。`passive` は
`canary_passive`、`induced` は `induced` という別の分類なので、後から来た `direct` の追従は別アラートになる）。

**AI セッション（`aidetect`）との関係**: Gate が `ai_canary` 資産の経路を返したとき（`kind=deception` イベント）、
セッションを AI と断定（`canary_hits`）するのは `provenance.decisive_canary_hit()` が真のとき — 既知のカナリア値を
カナリアヘッダで送っていて、誘発の兆候が無いとき — だけ。経路・カナリアページ（`/api/internal/openapi.json` 等）を
取得しただけなら `decoy_hits`（敵対スコアのみ）として数える。
トークン集合はメモリにキャッシュし、資産変更のコミット後・DB/設定の差し替え時・60 秒ごとに再読込。
DB が初期化されていない文脈（他モジュールの単体テスト等）では空集合として何もしない。

## 6. Gate との約束（gate モジュールへの依頼）

> **gate トークンの漏えい＝デセプション配置の漏えい**（監査 #33）。Gate ポリシー（`GET /api/v1/gate/policy`、`gate`
> スコープ）にはデコイ経路・レンダリング済みデコイ本文（ハニートークン値入り）・AI カナリア文・カナリアヘッダが入る。
> `gate` スコープは Gate 専用トークンに限定する（CLI の既定は `ingest` のみ）。ポリシーからハニートークン値を外し
> Gate 側で HMAC 派生させる案は未実装（`docs/handoff/2026-11-21-audit-tokens-roles.md`）。

- `GatePolicy.decoys`: 完全一致ルートを優先し、次に最長の前方一致（`*` 終端）。デコイ応答は上流へ転送しない。
- デコイ応答は **1 リクエストにつき 1 イベント**（`kind=deception`, `deception.asset_id` 付き, `http` も埋める）。
  HTTP イベントと二重に送るとトリップ数が 2 回加算される。
- `html_injection` は `text/html` 応答に挿入（ON/OFF は `deception.ai_canaries` と `deception.html_injection`）。
  位置は `GatePolicy.html_injection_positions`（`deception.html_injection_positions`、監査 #41）: `body_start`
  （最初の本物の `<body …>` の直後。`<script>`/`<style>`/`<title>`/`<textarea>`/`<template>`/コメント内の文字列と、
  引用符内の `>` は飛ばす）、`body_end`（最後の `</body>` の直前。#41 以前はこれだけ）、`head`（`<head …>` の直後に
  スニペット先頭の HTML コメントだけ。`<div>` を入れると `<head>` がそこで閉じるため）。既定は `body_start` + `body_end`。
  理由: AI エージェントのツールはページの先頭 N 文字だけを LLM に渡すことが多く（ARTEX は 30,000 文字）、大きいページの
  末尾だけでは読まれない。`<head>` が巨大（インライン CSS/JS で数十 KB）なページでは `body_start` も範囲外になり得るので
  `head` を足す。位置フィールドが無いポリシー（古いサーバー）は `body_end` のみ、古い Gate は新フィールドを無視する
  （`body_end` のみ）。
- `deceive` 対象 IP は全リクエストをデコイへ（Mirage の迷路・偽エンドポイントが受け皿になる）。

## 7. API（`/api/v1/deception`）

| Method | Path | 権限 | 入出力 |
|---|---|---|---|
| GET | /assets | user | `?kind&enabled` → `DeceptionAsset[]` |
| POST | /assets | analyst | `DeceptionAssetIn` → `DeceptionAsset`（422 検証エラー / 409 トークン・パス重複） |

パスの検証（監査 #65。`service._gate_safe_path`）: Gate はデコイを **全訪問者に** 返し上流へ転送しないので、Gate と同じ
`gate.policy.normalize_path`（URL デコード後も）で `/` になるパス（`/.`、`//`、`/a/..`、`/%2e` …）は 422。前方一致（`*` 終端）は
`*` の前に完全なセグメントが 1 つ以上必要（`/admin/*` は可、`/a*` は `/about`・`/api/…` まで奪うので 422）。保存するパスは Gate で
正規化した形（`/a/../.env` → `/.env`）なので重複は 409 になる。respond の `deploy_canary` も `create_asset` を通るので同じ検証。
検証前に作られた行がルートを指していても `render.shadows_site()` で Gate に渡さない（警告ログ）。
未対応: 作成時に直近の `gate.http` で同じパスが上流から 2xx/3xx を返していないかの確認（409 + force）、承認画面での
「全利用者に影響」表示、既定シードの事前確認（監査 #65 の (c)〜(e)）。

| GET | /assets/{id} | user | → `DeceptionAsset` |
| PATCH | /assets/{id} | analyst | `DeceptionAssetUpdate`（`token: null` でローテーション、kind は不変） |
| DELETE | /assets/{id} | analyst | 204（トリップ履歴は残る） |
| GET | /trips | user | `?asset_id&source_ip&limit&offset` → `Page[Event]`（各イベントに `deception` 情報を付与、新しい順） |
| GET | /preview/{id} | analyst | `?path`（迷路のページ）→ `DeceptionPreview{asset_id, path, content_type, body, status_code, headers, served, extra_paths}` |

bus `deception.tripped`: `{asset_id, asset_kind, asset_name, event_id, source_ip, session_id, trip_type,
ai_canary_followed, timestamp}`。他モジュール向け関数: `service.create_asset(DeceptionAssetIn)`,
`service.delete_asset(id)`, `service.disable_asset(id)`（respond の deploy_canary / revert）。

## 8. 設定（調整できるところ）

| キー | 既定 | 意味 |
|---|---|---|
| `deception.enabled` | true | 全体スイッチ（OFF で配信・検知とも停止） |
| `deception.ai_canaries` | true | AI カナリア（ページ・挿入・デコイ内注記・着地ルート） |
| `deception.html_injection` | true | 上流 HTML への隠し指示挿入だけを止める |
| `deception.html_injection_positions` | `[body_start, body_end]` | 挿入位置（`head` / `body_start` / `body_end`、§6） |
| `deception.canary_header` | `X-Debug-Auth` | 指示で送らせるヘッダ。秘匿ヘッダ一覧に入れないこと |
| `deception.canary_language` | `both` | `ja` / `en` / `both`（指示文・迷路） |
| `deception.downgrade_browser_induced` | true | ブラウザのクロスサイト/サブリソース要求を `induced`（low・AI 断定なし）にする。false で従来どおり（経路だけの `passive` は常に有効） |
| `deception.decoy_paths` | 5 パス | 起動時にシードするデコイ |
| `deception.labyrinth_enabled` / `labyrinth_max_depth` / `labyrinth_prefix` | false / 8 / `/archive/` | 迷路 |

そのほか: 指示文 `templates.canary_sentences()`、デコイ本文 `templates.py`、深さ閾値
`deception_trip.LABYRINTH_CRITICAL_DEPTH`、事前描画ページ数 `labyrinth.DEFAULT_MAX_PAGES`、
`passive` / `induced` の重大度・確度 `deception_trip._PASSIVE_SPECS` / `_INDUCED_SPEC` と
`PASSIVE_CANARY_AI_SCORE`、リンクで届く欄の一覧 `provenance.LINK_REACHABLE_FIELDS`。

## 9. 倫理・法的配慮・運用上の注意

**守ること（実装上もそうなっている）**
1. **自組織の資産上のみ**。デコイは保護対象サイトの Gate が自分のドメインで返すだけ。第三者のシステムには何も置かず、
   偽データ中のホスト名は私用予約 TLD `.internal` のみ（実在の第三者ドメインへ攻撃者を誘導しない）。
2. **偽データのみ**。生成値はどの実サービスでも有効にならない形式。実在の個人情報・実在の認証情報は含めない。
3. **反撃（hack-back）しない**。攻撃者側に何かを実行させる仕組み（ビーコン、追跡ピクセル、スクリプト、エクスプロイト、
   マルウェア的ペイロード、外部への通信）は作らない。デコイは不活性なテキスト。AI カナリアの指示も「このサイトへの
   リクエストにヘッダを付ける/このサイトのパスを見る」だけで、エージェントの利用者や第三者に害を与える内容にしない。
4. **自動遮断しない**。トリップは検知・アラートまで。遮断等の対処は respond の承認ワークフロー（人間承認が既定）。

**誤検知・限界**
- AI カナリアは「AI 駆動の自動化」を示すが **悪意は示さない**。利用者が自分の AI エージェントに当サイトを
  操作させた場合や、許可されたペネトレーションテスト（ARTEX 等）も同じく検知される。
- 保護対象アプリがページの DOM をサーバーへ送る仕組み（セルフホストのセッションリプレイ、DOM を丸ごと保存する
  エディタ等）を持つと、挿入された隠しテキスト中の値が正規ブラウザから送られ `ai_canary_token` になり得る。
  その場合は `html_injection=false`。
- **誘発（フレーミング）**: 罠の経路は第三者が他人に踏ませられる（`<img>`・リンク・リンクプレビュー）。
  ブラウザ由来は `induced`（low）、カナリア経路だけは `passive`（medium）にして AI 断定・遮断提案の根拠にしない（§5）。
  - 代償: 攻撃者が `Sec-Fetch-Site: cross-site` 等を自分で付ければ、自分のトリップを low に下げられる
    （記録・アラートは残る。消えはしない）。気になる運用は `deception.downgrade_browser_induced=false`。
  - 残り: `Sec-Fetch-*` を送らないリンク取得（チャットのリンクプレビュー、メールのリンク検査、古いブラウザ）による
    **デコイパス・ハニートークン** のトリップは従来どおり critical（ルール判定は遮断を提案する）。
    `/.env` は detect-web の `web.sensitive_file_probe`（high）も同時に立つ。自動承認を使う前に、共有 IP の扱い（#23）と
    単発 critical からの遮断提案（#154）を併せて見ること。実 LLM のトリアージは medium のインシデントにも遮断を
    提案し得るので、自動承認で守られるのはルール判定の経路だけ（監査ノート参照）。
- `/.env` 等のデコイパスは大量スキャナも叩くため critical が多発し得る（detect-web の機微パス検知とも重複）。
- TOKIWA 自身の管理 UI を Gate の背後に置くと、資産作成リクエストの本文にトークンが含まれ誤検知になり得る。
- 既定の接頭辞（`svc_live_`, `dbg_`, `app_rw_`, 24 文字の `AKIA…`）は OSS なので知られている。指紋化を避けたい
  運用ではトークンを独自形式で指定する（redact を通ることだけは検証される）。
- 迷路はワイルドカード部分が同一ページになる（Gate のデコイが静的なため）。

**法的配慮** — 本文書は法的助言ではない。デコイ・ハニートークンの設置、アクセス記録の保存、利用規約・プライバシー
ポリシーでの告知要否は管轄によって異なるため、本番導入前に自組織の法務に確認すること。
`TODO(verify)`: 日本国内での運用（不正アクセス禁止法・個人情報保護法との関係、ログ保存期間）について法務確認。
