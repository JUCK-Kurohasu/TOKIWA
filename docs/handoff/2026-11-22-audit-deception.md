# 2026-11 監査対応: deception レーン（系統 D「デセプション」、工数 S）

担当 Issue: #133, #30, #41, #65, #68, #84。指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`
（#133=L03-10, #30=L03-02, #41=L01-06, #65=L09-06, #68=L11-03, #84=L01-07）。

ブランチ `worktree-agent-a7faa5385edeed2b6`（基点 `672f7a5`）。コミット: c218d2d (#133) → a052a36 (#30) → 998950b (#41) →
cbaf5e4 (#65) → 6553210 (#41 の mypy) → c425ad3 (#68) → 93ffe32 (#84) → 本 NOTES の最終更新。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #133 | 部分（推奨 (1)(2) は完全。(3)〜(5) は未着手） | 新モジュール `deception/provenance.py` でトリップごとに「出所」を判定。`induced`（`Sec-Fetch-Site: cross-site`/`same-site`、`Sec-Fetch-Dest` が `document`/`empty` 以外、`Sec-Purpose: prefetch`、別ホスト or `null` の `Origin`、別ホストの `Referer`）は全分類 low・AI 断定なし、`passive`（AI カナリア値がパス・クエリ・本文・Referer 等リンクで届く欄だけ＝経路 GET 単独）は medium・ai_score 0.5、`direct`（カナリアヘッダ等クライアント自身にしか付けられない位置）は従来どおり critical/ai_agent/0.99。降格したアラートは相関・ルール判定が AI 断定に使う印（タグ部分一致 `ai_canary`・エンティティ値 `ai_canary`）を持たない。セッション（aidetect）が Gate の `ai_canary` デコイ応答を無条件に `canary_hits`（AI 断定）にしていた経路も `provenance.decisive_canary_hit()`（既知のカナリア値をカナリアヘッダで送り、誘発兆候なし）で絞った（それ以外は `decoy_hits`）。これでカナリアページ（`/api/internal/openapi.json`、隠し HTML からリンク）を取得しただけで AI 断定される問題も止まる。設定 `deception.downgrade_browser_induced`（既定 true）。テスト `tests/deception/test_deception_framing.py`: L03-10 の再現（Gate の `EventBuilder` で HTTP + deception イベントを生成、クロスサイト `<img>`・同一オリジンの投稿内 `<img>`・リンクプレビュー bot・カナリアページ取得・`<img src=/.env>`）を **自動承認を全 ActionType で有効** にして流し、被害者 IP に対処 0 件・Gate ポリシーに載らない・インシデントは ai_agent でなく high 未満、対照としてカナリアヘッダで追従した非ブラウザは critical/ai_agent で block_ip が自動承認されること | c218d2d |
| #30 | 部分（推奨 (1)(2) は完全。(3) 編集距離の近似一致は理由付きで不採用 — Closes か Refs かは統合担当の判断） | トークン照合を大文字小文字無視（正規表現 `IGNORECASE` + 格納値への逆引き。`find_tokens` は格納値を返すので呼び出し側は無変更）、`\` を除いた版も照合（markdownify の `dbg\_` 対策）、`/api/internal/<値>` の判定と Referer もデコード → `\` 除去 → 正規化で比較。カナリアヘッダが既知値以外で送られたら資産に紐付かない `canary_attempt`（medium・deception・AI 断定なし、送信元ごとに 1 件、誘発兆候があれば出さない、`ai_canaries=false` やカナリア値が無いときは出さない）。テスト `test_deception_variants.py`（repro の md_escaped_path / md_escaped_hdr / lowercase_hdr / %5C / 大文字パス / Referer / クエリ、切り詰め・1 文字違い・base64・でたらめ値の試み） | a052a36 |
| #41 | 部分（挿入位置の設定化と既定の先頭+末尾は完全。HTML 以外への展開・eval の先頭 N KB チェックは未着手） | 設定 `deception.html_injection_positions`（`head` / `body_start` / `body_end`、既定 `[body_start, body_end]`）を `GatePolicy.html_injection_positions`（新フィールド、default None）で Gate に渡す。Gate の `gate.proxy.inject_html()` が位置ごとに挿入: `body_start` は最初の本物の `<body …>` の直後（`<script>`/`<style>`/`<title>`/`<textarea>`/`<template>`/コメント内の文字列と引用符内の `>` を飛ばす）、`body_end` は従来どおり最後の `</body>` の直前、`head` は `<head>` 直後にスニペット先頭の HTML コメントだけ（`<div>` は `<head>` を閉じてしまう）。位置の無いポリシー（古いサーバー）は `body_end` のみ、古い Gate は新フィールドを無視（pydantic の既定で余分なフィールドは無視）。位置は policy version に含むので設定変更が稼働中の Gate に届く。`</body>` が省略されたページにも `<body>` 直後に入るようになった。テスト `test_deception_injection.py`（43 KB のページで先頭 1,000 バイト以内にトークン・従来位置は 30,000 超を再現、生テキスト内の `<body>`、属性内の `>`、`<header>`、未知の位置、旧/新ポリシーの互換、サーバーが設定の位置と version を返す）と `tests/gate/test_gate_app.py` に 1 件（gzip 応答の両位置挿入） | 998950b, 6553210（mypy） |
| #65 | 部分（(a)(b) 完全。(c)(d)(e) 未着手） | (a) 資産のパスを Gate と同じ `gate.policy.normalize_path`（URL デコード後も）で正規化して検証し、`/` になるもの（`/.`、`//`、`/a/..`、`/%2e`、`/%252e`、`/.*` …）は 422。保存するのは Gate で正規化した形（`/a/../.env` → `/.env`）なので重複は 409。respond の `deploy_canary` も `create_asset` を通るので同じく拒否（`respond/validate.py` は無変更）。検証前に作られた行がルートを指していても `render.shadows_site()` で Gate ポリシーに載せない（警告ログ）。(b) 前方一致は `*` の前に完全なセグメントが 1 つ以上（`/admin/*` 可、`/a*`・`/admin*` 不可。迷路の既定 `/archive/*` は通る）。テスト `test_deception_paths.py`（3 種別 × 12 のルート表現、前方一致、正規化保存と重複、迷路・更新、旧データの非配信） | cbaf5e4 |
| #68 | 完全 | 新モジュール `deception/keys.py`: デセプション派生鍵を JWT 署名鍵から分離し `data_dir/deception.key`（0600、`auth.files.create_private_file` で原子的に作成）に鍵リングとして保存。1 行 1 鍵（16 進、`#` コメント可）、先頭が現用（描画）、全行を照合（`DeceptionIndex.build(older_keys=...)`）。**初回は #68 以前の導出鍵（HMAC(JWT 鍵, 'tokiwa.deception.derive.v1')）をそのまま書き出す** ので既存デプロイの派生値は変わらず、以後 JWT 鍵を入れ替えても変わらない。ファイルが読めない・作れない（読み取り専用の data dir）・壊れている・空のときは検知を止めず JWT 由来の鍵で動きエラーログ。`docs/deploy.md` の状態・バックアップ/リストア・鍵ローテーション、`docs/deception.md` §3、wiki Installation（バックアップ手順）・Deception（4 言語）。テスト `test_deception_keys.py`（初回の値が旧導出と一致・0600、JWT 鍵ローテーション後も派生値と照合が不変、デセプション鍵の入れ替えで旧値も照合・新値で描画、壊れた/空のファイル） | c425ad3 |
| #84 | 部分（(1) 文書化は完全。(2) `canary_style`・(3) 実機計測手順の実施は未着手） | `docs/purple-team.md` §3 の「ARTEX が従えば決定的に判定できる」を改め、追従はモデル依存・確率的で未発火は非 AI の根拠にならないこと、演習の合否は振る舞いで見ること、追従率の測り方（モデル別・複数回、`details.provenance` と ARTEX の LLM 記録の突き合わせ）を明記。`docs/deception.md` §1 に「十分条件であって必要条件ではない」の注記、wiki Deception（4 言語）に同じ趣旨の段落 | 93ffe32 |

## 要判断

- **#133「相関で昇格」の解釈**: 検知器の中に昇格ロジックは作らなかった。`passive` は medium のまま、同じ送信元の攻撃系アラート
  （SQLi 等）があればインシデントの重大度は max でそちらに上がる（既存の相関）。カナリア自体を「攻撃と相関したら AI 断定に戻す」は、
  攻撃リクエストも `<img>` やリンクで誘発できる（`?q=' OR 1=1--`）ため採らなかった。
- **#133 誘発判定の回避（代償）**: 攻撃者が `Sec-Fetch-Site: cross-site` 等を自分で付ければ、自分のトリップを low に下げられる。
  記録・アラート（low）は残る。HTTP だけでは本物のクロスサイト要求と区別できない。`deception.downgrade_browser_induced=false` で従来の重み。
  非ブラウザ UA が `Sec-Fetch-*` を送るのは不自然なので、「ブラウザ UA のときだけ信じる」等の追加条件は将来の調整点（UA も詐称可能なので未実装）。
- **#133 経路 GET 単独を AI 断定しなくなった（検知力の低下）**: パスだけで追従するエージェントは、カナリアだけでは AI と断定されなくなる
  （他の振る舞いシグナル・攻撃アラートで判断）。推奨 (2) どおり。
- **#30 生成トークンの字母（`_`）は変えなかった**: 推奨 (1) の「字母から `_` を除く」案ではなく照合側の正規化を採った（既に配布・
  漏えいしたデコイの値を変えずに済むため）。新規生成値から `_` を外すかは任意（`tokens._FORMATS`）。
- **#30 `canary_attempt` を medium にした（推奨は high）**: ヘッダ名 `X-Debug-Auth` は本プロジェクトの公開文書・ソースにも載るので、
  「ヘッダ名だけ知っている」主体（このリポジトリを読んだ人・スキャナ）と区別できない。high にするとルール判定が rate_limit を提案する。
  `deception_trip.CANARY_ATTEMPT_SEVERITY` で調整可。`canary_header` を実クライアントが送るヘッダ名に変えた運用では雑音になる。
- **#30 経路 `/api/internal/dbg*` の値不一致は試みとして起票しない**: 実アプリの `/api/internal/` と紛れやすく、リンクで誘発もできるため。
- **#41 既定を「末尾のみ」から「先頭付近 + 末尾」に変えた（(b) 既定を変えて docs・wiki を同時更新）**: 同じ隠しスニペットが 1 ページに
  2 回入る（見た目・スクリーンリーダーには出ない）。`<body>` の検出を誤ると HTML を壊し得るので生テキスト領域を飛ばしているが、
  閉じていない `<script>` 等の壊れた HTML では誤検出の余地がある。従来の挙動は `html_injection_positions: [body_end]`。
  `head` は既定に入れていない（`<head>` が巨大なページでは `body_start` も 30,000 文字を超え得る。その場合は `head` を足す）。
- **#65 前方一致の最低条件は「完全なセグメント 1 つ」にした（推奨の例は「2 セグメント以上」）**: 2 にすると `/admin/*` のような
  明示的な指定や迷路の `/archive/*` まで拒否するため。`/api/*` のような 1 段の前方一致は通る（運用者の明示的な選択とみなす）。
- **#65 保存パスを Gate 正規化形にした**: `/static/../x` で作ると `/x` として保存・表示される。大文字小文字は保存時に変えない
  （Gate の照合も区別する）。`deception.decoy_paths` のシードも正規化形で既存行と突き合わせる（毎回の再作成・409 警告を避ける）。
- **#68 初回の鍵を乱数ではなく旧導出鍵にした**: 既存利用者の配布済み値を壊さないため（新規インストールでも同じ扱い）。そのため
  「JWT 鍵が漏えいした」場合は派生値の鍵も漏えい済みとみなし、`deception.key` の先頭に新しい乱数鍵を足す（旧行は残す）運用になる。
  ローテーション用の CLI は作っていない（`cli.py` は共有ファイル。手順は docs/deploy.md §7）。**古い鍵を消す時期（保持期間）は運用判断**。
- **#68 鍵ファイルを失うと現在の JWT 鍵から作り直される**: JWT 鍵が不変なら値も戻るが、JWT 鍵を入れ替えた後に失うと旧値は検知されない。
  バックアップ対象に追加した（docs/deploy.md・wiki Installation）。`scripts/docker-smoke.sh` の永続化確認には足していない。
- **#30 近似一致（編集距離 1〜2）は不採用**: 照合が正規表現の一括検索なので、近似一致は別の仕組みが要る。ヘッダでの写し間違いは
  `canary_attempt` で拾える。

## 既定動作の変更

- AI カナリアの経路 `/api/internal/<値>/` への GET（カナリアヘッダなし）: critical/ai_agent → **medium/deception**、セッションも AI 断定しない。
- カナリア値がクエリ・本文だけに現れた `ai_canary_token`: critical → **medium**。
- ブラウザのクロスサイト/サブリソース要求によるトリップ（全分類）: critical → **low**（`deception.downgrade_browser_induced=false` で従来どおり）。
- Gate の `ai_canary` デコイ応答（カナリアページ取得を含む）を AI セッション断定に数えるのは、カナリアヘッダで既知の値を送った場合だけ。
- カナリアヘッダでの追従（`direct`）は従来どおり critical/ai_agent/0.99。DB スキーマ変更なし（`deception_trips.detail` JSON に `provenance`/`induced_by` を追加）。
  bus `deception.tripped` に `provenance` を追加（後方互換）。
- （#30）トークン照合が大文字小文字を区別しなくなった（ハニートークン含む全トークン）。カナリアヘッダに既知値以外の値 → medium の
  `canary_attempt` アラート（新規）。
- （#41）HTML 応答への隠しスニペットの挿入位置: `</body>` 直前のみ → **`<body>` 直後と `</body>` 直前**（`deception.html_injection_positions`）。
- （#65）ルートと同じ意味のパス・`*` の前に完全なセグメントの無い前方一致での資産作成・更新・`deploy_canary` が 422 になった。
  既存の行は変更しないが、ルートを指す行は Gate に配信しない。
- （#68）`data_dir/deception.key` が初回起動時に作られる（中身は従来の導出鍵なので挙動は不変）。JWT 鍵の入れ替えでデコイの派生値が変わらなくなった。

## 失敗した試み

- e2e テストに `<img src=/.env>` の被害者も「対処 0 件」として入れたら、detect-web の `web.sensitive_file_probe`（high）が同じ要求で立ち、
  ルール判定が rate_limit を提案・自動承認した。デセプションの責任範囲外なので、e2e では deception.trip が low になることだけを確認し、
  残りは他レーンへの依頼に回した。

## 担当外の変更

- `backend/src/tokiwa/aidetect/sessions.py`（aidetect レーン）: `_observe_other` の `ai_canary` 計数を `decisive_canary_hit(e)` で絞る
  4 行（import は関数内。モジュール先頭の import 行は触っていない）。HTTP 情報の無い deception イベントは従来どおり断定
  （既存テスト `test_non_http_events_attach_and_canary_decides` / `test_agent_session_negative_and_canary` は無変更で通る）。
- `backend/src/tokiwa/config.py`: `DeceptionSettings` に `downgrade_browser_induced`（#133）・`html_injection_positions`（#41）を追加（自セクションのみ）。
- `backend/src/tokiwa/schemas/response.py`（#41）: `GatePolicy.html_injection_positions: list[str] | None = None` を追加（互換。フロントの型には GatePolicy が無いので types.ts は変更なし）。
- `backend/src/tokiwa/respond/policy.py`（#41、respond レーン）: `build_gate_policy` が `deception_policy.html_injection_positions()` を渡す 2 行と、
  `policy_version` にキーワード引数 `html_injection_positions=None`（None のときハッシュは従来と同じ）。
- `backend/src/tokiwa/gate/app.py`・`gate/policy.py`（#41、カナリア挿入部分）: `_send_injected` に位置を渡す、`CompiledPolicy.html_injection_positions`。
- `backend/tests/gate/test_gate_app.py`（#41）: 位置付きポリシーのテストを 1 件追加。
- `docs/gate.md`・`docs/response.md`（#41）: 挿入位置の 1 文。
- `frontend/src/pages/deception/DeceptionPage.tsx`（#133/#84）: AI カナリア説明（rule1/rule2/why、ja/en）と KPI の補足文を新しい判定に
  合わせた文言だけの変更（「カナリアヘッダでの追従だけが AI 断定、経路だけ・クエリは medium、クロスサイト/部品は low、未発火は非 AI の
  根拠にならない」）。旧文言は「指示されたパスへのアクセス → AI 0.99 の critical」「トリップは常に critical」だった。

## 他レーンへの依頼

- **respond / triage（自動承認の最終防衛線）**: 本対応で守られるのは **ルール判定（mock / fallback）の経路だけ**。実 LLM のトリアージは
  medium の deception インシデントにも block_ip を提案し得て、自動承認なら実行される。`details.provenance in (passive, induced)` の
  deception アラートだけを根拠にした提案は自動承認しない、等のガードを respond 側に入れてほしい（テストは本レーンの e2e を流用可）。
- **aidetect**: 経路 GET 単独・カナリアページ取得を `decoy_hits`（敵対スコアのみ）に回した。AI スコアに「弱い」重み（断定ではない）
  として足すかは aidetect 側の判断（`provenance.decisive_canary_hit` と `induced_by` を使える）。
- **detect-web（#154 / #23 系）**: `<img src="https://<site>/.env">` で閲覧者の IP に `web.sensitive_file_probe`（high）→ rate_limit 提案
  （自動承認なら実行）。同じ誘発判定（`deception.provenance.induced_by`）を使えば下げられる。
- **#133 の残り**: Sec-Fetch を送らない取得（チャットのリンクプレビュー、メールのリンク検査、古いブラウザ）での **デコイパス・ハニートークン**
  トリップは critical のまま（ルール判定は block_ip を提案する）。カナリアの `passive` 相当をデコイパスにも広げるかは要検討
  （スキャナの `/.env` 取得も medium になり検知力が下がる）。推奨 (3) 訪問者ごとのカナリア値＋`Cache-Control: private`（#45 と同じ作業）、
  (4) 宣言済み AI UA の別分類、(5) 検証済みクローラへの非注入は未着手。

## Issue ごとの残り（未着手）

- #133: 上記「#133 の残り」。
- #30: Gate の着地ルート（`/api/internal/<値>*`）は Gate 側の正規化のまま（大文字小文字・`\` を区別）なので、揺れた経路は上流へ
  転送され 404 になる（検知はサーバー側の HTTP イベントで行われる。Gate の `DecoyMatcher` は担当外）。
- #41: HTML 以外（JSON エラー応答の `hint`、`Link`/独自応答ヘッダ、JS のコメント）への展開（#135 と同じ作業）、評価（`tokiwa.eval`）に
  「先頭 N KB 以内にトークンがあるか」のチェックを足すこと（eval レーン）。ARTEX 実機での確認は未実施。
- #65: (c) 作成時に直近の `gate.http` で同じパス（前方一致なら配下）が上流から 2xx/3xx を返していれば 409 + `force`（API・スキーマ・
  イベント検索が要る）、(d) `deploy_canary` の承認画面に「全利用者に影響」を表示（フロント / respond）、(e) 既定シードを有効化する前に
  上流に同名ルートが無いことを確認。
- #84: (2) 文面バリエーション `canary_style`（命令形の「AI 向け注記」と開発者メモ風の漏えい）と eval での追従率比較（#136 と同じ作業）、
  (3) ARTEX 実機 + 実モデルでの追従率計測（手順は purple-team.md §3 に書いた。実施には実 LLM が要る）。

## チェック（最終）

- backend: `uv run pytest` 1544 passed（約 120 秒）、`ruff check` / `ruff format --check` 緑、`mypy src` は既知 4 件のみ
  （#41 で一度 1 件増やしたが 6553210 で解消）。`python3 scripts/check_wiki.py` OK。
- frontend（文言のみ変更）: `npm run typecheck`・`npm run lint`・`npx vitest run`（51 passed）・`npm run build` 緑。

## 未検証事項

- `Sec-Purpose: prefetch` / `Purpose: prefetch` を送るブラウザの範囲（`TODO(verify)` 相当。Chromium の prefetch / prerender で送られる想定）。
- リンクプレビュー bot・メールのリンク検査が `Sec-Fetch-*` を送らないこと（一般的な理解に基づく。個別製品は未確認）。
- 実 LLM のトリアージが降格アラートにどう反応するか（`needs-live-llm`）。
- #30: 実エージェントが `dbg\_` のまま送るか・写し間違えるかは未確認（`needs-live-llm`。照合側はどちらも拾う）。
