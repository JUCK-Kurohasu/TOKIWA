# 2026-11 監査対応: gate-capture レーン（系統 A「Gate」、工数 S）

担当 Issue（この順）: #140, #141, #138 + #147 + #149, #54, #146 + #148, #99, #143。指摘の詳細は
`docs/audit/2026-11/findings/*.jsonl`（#140=L06-09, #141=L06-10, #138=L06-06, #147=L06-07, #149=L06-14, #54=L06-03,
#146=L03-07, #148=L06-12, #99=L09-05, #143=L06-13）。

ブランチ `worktree-agent-ac5a31bda64077d5d`（基点 `95343eb`）。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| （未登録・high 相当）Gate の共有 httpx クッキージャー | 完全 | 上流・サーバー用の httpx クライアントに「何も保存しない」ポリシーの `CookieJar` を渡す。テスト `tests/gate/test_gate_upstream_headers.py`（A の Set-Cookie が B の要求に付かない・ジャーが空のまま・クライアント自身の Cookie はそのまま転送） | 6326b7e |
| #140 | 部分（推奨 (1)(3)(4) と「truncated 印・ヘッダ数」は完全。(2) の web_recon で「異常なヘッダ数」を medium シグナルにする部分は web-detect レーンへ依頼） | `gate.capture.capture_headers()` を作り直し: `PRIORITY_HEADERS`（UA・Referer・Host・Origin・Cookie・Content-*・Accept-*・`Sec-Fetch-*`・Client Hints・送信元 IP 系・ルーティング上書き・`web_common.INJECTABLE_HEADERS` 全部）とデセプションのカナリアヘッダ（`deception.canary_header`）は位置に関係なく必ず残し、残りの枠（合計 64 名 = `web_common.MAX_HEADERS`）を到着順に使う。辞書は到着順のままなので Web 検知器の `[:64]` で全部見える。超過は `gate:headers_truncated` + label `gate.header_count`（受信行数）/`gate.headers_dropped`。同名ヘッダの連結は 8192 文字で打ち切り（`gate.headers_clipped`）、`header_order` は同じ名前 2 回まで。リストでないヘッダ（Host・Content-Length・UA・`Sec-Fetch-*` 等）の重複は `gate:duplicate_header` + `gate.duplicate_headers`。推奨 (3): `gate.max_request_headers`（既定 100、0 で無効）を超えるヘッダ行の要求は転送せず 431（`gate:too_many_headers`。デコイ・deceive の判定より後＝ローカル応答はそのまま）。テスト `tests/gate/test_gate_header_capture.py`（ダミー 70 個の後ろの UA・Referer の SQLi・`Sec-Fetch-*`・Origin・カナリアヘッダ・X-Api-Version が残る、DB 往復後も `induced_by()` が理由を返す、`decisive_canary_hit()` が効く、`web_common.build_view()` が Referer の UNION SELECT を見る、`INJECTABLE_HEADERS ⊆ PRIORITY_HEADERS` のドリフト検査、重複・連結上限、431 と無効化、設定したカナリアヘッダ名の優先） | 8e3392f |
| #141 | 部分（推奨 (1) は完全、(2) の「展開不能を印にする」まで完全・web_recon でのシグナル化は web-detect レーンへ依頼、(3) 運用文書は完全） | `gate.capture.decode_request_body()`: `Content-Encoding` が gzip / x-gzip / deflate（zlib 形式と raw の両方、2 段まで、gzip の複数メンバーも）なら **捕捉した先頭だけ** を展開し、出力も `capture_body_bytes` で打ち切る（圧縮爆弾でも仕事量・メモリは捕捉上限まで。zlib の `max_length=0`＝無制限は捕捉 0 のとき展開しないことで回避）。展開した本文を `request_body` に入れ（テキスト判定・UTF-8 復号も展開後のバイト列で）、`gate:req_encoded` + `gate.request_encoding` / `gate.request_body_decoded_bytes`。br・zstd・3 段以上は `gate:req_encoding_unknown`（本文は記録しない）、壊れた gzip/deflate は `gate:req_decode_failed`。`request_body_size` は転送路上のサイズのまま、上流へは元の圧縮バイト列を送る（変えない）。docs/gate.md §3・§8（上流が展開するかを確認する項目）、wiki Sensors（4 言語）。テスト `tests/gate/test_gate_request_encoding.py`（各符号化・積み重ね・未知・破損・空、2 つ目の gzip メンバーに隠した本文、20 MB の圧縮爆弾が 4096 バイトで止まる、圧縮の途中で切れた先頭、イベントの印と `web_common.build_view()` が展開後の `password` パラメータに UNION SELECT を見る、Gate 経由で上流に圧縮のまま届く） | 2adbb4f |
| #138 | 完全（推奨 (1)〜(5)） | `gate.proxy.STRIPPED_CLIENT_HEADERS`（`Forwarded`・`X-Real-IP`・`True-Client-IP`・`CF-Connecting-IP`・`X-Client-IP`・`X-Cluster-Client-IP`・`Fastly-Client-IP`・`X-Originating-IP`・`Client-IP`・`X-Original-Forwarded-For`・`X-Forwarded-Port/Prefix/Server/Scheme/Ssl`・`Front-End-Https`・`X-Url-Scheme`）を上流へ渡さない。Gate が `X-Real-IP: <送信元 IP>` と 1 要素の `Forwarded: for=<送信元 IP>;proto=...;host=...` を付ける（送信元 IP は Gate がイベントに使う値＝信頼時は XFF の右端。IPv6 は `"[...]"`、host は token でなければ quoted-string でエスケープ）。(3) は「XFF と同じ信頼ルール」を **XFF のチェーンから組み立てる** 形では採らず、Gate の判定値 1 要素にした（左側はクライアントが書けるので `1.2.3.4;proto=https` で `Forwarded` に引数を足せる — 統合前の助言で変更）。**既存の X-Forwarded-For/Proto/Host の処理（trust_forwarded_for を含む）はバイト単位で不変**（既存テストもそのまま通る）。除去したヘッダ名は `gate:client_ip_header` + `gate.stripped_headers`（名前は固定語彙のみ）、値は #140 の優先ヘッダとしてイベントに残る（`STRIPPED_CLIENT_HEADERS ⊆ PRIORITY_HEADERS` をテスト）。前段の信頼できるプロキシが付けるヘッダ用に `gate.forward_client_headers`（既定 `[]`）。docs/gate.md §6 の「上流に IP を偽装させない」を正確化 | （このコミット） |
| #147 | 完全（推奨 (1)(2)。(3) の web_recon ルールは web-detect レーンへ依頼） | `X-Original-URL`・`X-Rewrite-URL`・`X-Override-URL` も上流へ渡さない（`forward_client_headers` で許可可）。値のパスをデコイ照合にかけ、一致すればデコイを返す（上流には転送しない、DECEPTION イベントも出る）。タグ `gate:route_override` | （このコミット） |
| #149 | 完全 | `build_request` の後、Gate が渡したヘッダ一覧に無い名前を `request.headers` から削除（Host・Content-Length・Transfer-Encoding・Connection だけは httpx に任せる）。httpx の既定 `User-Agent: python-httpx`・`Accept: */*`・`Accept-Encoding` が上流に届かない。上の未登録の指摘（クッキージャー）もこの規則で二重に防がれる。テスト: 生の ASGI scope（httpx クライアントだと自分の既定ヘッダを付けてしまう）で Host だけの要求が上流で UA/Accept/Accept-Encoding/Cookie なし、クライアントが送った UA・Accept はそのまま | 1a96ae4 |
| #54 | 部分（推奨 (1)(2)(3) は完全。overlong UTF-8 は印のみ、(4) 上流タイプ別の正規化プロファイルは未着手） | `gate.policy.normalize_path` は **変えず**（サーバー側の検証・保存・`shadows_site` が使う。大文字小文字を保つ）、その上に照合キー `match_key()` を追加し `DecoyMatcher.build`（完全一致・前方一致の両方）と `match` に対称にかける: 2 回目のパーセントデコード、`\`→`/`、各セグメントの NUL・`;` 以降を除去（`..;` は `..` に）、ドットセグメント解決 **の後** に末尾ドット・空白と `::$DATA` を除去、小文字化、末尾 `/` なし。前方一致は `key + "/"` で比べるので `/admin` も `/admin/*` に当たる（`/administrator` は当たらない）。照合キーが `/` になる完全一致ルート（`/;x`・`/%2e`・`/ `）も拒否（サーバーの #65 の検証は `normalize_path` なので通ってしまう）。`gate:path_anomaly` + `gate.path_anomaly`（nul / semicolon / backslash / double_encoding / invalid_utf8 / trailing_dot_or_space / ntfs_stream）を全要求に。テスト `tests/gate/test_gate_decoy_variants.py`（L06-03 の再現ターゲット 20 種がデコイに当たる、`.env.bak` 等は当たらない、ルート化するルートの拒否、`normalize_path` 不変、Gate 経由で `/.env;x` がデコイ応答・上流に届かない・path は送ったまま記録） | 3e61719 |
| #146 | 完全 | `gate.proxy.document_charset()`: UTF-8 BOM → `Content-Type` の charset → 先頭 1024 バイト内の `<meta charset>` / `http-equiv` の順で文字コードを決め（meta の UTF-16 は WHATWG どおり UTF-8、BOM なしの utf-16/32 コーデックは BOM を書かない LE に）、決まらない・未知の名前なら **ASCII のみ**（非 ASCII は `&#NNNN;`）でスニペットを符号化。`encode_snippet(snippet, content_type, html)` に展開後の HTML を渡す。テスト: `test_gate_proxy.py`（meta・http-equiv・BOM・1024 バイト超・未知名・ヘッダ優先）、`test_gate_app.py::test_html_injection_follows_meta_charset`（ヘッダ `text/html` + `<meta charset="Shift_JIS">` の上流ページで日本語の注記が Shift_JIS で正しく読める） | （このコミット） |
| #148 | 完全（Vary / CDN-Cache-Control は付けない — 要判断） | Gate 生成の応答（`_respond`: 403/429/431/501・deceive の汎用 404・デコイ・502/504）すべてに `Cache-Control: no-store`。デコイ自身が `Cache-Control` を持つときはそれを使い二重にしない。docs/gate.md・wiki Sensors（4 言語）に CDN 配下での注意。テスト: 汎用 404・502/504 に `no-store` が 1 つ、デコイ指定の値が優先 | （このコミット） |

## 未登録の指摘（このレーンで発見）

- **Gate の上流クライアント（共有 `httpx.AsyncClient`）が上流の `Set-Cookie` をクッキージャーに保存し、`Cookie` を送らない
  別のクライアントの要求に付けて上流へ送っていた**（セッションの横取り）。再現: 利用者 A が `/login` で `Set-Cookie: session=...`
  を受けた後、Cookie なしの利用者 B（別 IP）の要求が上流に `Cookie: session=<A の値>` 付きで届く。httpx はレスポンスごとに
  `client.cookies.extract_cookies()` し、`build_request` で `Cookie` ヘッダが無い要求にジャーの値を足すため。
  Issue 化はしていない（GitHub には書き込まない約束）。統合担当が Issue にするか判断する。

## 要判断

- **#140 `gate.max_request_headers` の既定を 100 にした**（(b) 既定を変え docs・wiki を同時更新）。Apache httpd の
  `LimitRequestFields` の既定と同じ値。ヘッダ行が 100 を超える正規の要求はまれだが、0 にすれば従来どおり無制限に転送する。
  65〜100 行の要求は転送され、64 名を超えた分の任意ヘッダ（優先リスト外の名前に載せた Log4Shell 等）はイベントに残らない
  （`gate:headers_truncated` とヘッダ数だけ残る）。64 にすれば穴は無くなるが、正規の要求を落とす可能性が上がるので 100 にした。
- **#140 カナリアヘッダ名は Gate プロセスの設定（`deception.canary_header`、既定 `X-Debug-Auth`）から取る**。サーバーと
  別ホストで Gate を動かし、サーバー側だけでヘッダ名を変えた場合は優先されない（64 名以内なら従来どおり残る）。ポリシー
  （`GatePolicy`）にヘッダ名を載せれば確実になるが、`schemas/response.py` とサーバー側の描画（他レーン）に触るので見送った。
- **#138/#147 送信元 IP 系・ルーティング上書きヘッダを既定で除去にした**（(b) 既定を変え docs・wiki を同時更新。セキュリティ側の既定）。
  **Cloudflare 等の背後で上流が `CF-Connecting-IP` / `True-Client-IP` を読んでいる構成は、更新後に上流から見た送信元が
  変わる**（`X-Real-IP` / `Forwarded` を読む上流は Gate の値＝今までどおりの送信元になる）。その場合は
  `gate.forward_client_headers: ["cf-connecting-ip"]` が必要。ラボ（lab/）はこれらのヘッダに依存していない（grep で確認）。
- **#138 Gate が `X-Real-IP` と `Forwarded` を新たに付ける**。上流が `Forwarded` を優先して読む（Spring の
  `forward-headers-strategy=framework` 等）場合、`host=` と `proto=` も効く。値は `X-Forwarded-Host` / `X-Forwarded-Proto` と同じ右端の値。
- **#147 ルーティング上書きの値がデコイに一致したらデコイを返す**: 上流が実際にはこのヘッダを解釈しない構成でも、要求行の
  パス（例 `/static/app.js`）に対してデコイ（例 `.env`）が返る。正規のクライアントはこのヘッダを送らない前提。
- **#54 デコイ照合を既定で大文字小文字無視にした（オプションなし）**: 大文字小文字を区別する上流（Linux）では `/.ENV` は別の
  リソース（多くは 404）だが、それを要求すること自体が探索なのでデコイを返す。デコイと大文字小文字だけ違う **実在の** パスが
  あると、その実在パスもデコイになる（まれと判断。必要ならポリシーに区別フラグを足す）。末尾 `/` の同一視で `/admin/*` は
  `/admin` にも当たるようになった。
- **#54 overlong UTF-8（`%c0%ae`）は `.` として扱わない**: 現行の ASGI サーバーは U+FFFD に置き換えるため元のバイト列が残らない。
  `gate:path_anomaly`（`invalid_utf8`）の印だけ付ける。古い IIS 等、overlong を解釈する上流の背後では迂回できる。
- **#146 文字コードが決まらないページへの注入を UTF-8 から ASCII（数値文字参照）に変えた**: ヘッダにも `<meta>` にも charset が
  無いページでは日本語の注記が `&#NNNN;` になる。ブラウザ表示（隠し要素なので見えない）と生 HTML を読む AI のどちらでも元の文字として
  解釈されるが、`head` 位置の HTML コメント内では文字参照は展開されない（生 HTML を読む AI には読める想定）。未知の charset 名
  （例 `charset=bogus`）も同じ扱い（以前は UTF-8）。
- **#148 `Vary: *` / `CDN-Cache-Control` / `Surrogate-Control` は付けなかった**: `no-store` は RFC 9111 で共有キャッシュも保存しては
  ならない指示。CDN 固有ヘッダは本物の応答との差（デコイの見破り材料）を増やすので見送り。CDN 側で 404 を強制キャッシュする設定が
  あれば効かない（docs に注意書き）。また deceive の汎用 404 に付く `no-store` は、別 IP から見た本物の 404 との小さな差になる。

## 既定動作の変更

- （#140）イベントの `http.headers` は「先頭 64 行」から「検知用ヘッダ + 到着順の残り、合計 64 名まで」に。`header_order` は
  同じ名前を 2 回までしか並べない（以前は先頭 64 行の全部）。同名ヘッダの連結は 8192 文字まで。
- （#140）ヘッダ行が 100 を超える要求は上流へ転送せず 431。
- （#141）gzip / deflate の要求ボディはイベントに展開後のテキストで載る（以前は圧縮バイト列＝バイナリ扱いで本文なし）。
  br 等の未対応符号化の本文は、以前は内容で判定していたが、今は記録しない（圧縮バイト列はテキストにならないため実質同じ）。
- （#138）上流へ `Forwarded`・`X-Real-IP`・`True-Client-IP`・`CF-Connecting-IP` 等と `X-Forwarded-Port/Prefix/Server/Scheme/Ssl`・
  `Front-End-Https`・`X-Url-Scheme` を渡さない。Gate が `X-Real-IP` と `Forwarded` を付ける。`gate.forward_client_headers` で従来どおり渡せる。
- （#147）`X-Original-URL`・`X-Rewrite-URL`・`X-Override-URL` を上流へ渡さない。値がデコイに一致すればデコイを返す。
- （#149）クライアントが送らない `User-Agent`・`Accept`・`Accept-Encoding` を上流へ付けない（以前は httpx の既定値が付いた）。
- （#54）デコイ照合が大文字小文字・末尾 `/`・`;` 以降・末尾ドット/空白・`\`・二重エンコード・`::$DATA` を区別しない。
  照合キーがルートになる完全一致ルートは Gate が拒否（WARN）。`gate:path_anomaly` タグが新たに付く。
- （#146）charset がヘッダに無いページは `<meta>` の文字コードで注入、決まらなければ ASCII（数値文字参照）。以前は常に UTF-8。
- （#148）Gate 生成の全応答に `Cache-Control: no-store`（以前は 403/429/501 だけ）。

## 失敗した試み

## 担当外の変更

- `docs/wiki/Data-Handling*.md`（4 言語）: Gate が集める項目の「リクエストヘッダ（先頭 64 個）」「65 個目以降のヘッダ」の記述を
  #140 の挙動に合わせて 1 行ずつ修正。

## 他レーンへの依頼

- **web-detect**: `gate:headers_truncated` / label `gate.header_count`（受信したヘッダ行数）、`gate:duplicate_header`
  （`gate.duplicate_headers`）を web_recon の「異常なヘッダ数・重複ヘッダ」シグナル（#140 推奨 (2)。例: 40 行超で medium）に。
- **web-detect**: `gate:req_encoding_unknown` / `gate:req_decode_failed`（#141 推奨 (2)）を web_recon の low〜medium シグナルに。
  展開済みの本文は `request_body` に入るので、既存の本文検査はそのまま効く（web_common は無変更）。
- **web-detect**: `http.headers` の `x-original-url` / `x-rewrite-url` / `x-override-url` の値を path ベースの検知
  （sensitive_file_probe 等）にもかける、`gate:route_override` / `gate:client_ip_header` を web_recon のシグナルに（#147 推奨 (3)、#138 推奨 (4)）。
  `web_common.INJECTABLE_HEADERS` に `cf-connecting-ip`・`x-cluster-client-ip`・`fastly-client-ip` が無い（Gate は全部イベントに残す）。
- **deception**: サーバー側の資産パス検証（`service._gate_safe_path` / `render.shadows_site`）を `gate.policy.match_key()` でも
  判定する（`/;x`・`/ ` 等は Gate の照合ではルートになり、Gate が拒否して WARN を出す）。`docs/deception.md` §6 の
  「デコイ照合」の記述に #54 の正規化（大文字小文字無視など）を反映。

## 未検証事項

- （#141）上流製品が要求ボディをどの符号化まで展開するか（Express body-parser の版ごとの br 対応、ASP.NET Core の
  RequestDecompression の既定）は一次資料で確かめていない。docs/gate.md に `TODO(verify)` を残した。
