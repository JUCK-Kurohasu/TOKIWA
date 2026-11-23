# Web 攻撃検知カタログ（detect-web / FR-05）

`backend/src/tokiwa/detect/detectors/web_*.py` の組み込み検知器 17 個。すべて `EventKind.HTTP` のみを対象とし、
`@register_detector` で自動登録される。共通処理は `backend/src/tokiwa/detect/web_common.py`。

AI エージェントも最終的にはこれらのペイロードを使うため、ここでのアラートは detect-ai（`ai.*`）の
アトリビューションの入力にもなる。AI らしさの判定（ai_score）はここでは行わない。

## 1. 共通の仕組み

### 1.1 正規化（イベントごとに 1 回、`ctx.scratch` にキャッシュ）

| ビュー | 内容 | 主な用途 |
|---|---|---|
| `raw` | 未デコード・小文字 | エンコードされた回避（`%2e%2e%2f`, `%c0%ae`）そのものの検出 |
| `decoded` | 多段デコード済み・大小文字保持 | 大小文字が意味を持つマーカー（`rO0AB`, `AAEAAAD/////`, PHP `O:8:"..."`） |
| `lower` | `decoded` + NFKC + 小文字、空白は保持 | 改行区切りが重要なコマンド注入、パス |
| `norm` | `lower` + SQL コメント除去 + 空白を 1 個に圧縮 | SQLi / XSS / SSTI |
| `value` | `name=value` の value 部分のみ（`lower` 相当） | SSRF / RFI（値が URL かどうか） |

デコードは最大 8 ラウンド（`detection.web.max_decode_rounds`。以前は 3 で、4 重 URL エンコードが素通りした #89）で安定するまで
繰り返す: `%XX`（多重エンコード、`%%32%65` のような入れ子）、`%uXXXX`、
overlong UTF-8（`%c0%ae` `%c0%af` `%c1%9c` `%e0%80%ae`）、`+`→空白（フォーム文脈の 1 ラウンド目のみ）、
HTML エンティティ、`\uXXXX` / `\xXX`。SQL の `/**/` は空白に、MySQL の `/*!50000 ... */` は中身を残す。全角文字は NFKC で ASCII に寄せる。
UTF-8 として不正な単独バイト（`%A0` 等）は U+FFFD ではなく Latin-1 の文字にする（`%A0` → U+00A0 → NFKC で空白。MySQL は 0xA0 を空白扱い）。

追加のターゲット（#89）:

- **base64**: `query` / `body` / `cookie` / `header_custom` の値が base64 / base64url（16 文字以上）で、デコード結果が UTF-8 かつ 95% 以上
  表示可能な文字なら、デコード結果も `param=<名前>(base64)` として検査する（1 要求 8 個まで）。トークン・ハッシュ・ID・バイナリは
  デコードするとテキストにならないので対象外。
- **パラメータ汚染（HPP）**: 同名パラメータが 2 回以上あれば、値を `,` で連結した `param=<名前>(joined)` も検査する（ASP.NET の挙動。
  他のフレームワークの先勝ち / 後勝ちは個別の値で検査済み。`TODO(verify)`）。1 location あたり 4 個まで。
- **UTF-16 のボディ**: センサーが UTF-8 として復号したため 1 文字おきに NUL が入ったボディ（multipart 以外）は、交互パターンを確かめてから
  NUL を除いて検査する（Jackson 等は UTF-16 の JSON を自動判定して受け付ける）。ゼロ埋めのバイナリは対象外。非 ASCII 文字はセンサー側で失われている。
- セミコロンなしの数値文字参照（`&#x3c`）は従来から展開している。監査の行列で取りこぼしに見えたのは、直後の文字が 16 進数字
  （`&#x3dalert` → U+03DA + `lert`）の場合で、HTML の仕様どおり貪欲に読むとブラウザでもペイロードが壊れる形だった（ブラウザでの確認は `TODO(verify)`）。

### 1.2 検査対象（location）

| location | 内容 |
|---|---|
| `path` | パス（クエリなし。`path` に `?` が含まれ `query` が空なら分割する） |
| `query` | クエリのパラメータごと（`name=value`、`param` に名前） |
| `body` | フォーム / JSON の文字列リーフ（`param` は `a.b[0]`）/ JSON のキー（全キーを 1 つにまとめた `param=(json keys)`）/ multipart パート。構造化できなければボディ全体 |
| `body_raw` | ボディ全体（構造化できた場合のみ追加。XXE・デシリアライズ・RSC 用） |
| `header` | 反射・記録されやすいヘッダ（User-Agent, Referer, Origin, X-Forwarded-For 系, Forwarded, X-Api-Version ...） |
| `header_custom` | アプリ固有のヘッダ（X-Tenant-Id, X-User-Id, X-Request-Id ... = `header` にも `header_other` にも当たらないもの）。SQLi / XSS / トラバーサル / コマンド注入 / LFI も検査する（#53。`detection.web.inspect_custom_headers=false` で従来どおり対象外） |
| `header_other` | フレーミング系のヘッダ（Accept*, Sec-Fetch-* / Sec-CH-*, If-*, Cache-Control, Content-Type, traceparent / tracestate / baggage, X-Requested-With ...。一覧は `web_common.FRAMING_HEADERS`、追加は `detection.web.extra_framing_headers`）。Log4Shell / OGNL / Shellshock / SSTI / デシリアライズ / クラウドメタデータだけが見る。Authorization 等は検査しない |
| `cookie` | Cookie のペアごと（名前も検査対象） |
| `filename` | multipart のファイル名 |

各フィールドは `detection.web.max_inspect_chars`（既定 8192）で切り詰めてからデコードする（CPU/ReDoS ガード）。

#### 1.2.1 検査の上限と打ち切り（#51）

構造の上限（`detection.web.max_params` / `max_headers` / `max_json_leaves` / `max_json_depth` / `max_multipart_parts`）を
超えた分は **捨てずに** 1 つの「あふれ」ターゲット（`param=(overflow)`）にまとめて検査する。以前は JSON の 129 番目以降の
リーフ・17 段目以降・キー名・multipart の 33 番目以降のパート・65 個目以降の Cookie / ヘッダが黙って捨てられ、
ダミー要素を前に置くだけで全 `web.*` を回避できた。まとめるときの区切りは NUL（空白にもシェルの区切りにも
ならないので、隣り合う項目が 1 つの文として読まれない）。

- 上限に達したことは、その要求から出た `web.*` 署名アラートの `details.inspection_truncated`（理由の一覧）と
  タグ `inspection-truncated` に残る。理由: `json_leaves` / `json_depth` / `multipart_parts` / `params:<location>` /
  `cookies` / `headers`（あふれを検査済み）、`chars:<location>` / `body_chars`（`max_inspect_chars` 以降は**未検査**）、
  `sensor_body`（センサーがボディの先頭しか捕捉していない。`request_body_size` との比較による概算で、マスキングで多少ずれる）。
- 上限に達しただけでは別のアラートにしない（アップロードや一括 API は普通に上限を超える）。上限の手前が
  **詰め物** に見えるときだけ `web.inspection_evasion`（low）を出す: 上限で切られたフィールドの 90% 以上が同じ 1 文字
  （NUL と U+FFFD はバイナリの痕跡なので除く）、あふれた JSON リーフ・multipart パート・パラメータ・Cookie・ヘッダの
  9 割以上が空か同じ値（16 個以上のとき）。`details.indicators` に `padding:<場所>` が入る。
- `max_inspect_chars` 以降の文字列は今も検査しない（CPU の上限）。そこに置かれたペイロードは、手前が詰め物なら
  `web.inspection_evasion` だけが鳴る。

#### 1.2.2 multipart の boundary（#52）

Content-Type のパラメータを `;` 区切りの `name=value` として解析する（名前は完全一致・大小無視、値は大小保持、
引用符付きの値は `;` やバックスラッシュエスケープを含められる）。以前の前方一致の正規表現は `; xboundary=ZZ; boundary=BB` で
`ZZ` を採用して分割に失敗し、全パートが `web.*` から見えなかった。`boundary` が複数あって値が違う場合はサーバーによって
どちらが採用されるかが違う（`TODO(verify)`: フレームワークごとの先勝ち / 後勝ちは未確認）ので **すべての候補で分割して検査** し、
`web.inspection_evasion` に `multipart_boundary_ambiguous` を出す（正規のクライアントは 2 つの boundary を送らない）。
どの候補でもパートに分割できなければボディ全体を `body` として検査する。RFC 2231 の分割パラメータ（`boundary*0=`）は組み立てない。

### 1.3 アラート形式

- 1 イベント × 1 検知器につき最大 1 アラート。最も重大度の高いヒットがタイトル・重大度を決め、異なる署名が
  複数ヒットすると信頼度を +0.05 ずつ（上限 0.95）上げる。
- `entities`: `path`（デコード済み、≤200 文字）, `host`, `param`（判明時）。
- `details`: `matched`（マッチ断片 ≤200 文字・制御文字はエスケープ・JSON 安全）, `signature`, `signatures`,
  `location`, `param`, `matches`（最大 5 件）, `method`, `status`。
- `fingerprint`: 署名系は `rule_id|source_ip|path_key`。`path_key` はパス先頭 3 セグメントで、数値→`{n}`、
  ID/UUID→`{id}`、`..` や記号を含むセグメント→`{x}`（連続は 1 つに）。ペイロード変種が同じアラートに畳まれる。
  例外: `web.sensitive_file_probe` は `rule|ip|署名ID`、`web.scanner_ua` は `rule|ip|ツール名`、
  `web.rare_method` は `rule|ip|メソッド`、レート系は `rule|ip`（credential は `|path_key` 付き）。
- `tags`: `web`, ファミリー名, ヒットした署名 ID（例 `sqli.union_select`）。CVE 系は `cve-2021-44228` 等。

## 2. 署名検知器

| id | 意図 | MITRE | 既定重大度 | 主な署名 |
|---|---|---|---|---|
| `web.sqli` | SQL インジェクション | T1190 | high | `union_select`, `time_based`（SLEEP/BENCHMARK/pg_sleep/WAITFOR DELAY）, `tautology_quoted`（`' OR 1=1`）, `tautology_numeric`, `comment_terminated`（`admin'--`）, `stacked_query`, `catalog_probe`（information_schema 等）, `dangerous_function`（xp_cmdshell, LOAD_FILE, @@version, extractvalue）, `order_by_probe` |
| `web.xss` | XSS | T1190, T1059.007 | medium | `script_tag`(high), `event_handler_tag`(high), `handler_breakout`, `javascript_uri`, `dangerous_tag`（iframe/object/embed/base）, `js_sink`（alert(1), document.cookie）, `csti`（AngularJS `{{constructor.constructor(...)}}`）, `data_uri_html` |
| `web.path_traversal` | ディレクトリトラバーサル | T1190, T1083 | high | `dotdot_multi`（`../../`, `....//`）, `tomcat_semicolon`（`..;/`）, `encoded`（`%2e%2e%2f`, `%252e`, `%c0%ae`, `%u002e`）, `os_file`（/etc/passwd, win.ini, /proc/self/environ, web-inf/web.xml）, `null_byte_ext`, `null_byte`（ボディ以外）, `dotdot_single`(medium) |
| `web.lfi_rfi` | LFI / RFI | T1190, T1105 | high | `php_wrapper`（php://filter/input）, `other_wrapper`（expect/phar/zip/glob）, `file_scheme`, `data_wrapper`（data://, data:text/plain;base64）, `php_code`（`<?php`）, `rfi.terminated_url`（`http://x/shell.txt?`）, `rfi.script_url` / `rfi.include_param_url`（`page`,`file`,`template` 等 include 系パラメータのみ） |
| `web.cmd_injection` | OS コマンド注入 | T1190, T1059, T1059.004 | high | `reverse_shell`(critical: /dev/tcp, nc -e, bash -i), `shellshock`(critical, 全ヘッダ), `download_exec`（curl … \| sh）, `separator_command`（`;cat /etc/passwd`, `\|whoami`）, `separator_short`（`;id` 等。単独の `\|` は対象外）, `subshell`（`$(id)`, `${IFS}`）, `backtick`(medium), `shell_path`（/bin/sh, cmd /c, powershell -enc） |
| `web.ssrf` | SSRF | T1190（+T1552.005） | high | `cloud_metadata`（169.254.169.254 と 10/16/8 進表記、metadata.google.internal、Azure/Alibaba/OCI、パス・ヘッダでも検出）, `internal_url`（ループバック/RFC1918/リンクローカル/ULA/`*.internal` 等を指す URL）, `dangerous_scheme`（gopher/dict/ldap/tftp/jar/netdoc/rmi。`jndi:` 直後は除外）, `bare_internal_host`(medium) |
| `web.log4shell` | Log4Shell（CVE-2021-44228） | T1190 | critical | `jndi`, `jndi_obfuscated`（`${${lower:j}ndi:`, `${::-j}`, `${env:NaN:-j}`, `${date:'j'}` を有界ループで展開して判定）, `lookup_exfil`（`${env:AWS_SECRET...}`）, `lookup`(high)。全 location を検査 |
| `web.ssti` | SSTI / 式言語注入 | T1190, T1059 | high | `math_probe`（`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`）, `python_object_walk`（`__class__.__mro__`, `__subclasses__`）, `config_leak`（`{{config}}`）, `erb_jsp`, `java_el`（SpEL `T(java.lang.Runtime)`, FreeMarker Execute, Velocity）, `twig_smarty`, `ognl`(critical, Content-Type ヘッダも検査) |
| `web.xxe` | XXE / エンティティ展開 | T1190 | high | `external_entity`, `parameter_entity`, `external_dtd`（w3.org の XHTML DTD は除外）, `xinclude`, `internal_subset`(medium), `entity_expansion`（`<!ENTITY` が 5 個以上 = billion laughs） |
| `web.deserialization` | 安全でないデシリアライズ | T1190, T1059 | high | Java `rO0AB` / `aced0005` / 既知ガジェットクラス / fastjson `@type`、PHP `O:n:"Class":n:{`、.NET `AAEAAAD/////` / Json.NET `$type` ガジェット、Python pickle（base64 `gASV`/`gAJj` 等・テキスト `cposix\nsystem`・`__reduce__`）、YAML `!!python/object/apply:`、node-serialize `_$$ND_FUNC$$_` |
| `web.rsc_action_abuse` | RSC Flight 返信の悪用（CVE-2025-55182 "React2Shell"） | T1190, T1059.007 | critical | `proto_ref`（`"$1:__proto__:then"`, `"$1:constructor:constructor"`）, `fake_chunk`（`"status":"resolved_model"`）= 強い指標。`internal_fields`（`_response`/`_formData`/`_prefix`）, `then_ref`, `proto_key` は RSC 文脈（Next-Action / RSC ヘッダ, text/x-component）か強い指標と同時のときのみ。`action_id_probe`（16 進でない Next-Action, low）。RSC 文脈 + 強い指標 → critical |
| `web.sensitive_file_probe` | 機微ファイル探索 | T1595.003, T1083, T1552.001 | medium | `file.secrets`（.env, .aws/credentials, id_rsa, wp-config.php.bak, .htpasswd, .kube/config ...）, `file.vcs`（.git/config, .svn）, `file.debug_endpoint`(high: actuator/env, heapdump, phpunit eval-stdin, _ignition) , `file.webshell`(high), `file.backup`（backup.zip, *.sql, `~`）, `file.admin_console`, `file.info_disclosure`(low: server-status, phpinfo, .DS_Store) |
| `web.scanner_ua` | 攻撃ツール・スキャナ | T1595, T1595.002 | medium | UA: sqlmap/commix/havij/xsstrike/hydra(high), nikto, nuclei, ffuf, gobuster, dirbuster, dirsearch, feroxbuster, wfuzz, wpscan, masscan, zgrab, Nmap NSE, Acunetix, Netsparker, w3af, Nessus, OpenVAS, ZAP ...、CensysInspect(low)。UA の表は AI 判定と共通の `aidetect/ua_catalog.py`（ここで鳴るツールと AI 判定で `scanner` になるツールは同じ集合。#124） / マーカーヘッダ（Acunetix-Aspect, X-Scan-Memo 等）/ マーカーパス（Nmap の `/nice ports,/Trinity.txt.bak` 等）/ OAST ドメイン(high: Burp Collaborator, oastify, interactsh, dnslog.cn, ceye.io。全 location) |
| `web.rare_method` | 稀な HTTP メソッド | T1595 | low | TRACE/TRACK/DEBUG/CONNECT(medium), WebDAV 動詞(low), 非標準トークン(low), 不正なトークン(medium), `X-HTTP-Method-Override` 等での偽装 |
| `web.inspection_evasion` | 検査上限を盾にした回避（#51, #52） | T1190 | low | `padding:<場所>`（上限の手前の詰め物。§1.2.1）、`multipart_boundary_ambiguous`（§1.2.2）。fingerprint は `rule|ip|path_key` |

`sensitive_file_probe` は応答も見る: **2xx かつ非 HTML** なら露出の疑い（secrets/vcs/debug/webshell → critical,
backup/admin → high, info → medium, `exposure_suspected` タグ）。2xx で Content-Type 不明なら最大 high、
2xx で HTML なら SPA のフォールバックとみなし昇格しない（`details.exposure` に理由）。

### 2.1 リクエスト形状の異常（`detect/detectors/web_anomaly.py`）

署名では見えない「検査から隠す・見た目を偽る」形のリクエスト。Gate が捕捉しきれなかったときに付けるタグ・ラベル
（`gate/capture.py`・`gate/app.py`）を入力に使うので、ヘッダ全体を見られない他のセンサー（アクセスログ等）では大半が鳴らない。
アラートの `details.signatures` に指標 ID が入るので、誤検知マーク（§5.1）は指標単位で効く。fingerprint は `rule|ip|最も重い指標`。
**どれも low / medium で、単独では送信元 IP の遮断提案の根拠にならない**（ルールベースのトリアージが対処を提案するのは high 以上。
medium は LLM トリアージ（`triage.min_severity_for_llm` 既定 medium）に乗り、low はインシデントの起点にはなりうる）。

| id | 意図 | MITRE | 重大度 | 指標（`details.signatures`） |
|---|---|---|---|---|
| `web.header_anomaly` | ヘッダ数の異常・非リストヘッダの重複（#140） | T1190 | low / medium | `header_anomaly.count`（ヘッダ行数が `header_count_low`（既定 40）超で low、`header_count_medium`（既定 64）超で medium）, `header_anomaly.capture_dropped`(medium: Gate が 64 名に収まらず記録しなかったヘッダがある = `gate.headers_dropped`), `header_anomaly.rejected`(medium: `gate.max_request_headers` 超で 431 = `gate:too_many_headers`), `header_anomaly.duplicate_framing`(medium: Host / Content-Length / Transfer-Encoding の重複), `header_anomaly.duplicate`(low: User-Agent・Referer・X-Real-IP 等の重複 = `gate.duplicate_headers`)。ヘッダ数は Gate が捕捉を打ち切ったときの `gate.header_count`（実数）、それ以外は記録したヘッダ名の数（同名の繰り返しは畳まれるので過小になりうる）。Cookie の連結が 8192 文字を超えただけ（`gate.headers_clipped`）では鳴らない |
| `web.uninspectable_body` | Gate が展開できない `Content-Encoding` の要求ボディ（#141） | T1190 | low / medium | `body.encoding_unknown`（br・zstd・compress・3 段以上 = `gate:req_encoding_unknown`。**本文はイベントに残らない**。上流が受け付けた（status 200〜399）なら medium、それ以外は low）, `body.decode_failed`(low: gzip / deflate と宣言して壊れている = `gate:req_decode_failed`。Gate は生の先頭をテキストとして記録するので、`Content-Encoding` を無視して生のまま読むアプリへの平文ペイロードは他の `web.*` が検査する)。gzip / deflate は Gate が展開して検査済み（`gate:req_encoded`）なので鳴らない |

## 3. レート / 振る舞い検知器（`ctx.window`, 送信元 IP ごと, イベント時刻基準）

| id | 意図 | MITRE | 既定重大度 | 条件（既定値） |
|---|---|---|---|---|
| `web.error_burst` | ディレクトリ総当たり・ワードリストスキャン | T1595.003, T1083 | medium | 60 秒窓で 4xx ≥ 30 件、4xx 比率 ≥ 0.6、異なるパス ≥ 15 |
| `web.credential_stuffing` | ログイン総当たり / クレデンシャルスタッフィング / スプレー | T1110（+.001/.003/.004） | high/medium | ログイン系パス（正規表現）で 401/403 が 300 秒窓に ≥ 10 件。異なるユーザー名 ≥ 4 なら stuffing(high)、それ未満は password guessing(medium)。ユーザー名はハッシュのみ保持 |
| `web.request_flood` | アプリ層 DoS・過剰クローラ | T1499.002 | medium（5 倍超で high） | 10 秒窓で 20 rps × 10 秒 = 200 件以上 |

発報後は送信元ごとに 1 窓分沈黙し（クールダウン）、継続中の攻撃はエンジンの fingerprint 重複排除で 1 アラートの
`count` 増加として表れる。

## 4. 設定（`detection.web`、env 例 `TOKIWA_DETECTION__WEB__FLOOD_MAX_RPS=50`）

| キー | 既定 | 説明 |
|---|---|---|
| `max_inspect_chars` | 8192 | フィールドごとの検査上限（これ以降の文字列は検査しない） |
| `max_params` / `max_headers` | 64 / 64 | パラメータ・Cookie / ヘッダを個別に検査する数。超えた分はまとめて検査（§1.2.1） |
| `max_json_leaves` / `max_json_depth` | 128 / 16 | JSON の文字列リーフを個別に検査する数 / 深さ。超えた分はまとめて検査 |
| `max_multipart_parts` | 32 | multipart のパートを個別に検査する数。超えた分はまとめて検査 |
| `max_decode_rounds` | 8 | 1 つの値に対する URL / HTML / JS のデコードの最大ラウンド数（安定したら早く止まる。#89 で 3 → 8） |
| `inspect_custom_headers` | true | アプリ固有ヘッダ（`header_custom`）を注入系の検知器でも検査する（#53）。false で従来の挙動（既知の反射ヘッダだけ） |
| `extra_framing_headers` | `[]` | 注入系の検知器で検査しないヘッダ名の追加（小文字。末尾 `*` で前方一致、例 `x-internal-*`）。値が不透明・自動生成のヘッダで誤検知するときに使う。Log4Shell 等は引き続き検査する |
| `header_count_low` / `header_count_medium` | 40 / 64 | `web.header_anomaly` のヘッダ行数のしきい値（超えたら low / medium。0 でその段を無効）。ブラウザは 10〜25 行程度（Client Hints を全部要求すると増える）、CDN・ロードバランサが 1 段ごとに数行足す |
| `error_burst_window_seconds` / `_min_errors` / `_min_ratio` / `_min_unique_paths` | 60 / 30 / 0.6 / 15 | error_burst |
| `login_path_regex` | login, signin, auth, session, token, wp-login.php, xmlrpc.php, j_security_check ... | ログイン系パス（大小無視）。不正/2000 文字超の正規表現は既定値にフォールバック |
| `credential_window_seconds` / `_fail_statuses` / `_min_failures` / `_min_unique_users` | 300 / [401, 403] / 10 / 4 | credential_stuffing |
| `flood_window_seconds` / `flood_max_rps` | 10 / 20 | request_flood |
| `allowed_methods` | GET HEAD POST PUT DELETE PATCH OPTIONS | rare_method の許可リスト（WebDAV 環境では PROPFIND 等を追加） |

個別の検知器の有効/無効は `detection.disabled_detectors` または detectors API（sigma タスク）で切り替える。

## 5. 誤検知抑制と性能

- 同梱 Sigma の web ルール（`rules/sigma/web`）は同じイベントで同じ種類の `web.*` が発報したらそちらに合流し、`web.*` が
  有効なのに沈黙したときは low に下がる（重複発報とネイティブの抑制のすり抜けを防ぐ。#76、docs/detection/sigma.md §5.1）。

### 5.1 誤検知のフィードバックと許可リスト（#166 / #173）

全検知器のアラートに効く（`web.*` に限らない）。テーブル `alert_suppressions`、ロジックは `detect/suppress.py`、適用は
`DetectionEngine.persist`（重複排除の前）。

- **誤検知（false_positive）**: アラートを `false_positive` にすると（`PATCH /alerts/{id}`）、そのアラートの指紋で
  `detection.fp_suppress_hours`（既定 168 時間。0 = 自動では作らない）抑制する。指紋 = ルール ID + 正規化した一致内容
  （`web.*`: 一致した署名 ID の集合・location・パラメータ名、Sigma: 真になった selection の集合）+ パスの route key（`path_key`）
  + 送信元 IP（/32・/128）。後続の draft がこれと同じルール・route・送信元で、署名 / selection が **部分集合** かつ重大度が元のアラート
  以下なら、新しいアラートを作らず元のアラートの `count`・`last_seen`・証拠に加算する（bus に流さないのでトリアージ・通知・
  インシデント再紐付けは起きない）。新しい署名・別パラメータ・重大度の上昇は新しい証拠として通常どおり発報する。
  `suppress: false` で作らない、`suppress_hours` / `suppress_permanent` で期間、`suppress_any_source: true` で送信元を問わない
  （広げると同じ route・パラメータへの攻撃も抑えるので注意）。状態を `false_positive` 以外に戻すと抑制は解除される。
- **許可リスト（allowlist）**: 許可済みの脆弱性診断・負荷試験のために、送信元 CIDR（必須。IPv4 は /8、IPv6 は /32 より狭いこと）と
  期間（必須。`detection.allowlist_max_hours` 既定 720 時間まで）を宣言する（`POST /alert-suppressions`、admin のみ）。任意でルール ID・
  パスを絞れる。`downgrade`（既定）はアラートを info・状態 acknowledged・タグ `allowlisted` で記録し bus に流さない（トリアージ・
  通知・インシデント・対処提案に乗らない）。`suppress` は記録せず件数だけ数える。ルールを絞らない許可リストはデセプションや
  AI 判定のアラートも静かにする（期間付きで、一覧・解除は API / 監査ログで追える）。

- 正常トラフィック fixture（`backend/tests/detect/fixtures/web_benign.json`: "select" を含む検索、アポストロフィ、
  `fields=name|id`、リッチテキスト JSON、JSON-LD の `@type`、XHTML DOCTYPE、正規の Next.js Server Action、
  開発者ブラウザの `Referer: http://localhost:3000/` 等）で web.* が 1 件も発火しないことをテストしている。
- すべての正規表現は `web_common.rx()` 経由で登録され、`test_web_perf.py` が 4 KiB の敵対的入力で全件を実行する
  （1 パターンの最悪 ~10 ms / 予算 250 ms）。署名作者向けルールは `web_common.py` の docstring 参照。
- 性能: fixture 混在で全 web 検知器合計 ~0.2 ms/イベント（開発コンテナ実測。テストの予算は 5 ms）。
  検知器ごとにビュー単位の結合プリフィルタ正規表現を 1 回だけ当て、ヒット時のみ個別署名を評価する。

## 6. 既知の限界

- **ボディが見えないログ**（nginx/caddy アクセスログ）では body 由来の検知（JSON/フォーム内の SQLi、XXE、
  デシリアライズ、RSC）は不可能。Gate（全 HTTP 捕捉）が前提。Gate も既定で先頭 4 KiB しか捕捉しない。
- センサーが**正規化済みパス**（nginx `$uri`）を記録すると、パス中のトラバーサルやエンコード回避は見えない。
- Gate のマスキングで Cookie / Authorization / `password=` 等の値は `[REDACTED:...]` になる。Cookie 内の
  シリアライズオブジェクトや password 欄の SQLi は検知できないことがある。メールアドレスのマスクにより
  credential_stuffing のユーザー名多様性は過小評価されうる（`details.username_unknown` に件数）。
- 字句的な検知である: DNS 名が内部アドレスに解決される SSRF（rebinding, nip.io 等）、未知のエンコード、
  意味的に等価な書き換えは見逃しうる。逆に、セキュリティ解説記事の投稿や CMS のリッチ HTML（iframe,
  `javascript:void(0)`）、SQLi について質問するチャット本文は誤検知しうる（medium 以下が中心）。
- レート系はプロセス内メモリで、再起動で 1 窓分失われる。NAT/プロキシ配下の共有 IP は閾値に達しやすい
  （Gate で X-Forwarded-For を信頼する設定にするか閾値を上げる）。ログイン失敗を 200 で返すアプリは検知不可。
- `web.rsc_action_abuse` の内部フィールド名・Action ID 形式は公開 PoC 由来（`TODO(verify)`、§7）。
- ユーザー設定の `login_path_regex` は ReDoS 検証の対象外（パス長 2048 で切って照合）。

## 7. TODO(verify)

- CVE-2025-55182: `resolved_model` / `_response` / `_formData` / `_prefix` / `_chunks` 等のフィールド名は、
  2025-12 に公開された PoC の形に基づく。修正版 react-server-dom-webpack のソースと照合すること。
  Next.js の Action ID 形式（40 文字以上の 16 進）もバージョン差を確認すること。
- スキャナのマーカーヘッダ（Acunetix-Aspect*, X-WIPP, X-Scan-Memo, X-RequestManager-Memo, X-Request-Memo）と
  Nessus のマーカー文字列 `nessus_is_probing_you` は一次資料で未確認。
- MITRE の付与（例: rare_method → T1595）は暫定。ATT&CK の最新版と照合すること。
