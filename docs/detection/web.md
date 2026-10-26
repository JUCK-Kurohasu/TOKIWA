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

デコードは最大 3 ラウンドで安定するまで繰り返す: `%XX`（多重エンコード、`%%32%65` のような入れ子）、`%uXXXX`、
overlong UTF-8（`%c0%ae` `%c0%af` `%c1%9c` `%e0%80%ae`）、`+`→空白（フォーム文脈の 1 ラウンド目のみ）、
HTML エンティティ、`\uXXXX` / `\xXX`。SQL の `/**/` は空白に、MySQL の `/*!50000 ... */` は中身を残す。全角文字は NFKC で ASCII に寄せる。

### 1.2 検査対象（location）

| location | 内容 |
|---|---|
| `path` | パス（クエリなし。`path` に `?` が含まれ `query` が空なら分割する） |
| `query` | クエリのパラメータごと（`name=value`、`param` に名前） |
| `body` | フォーム / JSON の文字列リーフ（`param` は `a.b[0]`）/ multipart パート。構造化できなければボディ全体 |
| `body_raw` | ボディ全体（構造化できた場合のみ追加。XXE・デシリアライズ・RSC 用） |
| `header` | 反射・記録されやすいヘッダ（User-Agent, Referer, Origin, X-Forwarded-For 系, Forwarded, X-Api-Version ...） |
| `header_other` | その他のヘッダ（Log4Shell / OGNL / Shellshock 用）。Authorization 等は検査しない |
| `cookie` | Cookie のペアごと（名前も検査対象） |
| `filename` | multipart のファイル名 |

各フィールドは `detection.web.max_inspect_chars`（既定 8192）で切り詰めてからデコードする（CPU/ReDoS ガード）。

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
| `web.scanner_ua` | 攻撃ツール・スキャナ | T1595, T1595.002 | medium | UA: sqlmap/commix/havij/xsstrike/hydra(high), nikto, nuclei, ffuf, gobuster, dirbuster, dirsearch, feroxbuster, wfuzz, wpscan, masscan, zgrab, Nmap NSE, Acunetix, Netsparker, w3af, Nessus, OpenVAS, ZAP ... / マーカーヘッダ（Acunetix-Aspect, X-Scan-Memo 等）/ マーカーパス（Nmap の `/nice ports,/Trinity.txt.bak` 等）/ OAST ドメイン(high: Burp Collaborator, oastify, interactsh, dnslog.cn, ceye.io。全 location) |
| `web.rare_method` | 稀な HTTP メソッド | T1595 | low | TRACE/TRACK/DEBUG/CONNECT(medium), WebDAV 動詞(low), 非標準トークン(low), 不正なトークン(medium), `X-HTTP-Method-Override` 等での偽装 |

`sensitive_file_probe` は応答も見る: **2xx かつ非 HTML** なら露出の疑い（secrets/vcs/debug/webshell → critical,
backup/admin → high, info → medium, `exposure_suspected` タグ）。2xx で Content-Type 不明なら最大 high、
2xx で HTML なら SPA のフォールバックとみなし昇格しない（`details.exposure` に理由）。

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
| `max_inspect_chars` | 8192 | フィールドごとの検査上限 |
| `error_burst_window_seconds` / `_min_errors` / `_min_ratio` / `_min_unique_paths` | 60 / 30 / 0.6 / 15 | error_burst |
| `login_path_regex` | login, signin, auth, session, token, wp-login.php, xmlrpc.php, j_security_check ... | ログイン系パス（大小無視）。不正/2000 文字超の正規表現は既定値にフォールバック |
| `credential_window_seconds` / `_fail_statuses` / `_min_failures` / `_min_unique_users` | 300 / [401, 403] / 10 / 4 | credential_stuffing |
| `flood_window_seconds` / `flood_max_rps` | 10 / 20 | request_flood |
| `allowed_methods` | GET HEAD POST PUT DELETE PATCH OPTIONS | rare_method の許可リスト（WebDAV 環境では PROPFIND 等を追加） |

個別の検知器の有効/無効は `detection.disabled_detectors` または detectors API（sigma タスク）で切り替える。

## 5. 誤検知抑制と性能

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
