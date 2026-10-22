# タスク: detect-web — Web 攻撃の署名・レート検知

## 目的
HTTP イベント（`EventKind.HTTP`）から既知の攻撃パターン・スキャナ・異常レートを検知する組み込み検知器群（FR-05）。
AI エージェントも結局はこれらのペイロードを使うため、AI 判定（detect-ai）の土台にもなる。

## 担当範囲
- `backend/src/tokiwa/detect/detectors/web_*.py`（新規、ファミリーごとに分割）
- `backend/src/tokiwa/detect/web_common.py`（デコード・正規化ユーティリティ、新規）
- `backend/tests/detect/test_web_*.py`, `backend/tests/detect/fixtures/`（新規）
- `docs/detection/web.md`（検知器カタログ）

## 要件
1. 入力正規化ユーティリティ: URL デコード（多重/混在エンコード、`%u` 形式、`+`）、HTML エンティティ、
   大文字小文字・空白・コメント（`/**/`）の正規化、path + query + body + 主要ヘッダ（UA, Referer, Cookie 名,
   X-Forwarded-For 等）の検査対象抽出。ReDoS を起こさない正規表現（入力長上限・非バックトラック的パターン）。
2. 署名検知器（それぞれ id, MITRE, 既定重大度, テスト付き）:
   - `web.sqli`（UNION SELECT, boolean/time-based: SLEEP/BENCHMARK/pg_sleep/WAITFOR DELAY, stacked, `' OR 1=1`, information_schema）
   - `web.xss`（script/iframe/on*= ハンドラ, javascript:, svg/onload, template injection 風）
   - `web.path_traversal`（`../`, エンコード変種, `/etc/passwd`, `win.ini`, null byte）
   - `web.lfi_rfi`（php://, file://, data://, expect://, 外部 URL include パラメータ）
   - `web.cmd_injection`（`;id`, `|whoami`, `$(...)`, バッククォート, `&& curl`, `nc -e`, `/bin/sh`）
   - `web.ssrf`（パラメータ内の内部 IP/localhost/169.254.169.254/metadata.google.internal/::1, gopher://, dict://）
   - `web.log4shell`（`${jndi:` と難読化 `${${lower:j}ndi:`）
   - `web.ssti`（`{{7*7}}`, `${7*7}`, `<%= %>`, `{{config}}`, `__class__.__mro__`）
   - `web.xxe`（`<!DOCTYPE` + `<!ENTITY ... SYSTEM`）
   - `web.deserialization`（Java `rO0AB`/`aced0005`, PHP `O:\d+:"`, .NET `AAEAAAD/////`, Python pickle 印）
   - `web.rsc_action_abuse`（React Server Components / Next.js Server Actions の不審な Flight ペイロード。
     `Next-Action` ヘッダ + body 内の `$` 参照連鎖や `__proto__`/`constructor` 等。CVE-2025-55182（いわゆる
     React2Shell）を念頭に。**公開情報で確認できた特徴のみ** を実装し、不確実な点は `TODO(verify)` とする）
   - `web.sensitive_file_probe`（/.env, /.git/config, /.aws/credentials, wp-config.php, /server-status, /actuator, .DS_Store, id_rsa, backup.zip 等）
   - `web.scanner_ua`（sqlmap, nikto, nuclei, ffuf, gobuster, dirbuster, wpscan, masscan, zgrab, nmap NSE, Acunetix, Burp Collaborator ドメイン）
   - `web.rare_method`（TRACE, TRACK, PROPFIND, DEBUG, CONNECT 等）
3. レート/振る舞い検知器（`ctx.window` 使用）:
   - `web.error_burst`（同一送信元の 4xx 比率・件数が窓内で閾値超え = ディレクトリ総当たり）
   - `web.credential_stuffing`（ログイン系パス（設定可能な正規表現）への 401/403 多発、ユーザー名多様性）
   - `web.request_flood`（送信元ごとの RPS 異常）
4. 各 AlertDraft に `entities`（`path`, `param`（わかれば）, `host`）と `details`（マッチした断片 ≤200 文字）。
   `fingerprint` は `rule_id|source_ip|path(正規化)` を基本に過剰アラートを抑える。
5. 誤検知抑制: 正常トラフィック fixture（一般的なブラウジング・API 呼び出し・検索クエリに "select" を含む等）で
   発火しないことをテスト。
6. 性能: 1 イベントあたり全署名検知器で < 1ms 目安（簡易ベンチをテストに含める、閾値は緩めに）。

## 受け入れ基準
- 上記すべての検知器が登録され、陽性/陰性 fixture でテストが緑。
- `docs/detection/web.md` に各検知器の id・意図・MITRE・既知の限界（ボディが見えないログでは検知不可など）。
