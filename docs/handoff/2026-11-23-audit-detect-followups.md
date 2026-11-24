# 2026-11-23 監査対応レーン: detect-followups（第 1〜3 弾で「他レーンへの依頼」として残った検知シグナル）

担当（この順）: #140 残り → #141 残り → #147 残り → #150 残り → #177 残り。依頼の出所は
`docs/handoff/2026-11-22-audit-gate-capture.md`（#140 #141 #147）、`2026-11-21-audit-frontend.md`（#150）、
`2026-11-21-audit-eval-docs.md`（#177）。指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`
（#140=L06-09, #141=L06-10, #147=L06-07, #150=L10-05, #177=L15-04）。

ブランチ `worktree-agent-ac04ee82724b63d99`（基点 `4d79617`）。新しい検知器は `backend/src/tokiwa/detect/detectors/web_anomaly.py`、
テストは `backend/tests/detect/test_web_anomaly.py`（Gate の `EventBuilder` でイベントを作り、Gate が付けるタグ・ラベルの語彙が
変わったらテストが落ちるようにしてある）。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #140 | 部分（推奨 (1)(3)(4) は gate-capture レーンで完了。(2) の「異常なヘッダ数をシグナルに」は実装したが、**41〜64 行は low**（推奨の例は「>40 で medium」）。理由は要判断 1） | 新検知器 `web.header_anomaly`（`category=anomaly`, T1190）。指標: `header_anomaly.count`（ヘッダ行数 > `detection.web.header_count_low`（既定 40）で low、> `header_count_medium`（既定 64）で medium）、`header_anomaly.capture_dropped`（medium: Gate が 64 名に収めきれず記録しなかった行がある = label `gate.headers_dropped`）、`header_anomaly.rejected`（medium: `gate:too_many_headers` = 431。同名 101 行のように件数ラベルが付かない場合もこれで拾う）、`header_anomaly.duplicate_framing`（medium: Host / Content-Length / Transfer-Encoding の重複）、`header_anomaly.duplicate`（low: その他の非リストヘッダの重複 = `gate.duplicate_headers`）。ヘッダ行数は `gate.header_count`（Gate が捕捉を打ち切ったときだけ付く実数）、無ければ `max(len(headers), len(header_order))`。Cookie の連結が 8192 文字を超えただけ（`gate.headers_clipped`）では鳴らさない。`details` に `signatures`・`location`・`param` を入れて誤検知マーク（#166）が指標単位で効くように。fingerprint `rule|ip|最も重い指標`。テスト: 70 個のパディング → medium・件数 78・未記録 14、48 行 → low、Client Hints + CDN ヘッダ + 分割 Cookie（20 行・clipped）→ 無音、しきい値の設定、431、Host 重複 → medium・UA 重複 → low、DECEPTION 種別のコピーでは重複発報しない。docs/detection/web.md §2.1・§4、wiki Configuration ×4 | 7e35122 |
| #141 | 完全（推奨 (1) と (2) の「印を付ける」・(3) 運用文書は gate-capture レーンで完了。(2) の「web_recon で low〜medium シグナル化」をこのレーンで実装） | 新検知器 `web.uninspectable_body`（`category=anomaly`, T1190）。`gate:req_encoding_unknown`（br・zstd・compress・3 段以上。Gate は本文を記録しない）→ `body.encoding_unknown`: **上流が受け付けた（status 200〜399）なら medium**、それ以外（415・400・Gate の 403 等）は low。`gate:req_decode_failed`（gzip / deflate と宣言して展開できない。Gate は生の先頭をテキストとして記録するので他の `web.*` が検査する）→ `body.decode_failed`: low。`details.content_encoding` は `Content-Encoding` ヘッダの値（`clean_label`、60 文字）。テスト: br + 200 → medium・本文なし、br + 415 → low、壊れた gzip に平文の SQLi → low + `web.sqli`（param=password）も鳴る、正しい gzip と非圧縮は無音。docs/detection/web.md §2.1 | ccad1ff |
| #147 | 完全（推奨 (1) と (2) の除去・タグ・デコイ照合は gate-capture レーンで完了。(2) の「値を sensitive path 検知にかける」と (3) の検知ルールをこのレーンで実装） | 新検知器 `web.route_override`（`category=exploit_attempt`, T1190）。`X-Original-URL` / `X-Rewrite-URL` / `X-Override-URL` の値のパス（`web_common.override_path()`: 絶対 URL はパス部分、`?`・`#` 以降を除く、先頭 `/` 補完、デコード・NFKC・小文字化・`clean_path` = `HttpView.path_clean` と同じ正規化）が要求行のパスと違えば `route_override.different_path`（**medium**）、値が空なら `route_override.empty`（low）。**要求行と同じパスは鳴らさない**（`X-Forwarded-Prefix` + パスで同じ場合も）: 前段のプロキシが受けた URL をそのまま付ける形（IIS ARR、nginx の `proxy_set_header X-Original-URL $request_uri` 等）で、web-detect レーンの良性 fixture「app custom headers」もこの形（初版は同一パスを low にしていてこの fixture で落ちた）。Gate がそのヘッダを渡した（`gate:route_override` あり・`gate.action=proxy`・`gate.stripped_headers` に名前が無い = 運用者が `gate.forward_client_headers` で許可）ときは鳴らさない。タグが無い（Gate 更新前の古い Gate はこのヘッダを上流へ渡す）ときはクライアント由来として扱う。`web.sensitive_file_probe` は値のパスも同じ署名で検査（`location=header_custom`・`param`=ヘッダ名・タグ `route_override`。応答は要求行のものなので 2xx による昇格はしない）。テスト: `/static/app.js` + `X-Original-URL: /.env` → route_override medium と sensitive_file_probe medium（200 text/plain でも critical にならない）、絶対 URL、空値、タグなし、運用者許可で無音、デコイ応答では鳴る、同一パス・プレフィックス付き同一パスは無音。攻撃 fixture 3 件。docs/detection/web.md §2・§2.1 | af7884b |
| #150 | 完全（推奨のフロント部分は frontend レーンで完了。末尾の「サーバー側にも path/UA の双方向制御文字を低重大度の検知シグナルに」をこのレーンで実装） | 新検知器 `web.deceptive_unicode`（`category=anomaly`, **T1036.002** Masquerading: Right-to-Left Override, low）。指標: `unicode.bidi_control`（U+202A〜U+202E・U+2066〜U+2069 は常に、LRM・RLM・ALM は文脈付き）、`unicode.zero_width`（U+200B・U+2060・U+FEFF は常に、ZWNJ・ZWJ・U+180E・ハングルの埋め字 U+115F/U+1160/U+3164/U+FFA0 は文脈付き）、`unicode.tag_characters`（U+E0000〜U+E007F、旗の絵文字 = U+1F3F4 に続く列は除く）。「文脈付き」= 隣が ASCII か値の端のときだけ（`/.e<ZWJ>nv` は鳴り、ペルシア語の ZWNJ・絵文字の ZWJ 列は鳴らない）。対象: デコード後のパス（アクセスログの `%E2%80%8B` も Gate のデコード済みパスも同じ判定）、User-Agent、全ヘッダ値（Gate は latin-1 で記録するので UTF-8 として読み直す `as_received()`）。**クエリ・ボディは対象外**（RTL 文字列・絵文字の本文に普通に含まれる）。候補文字の正規表現 1 本（`rx()` 登録で ReDoS テスト対象）で先にふるい、ASCII だけの値は即スキップ。1 回の前向き走査（タグ文字の列は先頭で 1 回だけ旗かどうかを判定）で、候補は 1 フィールド 512・1 イベント 2048 まで。上限に達したら `unicode.excessive`（数百の書式文字はテキストではない。上限の手前に良性の結合子を並べてすり抜ける手も塞ぐ）。`details.code_points`（場所ごとの `U+XXXX 名前`）・`details.excerpts`（`<U+202E>` 形式。普通の文字はそのまま）。タイトル・`matched` は ASCII のみ、抜粋に該当文字の実物は残らない（テストで確認）。並べ替え文字の集合は UI の `BIDI_RE` と同じ。テスト: パスの RLO、パーセントエンコードの ZWSP、ASCII 間の ZWJ、Gate 経由の UA（latin-1）の RLO、ヘッダのタグ文字（ASCII smuggling）、ペルシア語・絵文字の家族・イングランド旗・日本語のパス、RTL のクエリ、ボディ、Gate 経由の日本語ヘッダは無音、タグ文字 8192 個のパス・ヘッダと ZWSP 8192 個の UA・結合子 4096 組のヘッダ 2 つでも 0.25 秒未満（実測は 1 ms 未満）。docs/detection/web.md §2.1 | c15bcba, （追補コミット） |
| #177 | 完全（推奨のうち既定パス・起動時 ERROR・eval の `sigma_rules_loaded` は eval-docs レーンで完了。残りの「/health の degraded 表示」をこのレーンで実装。0 件読み込みの起動時 ERROR も追加） | `SigmaRuleStore`（`detect/sigma/loader.py`）に `file_rules_found`（ディレクトリから読めた有効なルールファイル数。rules テーブルの status を適用する **前** なので、運用者が無効化した組み込みルールは「欠落」に数えない。未読込は None）・`file_rules_invalid` と `health(detector_enabled, include_paths)`（属性を読むだけ。ファイル・DB に触れない）。ディレクトリはあるのに有効なルールが 0 件なら起動時に ERROR を 1 回（ディレクトリ欠落は eval-docs レーンの ERROR が既にある）。`GET /api/v1/health`: **未認証（API トークン含む）は従来どおり常に `{"status": "ok"}`・200**。有効なユーザー JWT 付きのときだけ `version` に加えて `checks.sigma`（`status` = ok / degraded / disabled / starting / unknown、`rule_dirs`・`missing_dirs`（件数）・`file_rules_found`・`file_rules_invalid`・`rules_active`・`file_rules_active`、**admin のみ** `missing_dir_paths`）を返し、degraded があれば `status: "degraded"`（HTTP は 200 のまま）。検知器 `sigma` の無効化（設定・`PATCH /detectors` の上書きとも `engine.is_enabled` で判定）と `sigma_rule_dirs: []` は `disabled`（degraded にしない）。判断の理由は要判断 2。テスト `tests/api/test_health_checks.py`: 同梱ルール → ok・20 件以上・viewer も見える、ディレクトリ欠落 → degraded・admin にだけパス・viewer にはパスなし・未認証は `{"status": "ok"}`、壊れたルール 1 件だけのディレクトリ → degraded・invalid 1、検知器無効 → disabled で全体 ok、組み込みルールを 1 件無効化 → ok のまま・active が 1 減る。docs/api-contract.md、docs/detection/sigma.md、wiki Troubleshooting ×4（「Sigma ルールのアラートが 1 件も出ない」） | 2f9f525 |

## チェック（HEAD = 2f9f525 + この NOTES 更新）

- backend: `uv run pytest -q` 全体が終了コード 0（失敗・エラーなし。aiosqlite の「Event loop is closed」の
  `PytestUnhandledThreadExceptionWarning` が無関係なテスト 6 件で出る — 警告のみ）。`ruff check` / `ruff format --check` 緑、
  `mypy src` は既知の 4 件のみ（detect/context.py・db/session.py ×2・intel/sources/_common.py）。
- `python3 scripts/check_wiki.py` OK（14 ページ × 4 言語）。フロントエンドは触っていない。
- 監査の L16 良性コーパス（`docs/audit/2026-11/repro/L16/pass2/run.py` をスクラッチにコピーし、Sigma のパスだけ worktree に変えて実行。
  6,855 イベント・mock LLM）: アラート 31（critical 3 / high 13 / medium 13 / low 2）、インシデント 3、提案 5、LLM 呼び出し 64 —
  web-detect レーンの #76 後の値（31 / 3 / 5 / 64）と同じで、**新しい 4 検知器はどれも 1 件も鳴らなかった**。ただしこのコーパスは
  Gate のタグ・ラベル（打ち切り・展開不能・ルーティング上書き）を含まないので、#140 #141 #147 の良性側の根拠は主に fixture
  （51 件 + test_web_anomaly.py の良性ケース）。
- 変更ファイルに双方向制御文字・ゼロ幅文字の実文字が無いことを `LC_ALL=C.UTF-8 grep -P` で確認（既存の web_common.py の BOM 1 つを除く）。

## 要判断

1. **#140 のしきい値**: 推奨は「>40 で medium」だが、Client Hints を全部要求するサイト（`Accept-CH` で `sec-ch-ua-arch` 等 10 個前後）を
   CDN（cf-ray・cf-ipcountry・cdn-loop・x-forwarded-for 等）と ALB（x-amzn-trace-id・x-forwarded-port）の後ろで受けると、正規のブラウザでも
   40 行前後になりうる（行数は各ヘッダの一般的な付与状況からの見積もりで、実測ではない）。そこで「41〜64 行 = low、Gate が記録しきれない
   （64 名超）・431・65 行超 = medium」にした。low は LLM トリアージ・通知に乗らない（インシデントの起点にはなる）。推奨どおりにするなら
   `detection.web.header_count_medium: 40`。統合担当は #140 を Closes にせず Refs のままにするか、この判断を受け入れて Closes にするかを決める。
2. **#177 の degraded を誰に見せるか**: 未認証の `/health` には出さない（常に `{"status": "ok"}`・200）。理由: (a) Docker HEALTHCHECK
   （`deploy/healthcheck.py` は 2xx かどうかだけを見る）やロードバランサが 503 を受けるとコンテナの再起動・振り分け停止になり、再起動では
   直らない問題（ディレクトリが無い）のために **他のすべての検知まで止まる**。(b) 「Sigma が止まっている」は攻撃者に何が見えていないかを
   教える情報（http-hardening レーンが version を隠したのと同じ理由）。(c) パスはサーバーのファイル配置なので admin のみ。
   代償: 外部の監視から degraded を見るにはユーザー JWT が要る（API トークン = センサー用では見えない）。監視用に「health スコープの
   API トークン」を作るかは要判断（今回は作っていない）。UI はまだ degraded を表示しない（frontend レーンへ依頼）。

## 送信元 IP の扱い（遮断提案との関係）

- ルールベースのトリアージ（`triage/fallback.py`）が対処（block_ip / rate_limit）を提案するのは **high 以上** だけ。このレーンの検知器は
  すべて low / medium なので、単独では遮断提案の根拠にならない。medium は LLM トリアージ（`triage.min_severity_for_llm` 既定 medium）に乗り、
  実 LLM が対処を推奨しうるが、提案は人間承認が既定（自動承認は第 2 弾の `response.auto_approve_withheld` 等の条件付き）。
- #140: ヘッダ数・重複は送信元が実際に送ったもの（他人の IP を装えない）。送信元 IP は Gate の判定値（信頼設定時は XFF の右端）。
- #141: medium は「上流が受け付けた」場合だけ。圧縮ボディは送信元が自分で送るもので、第三者を装うことはできない。
- #147: medium。値が要求行と違うことだけが根拠で、上流が実際にこのヘッダを解釈したかは分からない（Gate は渡さない）。
  `web.sensitive_file_probe` のヘッダ由来ヒットは署名の重大度のまま（`file.debug_endpoint` / `file.webshell` は high なので、
  ルールベースのトリアージが rate_limit を提案しうる。要求行で同じパスを叩いた場合と同じ扱い）。
- #150: low のみ。LLM トリアージにも乗らない（インシデントの起点にはなりうる）。欺瞞の意図を示すが攻撃の成否とは無関係なので、
  遮断の根拠にはしない設計。

## 既定動作の変更

- （#140）新しい検知器 `web.header_anomaly` が既定で有効。ヘッダ行 41 以上の要求で low、65 以上・Gate が記録しきれない・431・Host /
  Content-Length の重複で medium のアラートが出る（以前は何も出なかった）。`detection.disabled_detectors: ["web.header_anomaly"]` で無効、
  しきい値は `detection.web.header_count_low` / `header_count_medium`（0 でその段を無効）。
- （#141）新しい検知器 `web.uninspectable_body` が既定で有効。Gate が展開できない符号化の要求ボディで low / medium（上流が 2xx・3xx）。
- （#147）新しい検知器 `web.route_override` が既定で有効。`web.sensitive_file_probe` がルーティング上書きヘッダの値のパスでも鳴る。
  **前段に URL を書き換えて `X-Original-URL` に元の URL を入れるプロキシ（IIS ARR 等）があり、Gate がそれを上流へ渡さない構成では、
  書き換えのあるパスごとに medium が出る**（その構成では上流が必要なら `gate.forward_client_headers: ["x-original-url"]`、不要なら
  `web.route_override` を無効化）。
- （#150）新しい検知器 `web.deceptive_unicode`（low）が既定で有効。
- （#177）ログイン済みの `GET /api/v1/health` の応答に `checks` が増え、Sigma のルールディレクトリ欠落・0 件で `status` が
  `"degraded"` になる（以前は常に `"ok"`）。未認証の応答・HTTP ステータスは不変。ディレクトリはあるのに有効なルールが 0 件なら起動時 ERROR。

## 失敗した試み

- （#150）編集ツールが Python ソース中の `\u061c` 等のエスケープを実文字に展開した（frontend レーンの NOTES と同じ現象）。
  候補文字の正規表現をスクラッチのスクリプト（`chr(92)` でバックスラッシュを組み立て）で ASCII のエスケープに書き直し、テストは
  `chr(0x202E)` で文字を作る形にした。コミット前に `LC_ALL=C.UTF-8 grep -nP '[^\x00-\x7F]'` で検知器・テストに非 ASCII が無いことを確認。
  既存の `web_common.py` 569 行目（#89 の `utf16_text`）には BOM の実文字が 1 つある（このレーンの変更ではない）。
- （#150）初版（c15bcba）はタグ文字ごとに列の先頭まで後ろ向きに辿っていたため、タグ文字 n 個で O(n²)（8192 個で 3.3 秒。
  未認証のクライアントが Gate 経由のヘッダや ingest のパスで検知ループの CPU を使える）。統合前の助言で発見し、前向き 1 回の走査と
  候補数の上限に直した（追補コミット。8192 個で 1 ms 未満）。`test_web_perf.py` は登録した正規表現しか計らないので、検知器の Python
  ループは自分でタイミングテストを書く必要がある。
- （#147）同じく追補で、`web.sensitive_file_probe` のヘッダ側の検査も「要求行と同じパスの X-Original-URL」を飛ばすようにした
  （前段プロキシの後ろでは `/.env` を直接叩いた要求にも `route_override` タグと重複した `matches` が付いていた）。判定は
  `web_common.differing_override_paths()` に寄せ、`web.route_override` と共有。
- （#147）初版は要求行と同じパスの `X-Original-URL` を low にしていたが、良性 fixture「app custom headers」（前段プロキシが付ける形）で落ちたので鳴らさないようにした。

## 担当外の変更

- `backend/src/tokiwa/config.py`: `WebDetectionSettings` に `header_count_low` / `header_count_medium` を追加（所有範囲）。
- `backend/tests/detect/test_web_signatures.py`: `EXPECTED_IDS` に新しい検知器 ID、`gate_recorded`（Gate の記録を読むので fixture でなく
  test_web_anomaly.py で検査する）を除外集合に追加。`fixtures/web_attacks.json` に #147 の 3 件。
- `backend/src/tokiwa/detect/web_common.py`（所有範囲の該当部分）: `ROUTE_OVERRIDE_HEADERS`・`override_path()`・`differing_override_paths()` を追加（他は不変）。
- `backend/src/tokiwa/detect/detectors/web_recon.py`（所有）: `SensitiveFileProbeDetector.scan_overrides()`。要求行だけの要求の挙動は不変。
- `backend/src/tokiwa/api/routes/health.py`（#177 の degraded 表示のみ所有）: `system_checks()` と認証時の `checks`。未認証の分岐は不変。
- `backend/src/tokiwa/detect/sigma/loader.py`（読み込み件数の公開のみ所有）: `file_rules_found` / `file_rules_invalid` / `health()`、
  `load_file_rules()` で件数を数えて 0 件なら ERROR。読み込みのロジックは不変。
- `backend/tests/api/test_exposure.py`（http-hardening レーンのテスト）: `test_health_hides_version_from_anonymous_callers` の
  ログイン時の完全一致の 1 行を「status・version が一致 + `checks.sigma.status == "ok"`」に変更（未認証・不正トークン・API トークンの
  完全一致はそのまま）。
- `backend/tests/api/test_health_checks.py`（新規。viewer を作る `tests/api/conftest.py` のフィクスチャを使うため tests/api に置いた）。
- `docs/api-contract.md`: `/health` の行。`docs/detection/sigma.md`: 1 項目追加。`docs/wiki/Troubleshooting*.md`（4 言語）: 1 項目追加。

## 見送った依頼（gate-capture レーンの NOTES にあったもの）

- `gate:client_ip_header`（クライアントが `X-Real-IP` / `CF-Connecting-IP` 等を自分で付けた。#138 推奨 (4)）のシグナル化: このレーンの担当
  （#140 #141 #147 #150 #177）に入っておらず、Cloudflare 等の背後に Gate を置くと全要求に付くので、そのままでは誤検知の嵐になる。
  前段の信頼設定（`gate.trusted_proxies` 相当）と組で設計すべきなので見送り。#138 は gate-capture レーンで完全扱い。
- `web_common.INJECTABLE_HEADERS` に `cf-connecting-ip`・`x-cluster-client-ip`・`fastly-client-ip` が無い件: #53 以降これらは
  `header_custom` として注入系の検知器が検査するので、検査漏れは無い（`header` との違いはトラバーサルの単発 `../` を見ない程度）。

## 他レーンへの依頼

- **gate（#140）**: `gate.header_count` を捕捉を打ち切ったときだけでなく、ヘッダ行数がある程度（例 32）を超えたら常に付けてほしい。
  同じ名前を 90 回繰り返した要求は、名前 1 つ・連結 8192 文字未満なら打ち切りにならず、`header_order` も同名 2 回までなので、
  検知側からは行数が分からない（100 行を超えれば 431 + `gate:too_many_headers` で拾える）。
- **gate（#141）**: `gate:req_encoding_unknown` のときも、捕捉した生の先頭がテキストに見えるなら（`looks_textual`）本文として記録して
  ほしい。`Content-Encoding: br` を付けた **平文** の SQLi を、符号化を無視して生のまま読むアプリ（要求ボディを展開しない FastAPI 等）に
  送ると、アプリは平文を処理するのにイベントには本文が無い（`web.uninspectable_body` は鳴るが中身のクラスは分からない）。
  `decode_failed` の場合は既にそうしている（`capture.py` の `body.status != "unknown"`）。

- **frontend（#177）**: `AppShell.tsx` の `SystemStatus` は `/health` の `status` を見ずに緑の点を出している。`status === "degraded"` の
  ときに警告色と「Sigma ルール未読込」等の表示（`checks.sigma` の `missing_dirs` / `file_rules_found`。admin には `missing_dir_paths`）を
  出してほしい。応答の型は `{status, version, checks?: {sigma: {...}}}`（`frontend/src/api/types.ts` には型が無く、AppShell 内のインライン型）。

## 未検証事項

- （#140）正規のブラウザ + CDN + ロードバランサでのヘッダ行数は見積もり（実トラフィックで未計測）。
- （#141）br / zstd の要求ボディを送る正規クライアントがどれだけあるか（ブラウザは要求ボディを圧縮しない。SDK・モバイルアプリは
  gzip が中心という一般的な理解に基づく）は未確認。どの上流が br の要求ボディを展開するかも未確認（gate-capture レーンの `TODO(verify)`）。
- （#147）`X-Original-URL` を元の URL として付ける前段プロキシの具体例（IIS ARR・Azure App Service・nginx の設定例）は一般的な知識に基づき、
  一次資料で確認していない。
- （#150）ASCII の隣だけを見る文脈判定は、ペルシア語・インド系文字・絵文字の一般的な使い方に基づく。実際の多言語サイトのパスでの
  誤検知率は未計測（良性 fixture と L16 コーパスのみ）。
