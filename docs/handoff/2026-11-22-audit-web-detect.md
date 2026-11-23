# 2026-11-22 監査対応レーン: web-detect（系統 B「Web 検知」の工数 S）

担当 Issue（この順）: #51 → #52 → #53 → #89 → #76 → #166 + #173。
指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`（#51=L05-04, #52=L05-05, #53=L05-06, #89=L05-07, #76=L05-11,
#166=L16-02, #173=L16-05）。再現は `docs/audit/2026-11/repro/L05/`（matrix.py / t_fpsev.py）と `repro/L16/pass2/`（良性コーパスの全パイプライン再生）。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #51 | 完全 | `detect/web_common.py`: 構造の上限（JSON リーフ・深さ・multipart パート・パラメータ・Cookie・ヘッダ）を超えた分を捨てず、NUL 区切りで 1 つの `(overflow)` ターゲットにまとめて検査。JSON キーを `(json keys)` ターゲットとして検査（キーの絞り込みはしない: `rO0AB…` や内部 IP のように英数字だけのペイロードもあるため）。JSON の走査を反復化（深いネストでもスタックを使わない）。上限到達を `HttpView.truncated` に記録し、`web.*` 署名アラートの `details.inspection_truncated` とタグ `inspection-truncated` へ。上限を `detection.web.max_params / max_headers / max_json_leaves / max_json_depth / max_multipart_parts / max_decode_rounds` で設定可能に（既定は従来値）。新検知器 `web.inspection_evasion`（low, `detect/detectors/web_evasion.py`）: 上限の手前が詰め物（同一文字 90% 以上・空/同値のダミー要素 90% 以上）のときだけ発報（上限到達だけでは鳴らさない）。テスト `tests/detect/test_web_limits.py`。docs/detection/web.md §1.2.1・§4、wiki Configuration ×4 | 29e21a0 |
| #52 | 完全 | `web_common.content_type_params()`: Content-Type を `;` 区切りの `name=value` として解析（名前は完全一致・大小無視、値は大小保持、引用符・バックスラッシュエスケープ対応）。前方一致の `_BOUNDARY` 正規表現を廃止。`boundary` が複数（値が違う）なら全候補で分割して検査し、`web.inspection_evasion` に `multipart_boundary_ambiguous`。どの候補でも分割できなければ `None` を返しボディ全体を `body` として検査（以前は空リストで `body_raw` にしか入らなかった）。テスト `tests/detect/test_web_multipart.py`。docs/detection/web.md §1.2.2 | a1460cb |
| #53 | 完全 | 許可リスト方式を反転: 既知の反射ヘッダ（`header`）とフレーミング系（`header_other` = Accept*・Sec-CH-*/Sec-Fetch-*・If-*・Cache-Control・Content-Type・traceparent/tracestate/baggage・X-Requested-With ほか `FRAMING_HEADERS`）以外のヘッダを新 location `header_custom` とし、`INJECTION_LOCATIONS` に追加（SQLi・XSS・コマンド注入・LFI・SSTI）。トラバーサルは `header_custom` だけ追加（Referer はブラウザ正規化済み URL で、`/etc/hosts` の解説ページ等が os_file に当たるため対象外）、単発の `../`（dotdot_single, medium）はヘッダでは見ない（`X-Return-To: ../orders` 等）。デシリアライズ・SSRF メタデータは全ヘッダ（`HEADER_LOCATIONS`）。件数は `max_headers`、長さは `max_inspect_chars`（#51 のあふれ・打ち切り記録が効く）。設定 `detection.web.inspect_custom_headers`（既定 true）・`extra_framing_headers`（末尾 `*` で前方一致）。RFI の include パラメータ判定で `(overflow)` / `(json keys)` を 1 つの値として扱わないよう修正。良性 fixture に実在形のカスタムヘッダ 36 個（Stripe-Signature, X-Hub-Signature-256, sec-ch-ua, baggage, JSON 値ヘッダ等）。テスト `tests/detect/test_web_headers.py`。docs/detection/web.md §1.2・§4、wiki Configuration ×4 | 82add43 |
| #89 | 完全（HTML 実体参照は「直す必要なし」と判断） | (1) URL 多重: デコード上限 3 → 8 ラウンド（安定したら止まるので通常の値のコストは不変。`max_decode_rounds`）。(2) base64: `query`/`body`/`cookie`/`header_custom` の値が base64/base64url（16 文字以上）でデコード結果が UTF-8・95% 以上表示可能なら `<名前>(base64)` を追加ターゲット化（1 要求 8 個まで。トークン・hex ID・JWT・バイナリは対象外をテスト）。(3) UTF-16 JSON: 交互 NUL パターン（先頭 256 文字で片側 90% 以上 NUL・もう片側 10% 以下）なら NUL を除去してから解析（ゼロ埋めバイナリは対象外）。(4) セミコロンなし実体参照: Python の `html.unescape` は既に `;` 省略を展開する。行列の取りこぼしは直後が 16 進数字（`&#x3dalert` → U+03DA）の場合で、仕様どおり貪欲に読むとブラウザでも壊れる形 = 行列の作り方の問題と判断（テストで挙動を固定、ブラウザ実機は未確認）。(5) %A0: 不正な UTF-8 単独バイトを U+FFFD ではなく Latin-1 に（surrogateescape → 0x80-0xFF）。NFKC で U+00A0 → 空白。(6) HPP: 同名パラメータ 2 回以上で `,` 連結した `<名前>(joined)`（ASP.NET の挙動。1 location 4 個まで）。L05 行列: url 4x / %a0 / base64 / UTF-16 / HPP の SQLi がすべて W に（残る `w` は HPP の cmdi: 分割位置でコマンドが壊れるため）。テスト `tests/detect/test_web_normalize.py`。docs/detection/web.md §1.1・§4、wiki Configuration ×4 | 9ee199f |
| #76 | 完全（fingerprint の path_key 化は不採用） | 3 案から「合流」を選択（理由は要判断）。新モジュール `detect/sigma/overlap.py`: 同梱 web ルール 14 本の Sigma id → ネイティブ検知器の対応表。`DetectionEngine.run()` でイベントごとに全検知器の後に適用: ネイティブが同じイベントで発報 → Sigma を落としネイティブに `details.corroborated_by` とタグ `sigma-corroborated`／ネイティブ有効だが沈黙 → Sigma を low に（`native_detector`・`native_verdict=silent`・`sigma_level_severity`、タグ `native-silent`）／ネイティブ無効 → ルールの level のまま。rules テーブル由来（利用者・LLM）のルールは対象外。L16 良性コーパス: アラート 42 → 31、mock LLM 82 → 64、提案 5 のまま。テスト `tests/sigma/test_sigma_overlap.py`（同梱 web ルール全件が対応表にあること・合流・無効時・沈黙時・利用者ルール）、`tests/sigma/test_sigma_api.py` の 2 テストはスキャナルール自身のアラート数を数えるため設定でネイティブ `web.scanner_ua` を無効化。docs/detection/sigma.md §5.1、web.md §5、wiki Web-UI ×4 | (このコミット) |
| #166 + #173 | 未着手 | | |

## 計測（ベースライン = 95343eb、worktree の rules/sigma を指すよう harness のパスだけ書き換えて実行）

- L05 matrix（9 クラス × 33 手法）: 監査時の `matrix.md` と同一（url 4x / base64 / UTF-16 / json 128 leaves / json key /
  xboundary / X-Tenant-Id / %A0 / HPP / 8192 文字後 が不発または Sigma のみ）。
- L16 良性コーパス（6,855 イベント）: アラート 42（critical 4 / high 19 / medium 17 / low 2）、インシデント 3、提案 5、mock LLM 82。

## 要判断

- **#51**: `max_inspect_chars`（既定 8192）以降の文字列は今も検査しない（CPU の上限）。「8200 文字の詰め物 + ペイロード」は
  `web.inspection_evasion`（low）だけが鳴り、ペイロードのクラス（SQLi 等）は分からない。末尾も検査する案（先頭 N/2 + 末尾 N/2）は
  中央に置かれると同じなので採らなかった。上限そのものを上げるかは性能とのトレードオフ（設定で可能）。
- **#51**: `web.inspection_evasion` を low にした。low は新規インシデントを作りうる（`NEW_INCIDENT_MIN_SEVERITY = low`）が、
  LLM トリアージ（既定 medium 以上）・通知（既定 high 以上）には乗らない。詰め物の判定は 16 個以上 / 1024 文字以上でだけ行う。

- **#53**: カスタムヘッダの検査を既定で有効にした（セキュリティ製品として安全側。`inspect_custom_headers=false` で旧動作）。
  誤検知の実測は良性 fixture（36 ヘッダ）と L16 コーパスのみ。社内固有のヘッダ（署名・暗号化済みトークン・検索 DSL を載せるもの）で
  鳴る場合は `extra_framing_headers` に足す運用。フレーミング系の一覧（`web_common.FRAMING_HEADERS`）は調整余地がある。

- **#76**: 3 案（同梱ルールの既定無効化 / level の一律引き下げ / ネイティブとの合流）のうち合流を選んだ。無効化はネイティブが
  取りこぼした変種への安全網（監査の行列で Sigma だけが拾っていた形）を失い、一律引き下げはネイティブを無効にした環境での
  フォールバックとしての重大度を失うため。「ネイティブ有効だが沈黙」を low にしたのは、ネイティブの誤検知抑制（単発 `../` 等）を
  Sigma 経由ですり抜けさせないため。ネイティブが見逃した本物の攻撃も low になる点はトレードオフ（low でも記録・インシデント化はされる）。
  推奨 (2) の「Sigma の fingerprint を path_key ベースに」は採らなかった: IP ローテーションによる件数増（監査の 200 件）は path_key では
  減らず、合流でほぼ解消するため。

## 既定動作の変更

- **#76**: 同梱 Sigma の web ルールが同じイベントで同じ種類の `web.*` と重複したら Sigma のアラートは作られない（ネイティブ側の
  `details.corroborated_by` に残る）。`web.*` が有効なのに沈黙したときの Sigma アラートは low。Sigma の rules API のヒット数
  （`hit_count`）は従来どおり数える（アラートの件数とは一致しなくなる）。

- **#53**: アプリ固有のヘッダ（`header` / `header_other` 以外）が SQLi・XSS・トラバーサル・コマンド注入・LFI の検査対象になった。
  アラートの `details.location` に新しい値 `header_custom` が出る。L16 コーパスではアラート数は不変（42）。
- **#89**: デコードの最大ラウンド 3 → 8、不正 UTF-8 バイトは Latin-1 として読む（`decoded` ビューの `%E9` が `é` になる。
  以前は U+FFFD）。base64 / HPP 連結 / UTF-16 の追加ターゲットで `param` に `(base64)` / `(joined)` の接尾辞が付くアラートが出うる。
  L16 コーパスではアラート数は不変（42）、良性 fixture も静か。

- **#51**: JSON ボディのキーが検査対象になった（`param=(json keys)`）。構造の上限を超えた要素も検査されるので、以前は
  黙って素通りしていた大きな JSON / multipart / Cookie / ヘッダ群でも `web.*` が鳴りうる。良性コーパス（L16, 6,855 イベント）と
  良性 fixture では変化なし（アラート 42 件のまま）。新検知器 `web.inspection_evasion`（low）。

## 失敗した試み

## 担当外の変更

- `backend/src/tokiwa/detect/engine.py`（#76）: `run()` でイベントごとの drafts を集め、`merge_native_overlap()` を 1 回呼ぶだけ
  （+6 行）。ロジックは所有モジュール `detect/sigma/overlap.py`。
- `backend/tests/sigma/test_sigma_api.py`（所有 `tests/sigma/` 内だが他レーンの API テスト）: 2 テストに `native_scanner_off()`
  （設定でネイティブ `web.scanner_ua` を無効化）を追加。

## 他レーンへの依頼

## 未検証事項

- **#89**: HPP の `,` 連結は ASP.NET の挙動として知られているもの（`TODO(verify)`: 一次資料で未確認。他のフレームワークの
  先勝ち / 後勝ちは個別の値として検査済み）。セミコロンなし数値文字参照の貪欲な解釈がブラウザでも同じかは実機未確認
  （WHATWG HTML の文字参照の状態機械に基づく判断）。MySQL が 0xA0 を空白として扱う点は監査の記述に依拠（一次資料未確認）。

- **#52**: `boundary` パラメータが重複したときにどちらを採るか（Starlette / python-multipart、Werkzeug、PHP、Node の busboy 等）は
  一次情報で確認していない（`TODO(verify)`）。TOKIWA は全候補で分割するので、どちらが採られても検査は漏れない。
  RFC 2231 の分割パラメータ（`boundary*0=`）を組み立てるパーサーがあれば、そこは見えない。

- **#51**: `sensor_body`（センサーが先頭だけ捕捉）は `request_body_size`（バイト）と捕捉文字列の UTF-8 長の比較による概算。
  Gate のマスキングで長さが変わると誤判定しうる（タグ・details だけで、アラートにはしない）。

- 既知の不安定テスト: `tests/deception/test_deception_variants.py::test_canary_header_with_unknown_value_is_an_attempt[typo]`
  がまれに落ちる（テスト自体の問題。統合担当が上流 852caf6 で修正済み。このレーンの変更とは無関係）。
