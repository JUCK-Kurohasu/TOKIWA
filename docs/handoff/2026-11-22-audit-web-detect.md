# 2026-11-22 監査対応レーン: web-detect（系統 B「Web 検知」の工数 S）

担当 Issue（この順）: #51 → #52 → #53 → #89 → #76 → #166 + #173。
指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`（#51=L05-04, #52=L05-05, #53=L05-06, #89=L05-07, #76=L05-11,
#166=L16-02, #173=L16-05）。再現は `docs/audit/2026-11/repro/L05/`（matrix.py / t_fpsev.py）と `repro/L16/pass2/`（良性コーパスの全パイプライン再生）。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #51 | 完全 | `detect/web_common.py`: 構造の上限（JSON リーフ・深さ・multipart パート・パラメータ・Cookie・ヘッダ）を超えた分を捨てず、NUL 区切りで 1 つの `(overflow)` ターゲットにまとめて検査。JSON キーを `(json keys)` ターゲットとして検査（キーの絞り込みはしない: `rO0AB…` や内部 IP のように英数字だけのペイロードもあるため）。JSON の走査を反復化（深いネストでもスタックを使わない）。上限到達を `HttpView.truncated` に記録し、`web.*` 署名アラートの `details.inspection_truncated` とタグ `inspection-truncated` へ。上限を `detection.web.max_params / max_headers / max_json_leaves / max_json_depth / max_multipart_parts / max_decode_rounds` で設定可能に（既定は従来値）。新検知器 `web.inspection_evasion`（low, `detect/detectors/web_evasion.py`）: 上限の手前が詰め物（同一文字 90% 以上・空/同値のダミー要素 90% 以上）のときだけ発報（上限到達だけでは鳴らさない）。テスト `tests/detect/test_web_limits.py`。docs/detection/web.md §1.2.1・§4、wiki Configuration ×4 | 29e21a0 |
| #52 | 完全 | `web_common.content_type_params()`: Content-Type を `;` 区切りの `name=value` として解析（名前は完全一致・大小無視、値は大小保持、引用符・バックスラッシュエスケープ対応）。前方一致の `_BOUNDARY` 正規表現を廃止。`boundary` が複数（値が違う）なら全候補で分割して検査し、`web.inspection_evasion` に `multipart_boundary_ambiguous`。どの候補でも分割できなければ `None` を返しボディ全体を `body` として検査（以前は空リストで `body_raw` にしか入らなかった）。テスト `tests/detect/test_web_multipart.py`。docs/detection/web.md §1.2.2 | (このコミット) |
| #53 | 未着手 | | |
| #89 | 未着手 | | |
| #76 | 未着手 | | |
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

## 既定動作の変更

- **#51**: JSON ボディのキーが検査対象になった（`param=(json keys)`）。構造の上限を超えた要素も検査されるので、以前は
  黙って素通りしていた大きな JSON / multipart / Cookie / ヘッダ群でも `web.*` が鳴りうる。良性コーパス（L16, 6,855 イベント）と
  良性 fixture では変化なし（アラート 42 件のまま）。新検知器 `web.inspection_evasion`（low）。

## 失敗した試み

## 担当外の変更

## 他レーンへの依頼

## 未検証事項

- **#52**: `boundary` パラメータが重複したときにどちらを採るか（Starlette / python-multipart、Werkzeug、PHP、Node の busboy 等）は
  一次情報で確認していない（`TODO(verify)`）。TOKIWA は全候補で分割するので、どちらが採られても検査は漏れない。
  RFC 2231 の分割パラメータ（`boundary*0=`）を組み立てるパーサーがあれば、そこは見えない。

- **#51**: `sensor_body`（センサーが先頭だけ捕捉）は `request_body_size`（バイト）と捕捉文字列の UTF-8 長の比較による概算。
  Gate のマスキングで長さが変わると誤判定しうる（タグ・details だけで、アラートにはしない）。

- 既知の不安定テスト: `tests/deception/test_deception_variants.py::test_canary_header_with_unknown_value_is_an_attempt[typo]`
  がまれに落ちる（テスト自体の問題。統合担当が上流 852caf6 で修正済み。このレーンの変更とは無関係）。
