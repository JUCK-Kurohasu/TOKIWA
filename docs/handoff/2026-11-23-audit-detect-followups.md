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
| #140 | 部分（推奨 (1)(3)(4) は gate-capture レーンで完了。(2) の「異常なヘッダ数をシグナルに」は実装したが、**41〜64 行は low**（推奨の例は「>40 で medium」）。理由は要判断 1） | 新検知器 `web.header_anomaly`（`category=anomaly`, T1190）。指標: `header_anomaly.count`（ヘッダ行数 > `detection.web.header_count_low`（既定 40）で low、> `header_count_medium`（既定 64）で medium）、`header_anomaly.capture_dropped`（medium: Gate が 64 名に収めきれず記録しなかった行がある = label `gate.headers_dropped`）、`header_anomaly.rejected`（medium: `gate:too_many_headers` = 431。同名 101 行のように件数ラベルが付かない場合もこれで拾う）、`header_anomaly.duplicate_framing`（medium: Host / Content-Length / Transfer-Encoding の重複）、`header_anomaly.duplicate`（low: その他の非リストヘッダの重複 = `gate.duplicate_headers`）。ヘッダ行数は `gate.header_count`（Gate が捕捉を打ち切ったときだけ付く実数）、無ければ `max(len(headers), len(header_order))`。Cookie の連結が 8192 文字を超えただけ（`gate.headers_clipped`）では鳴らさない。`details` に `signatures`・`location`・`param` を入れて誤検知マーク（#166）が指標単位で効くように。fingerprint `rule|ip|最も重い指標`。テスト: 70 個のパディング → medium・件数 78・未記録 14、48 行 → low、Client Hints + CDN ヘッダ + 分割 Cookie（20 行・clipped）→ 無音、しきい値の設定、431、Host 重複 → medium・UA 重複 → low、DECEPTION 種別のコピーでは重複発報しない。docs/detection/web.md §2.1・§4、wiki Configuration ×4 | （このコミット） |

## 要判断

1. **#140 のしきい値**: 推奨は「>40 で medium」だが、Client Hints を全部要求するサイト（`Accept-CH` で `sec-ch-ua-arch` 等 10 個前後）を
   CDN（cf-ray・cf-ipcountry・cdn-loop・x-forwarded-for 等）と ALB（x-amzn-trace-id・x-forwarded-port）の後ろで受けると、正規のブラウザでも
   40 行前後になりうる（行数は各ヘッダの一般的な付与状況からの見積もりで、実測ではない）。そこで「41〜64 行 = low、Gate が記録しきれない
   （64 名超）・431・65 行超 = medium」にした。low は LLM トリアージ・通知に乗らない（インシデントの起点にはなる）。推奨どおりにするなら
   `detection.web.header_count_medium: 40`。統合担当は #140 を Closes にせず Refs のままにするか、この判断を受け入れて Closes にするかを決める。

## 送信元 IP の扱い（遮断提案との関係）

- ルールベースのトリアージ（`triage/fallback.py`）が対処（block_ip / rate_limit）を提案するのは **high 以上** だけ。このレーンの検知器は
  すべて low / medium なので、単独では遮断提案の根拠にならない。medium は LLM トリアージ（`triage.min_severity_for_llm` 既定 medium）に乗り、
  実 LLM が対処を推奨しうるが、提案は人間承認が既定（自動承認は第 2 弾の `response.auto_approve_withheld` 等の条件付き）。
- #140: ヘッダ数・重複は送信元が実際に送ったもの（他人の IP を装えない）。送信元 IP は Gate の判定値（信頼設定時は XFF の右端）。

## 既定動作の変更

- （#140）新しい検知器 `web.header_anomaly` が既定で有効。ヘッダ行 41 以上の要求で low、65 以上・Gate が記録しきれない・431・Host /
  Content-Length の重複で medium のアラートが出る（以前は何も出なかった）。`detection.disabled_detectors: ["web.header_anomaly"]` で無効、
  しきい値は `detection.web.header_count_low` / `header_count_medium`（0 でその段を無効）。

## 失敗した試み

## 担当外の変更

- `backend/src/tokiwa/config.py`: `WebDetectionSettings` に `header_count_low` / `header_count_medium` を追加（所有範囲）。
- `backend/tests/detect/test_web_signatures.py`: `EXPECTED_IDS` に新しい検知器 ID、`gate_recorded`（Gate の記録を読むので fixture でなく
  test_web_anomaly.py で検査する）を除外集合に追加。

## 他レーンへの依頼

- **gate（#140）**: `gate.header_count` を捕捉を打ち切ったときだけでなく、ヘッダ行数がある程度（例 32）を超えたら常に付けてほしい。
  同じ名前を 90 回繰り返した要求は、名前 1 つ・連結 8192 文字未満なら打ち切りにならず、`header_order` も同名 2 回までなので、
  検知側からは行数が分からない（100 行を超えれば 431 + `gate:too_many_headers` で拾える）。

## 未検証事項

- （#140）正規のブラウザ + CDN + ロードバランサでのヘッダ行数は見積もり（実トラフィックで未計測）。
