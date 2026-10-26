# Wave 2 / E: feature-gaps — 第 1 波で残った機能

## 担当範囲
`gate/capture.py`, `gate/proxy.py`, `detect/detectors/web_spray.py`（新規）, `respond/**`, `deception/service.py`,
`correlate/**`, 各テスト。`config.py` は `ResponseSettings` / `DeceptionSettings` セクションへの追加のみ。

## 要件
1. **Gate の捕捉強化**（detect-web からの依頼）: `next-action`, `rsc`, `x-http-method-override` ヘッダを透過・記録、
   `response_content_type` を必ず記録（.env の実漏えいと SPA の 200 を区別するため）、正規化前の生パスを記録。
2. **多 IP パスワードスプレー検知**（新検知器 `web.password_spray`）: 同一ユーザー名・同一ログインパスへの失敗が多数の送信元から
   短時間に集中するパターン。あわせて「多数の失敗の後の成功」を高重大度で。
3. **二者承認**（設定 `response.require_second_approver`、既定 OFF）: ON のとき提案者と承認者が同一なら拒否、LLM/ルール提案は
   人間 1 名の承認で可など、ポリシーを docs/response.md に明記。テストで保証。
4. **デセプション資産のシード関数**: `deception.service.seed_defaults(session)`（冪等）を公開し、評価ハーネス（B 担当）から呼べるように。
5. **KEV ブーストの拡張**（correlate）: アラートが CVE を直接参照しなくても、対象ホスト → `vuln_matches` → KEV の経路で引き上げ。
6. Gate の優先度: 完全一致のデコイ経路を前方一致より優先、デコイ応答 1 件につきデセプションイベント 1 件（二重計上の解消）。

## 受け入れ基準
- 各項目に陽性/陰性テスト。既存テストを壊さない。docs（gate.md / response.md / deception.md / detection/web.md）を更新。
