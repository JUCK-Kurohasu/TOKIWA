# タスク: intel-advisor — 資産照合・LLM 脆弱性アドバイザ・0day Web リサーチ

## 目的
「自分の環境に関係ある脆弱性はどれで、何をすべきか」を LLM で根拠付きに提案する。
加えて Claude のサーバーサイド Web 検索で、フィードに載る前の 0day / 悪用報告 / AI 攻撃キャンペーン情報を定期調査。

## 担当範囲
- `backend/src/tokiwa/intel/matcher.py`（資産ソフトウェア ↔ vulns.affected 照合）
- `backend/src/tokiwa/intel/advisor.py`（`AdvisoryAnalysis` 生成、Sigma 提案の検証と保存）
- `backend/src/tokiwa/intel/research.py`（定期 Web リサーチ → `ResearchReport`）
- `backend/src/tokiwa/intel/prompts.py`
- `backend/src/tokiwa/enrich/asset_mapper.py`（イベントの dest IP/host → asset_id）
- `backend/src/tokiwa/detect/detectors/vuln_exposure.py`（KEV/高 EPSS × 資産一致 → vuln_exposure アラート）
- `backend/src/tokiwa/api/routes/assets.py`, `backend/src/tokiwa/api/routes/intel_advice.py`
  （/intel/matches, /intel/advisories*, /intel/research*）
- `backend/tests/intel_advisor/`

## 要件
1. matcher: CPE 2.3 の vendor/product/version 比較（ワイルドカード・バージョン範囲 `versionStartIncluding` 等）、
   CPE が無い場合は正規化した製品名の一致 + バージョン範囲（`packaging.version` 互換の比較、失敗時は低信頼度）。
   `confidence` と `reason` を必ず残す。結果を `vuln_matches` に upsert、新規は bus `intel.vuln_matched`。
   トリガ: 資産の作成/更新、`intel.vuln_updated`、定期ジョブ。
2. advisor: 優先対象 = KEV 該当 ∧ 資産一致 → 即時、EPSS ≥ `epss_alert_threshold` ∧ 一致 → 高、その他一致 → 通常。
   LLM 入力 = 脆弱性情報（description/CVSS/EPSS/KEV/references）+ 該当資産（id/name/software/criticality）
   （**外部テキストも非信頼データとして `untrusted_block`**）。deep tier。出力 `AdvisoryAnalysis`。
   `affected_assets` は入力した資産 ID のみ許可（それ以外は除外）。`proposed_rules` は sigma モジュールの
   バリデータ（`tokiwa.detect.sigma` が無ければ YAML 構文チェックのみ）で検証し、合格したものだけ `rules` に
   `status=proposed, source=llm` で保存。LLM 不在時は定型テンプレートの Advisory（ルール由来）を作る。
   重複生成を防ぐ（同じ vuln + 資産集合で 7 日以内に生成済みならスキップ）。
3. research: `@periodic("intel.research", every=research_interval_hours)`（`research_enabled` かつ LLM 利用可能時）。
   各 `research_topics` + 資産インベントリの製品名を文脈に、`StructuredRequest(web_search=True,
   allowed_domains=信頼できる情報源の既定リスト（NVD, CISA, JPCERT, IPA, ベンダー公式, 主要セキュリティメディア）)`。
   出力 `ResearchOutput` を `research_reports` に保存。findings の CVE で vulns に無いものは `sources=["research"]`
   の最小レコードとして登録（後続フィードで上書きされる）。高関連の finding は Advisory 候補に。
4. vuln_exposure 検知器: イベントの asset_id に open な KEV/高 EPSS マッチがあり、かつそのイベントが攻撃系アラートを
   伴う場合（同バッチの drafts を `ctx.scratch` で参照するか、alert.created 購読で処理）に critical へ。
   シンプルな実装で良いが二重アラートを避ける。
5. API（docs/api-contract.md「ホスト・資産」の assets 部分、「インテル」の matches/advisories/research）。

## 受け入れ基準
- matcher の単体テスト（CPE 範囲・名前一致・誤一致回避）。mock LLM で advisor/research の E2E（DB 保存、
  不正な asset ID の除外、Sigma 提案の検証/却下）。research で web_search=True が gateway に渡ること。
