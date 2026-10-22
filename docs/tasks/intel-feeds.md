# タスク: intel-feeds — 脆弱性・脅威フィードの取り込み

## 目的
FR-08 + ユーザー要望「インターネット上を定期的に検索し 0day や脆弱性情報を分析・提案」のうち、
**構造化フィードの定期取得と統合** を担う（LLM 分析は intel-advisor）。

## 担当範囲
- `backend/src/tokiwa/intel/sources/`（kev.py, epss.py, nvd.py, osv.py, jvn.py, ghsa.py, rss.py）
- `backend/src/tokiwa/intel/store.py`（upsert/マージ）, `backend/src/tokiwa/intel/sync.py`（同期ジョブ・状態管理）,
  `backend/src/tokiwa/intel/cli.py`（`tokiwa intel sync|status|show CVE-...`）
- `backend/src/tokiwa/api/routes/intel.py`（/intel/vulns, /intel/vulns/{id}, /intel/news, /intel/sources, /intel/sync）
- `backend/tests/intel/`, `backend/tests/fixtures/intel/<source>/`（各 API の実レスポンス形状に沿った小さな fixture）

## 要件
1. 各ソース（`IntelSource` を継承、`@register_source`）。**API 仕様は実装前に公式ドキュメントで確認**（WebFetch 可）し、
   URL・パラメータ・レート制限・ライセンス/利用条件を docstring に出典付きで書く。サンドボックスからは実 API に
   出られないことが多いので、テストは fixture + `httpx.MockTransport`。
   - CISA KEV: JSON フィード（全件、`dateAdded` で差分）→ kev フラグ・期限・ランサム利用
   - FIRST EPSS: CVE 群に対するスコア/パーセンタイル（KEV・NVD で得た CVE をまとめて問い合わせ、バッチ上限に注意）
   - NVD CVE API 2.0: `lastModStartDate/EndDate` で差分（最大期間制約あり）、API キー任意、レート制限を尊重
     （キーなしは間隔を空ける）。CVSS v3.1/v4.0、CWE、CPE configurations → `affected`
   - OSV: 資産のソフトウェア（ecosystem+package+version）に対する `querybatch`（資産が無ければスキップ）
   - JVN iPedia（MyJVN API）: 日本語の脆弱性概要（`getVulnOverviewList` 等）。JVNDB ID と CVE の対応を aliases に
   - GitHub Security Advisories: REST `/advisories`（トークン任意）→ GHSA と CVE エイリアス
   - RSS/Atom: 設定のフィード（JPCERT/CC, IPA, CISA, The Hacker News, BleepingComputer 等）→ `intel_items`。
     本文から CVE ID を抽出して `vuln_ids`。`url_hash` で重複排除。
2. `store.upsert_vulns()`: ID 正規化（CVE を主キー、GHSA/JVNDB は aliases に。CVE が無いものは自 ID で）。
   ソースごとに担当フィールドを持ち、より信頼できる値で上書き（NVD の CVSS > GHSA の severity 等。方針を docstring に）。
   `sources` に追記。KEV 新規追加・EPSS 急上昇は bus `intel.vuln_updated` を publish（advisor が購読）。
3. `sync.py`: `@periodic("intel.sync", every=intel.sync_interval_minutes)`。ソースごとの最終同期時刻・エラー・件数を
   `settings_kv["intel.sync_state"]` に保存。1 ソースの失敗は他に影響させない。手動同期 API はバックグラウンド実行。
4. API（docs/api-contract.md「インテル」の担当分）。`/intel/vulns` は KEV/EPSS/CVSS/資産一致（`vuln_matches` 存在）で
   絞り込み、既定ソートは「KEV → EPSS → CVSS → modified」。

## 受け入れ基準
- 全ソースの fixture パーステスト、マージ規則のテスト、差分取得のパラメータ生成テスト、同期ジョブのエラー分離テスト。
- 同期後 `/intel/vulns?kev=true` で KEV のみが返る統合テスト。
