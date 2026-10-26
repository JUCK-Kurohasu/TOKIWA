# 2026-10-22 intel-feeds 作業ログ

担当: intel-feeds（docs/tasks/intel-feeds.md）。ブランチ `worktree-agent-a210c7208ef9de27a`
（作業開始時にスケルトン `c4881e1` へ fast-forward してから着手）。

## やったこと

| ファイル | 内容 |
|---|---|
| `backend/src/tokiwa/intel/sources/_common.py` | ID 正規化、CVE 抽出、日付、CPE 2.2→2.3、HTTP（リトライ・Retry-After・サイズ上限・差し替え可能な sleep） |
| `sources/kev.py` | CISA KEV JSON（全件 + `If-Modified-Since`）。ransomware: Known→True / Unknown→False |
| `sources/epss.py` | FIRST EPSS。`cve` パラメータ 2000 文字・1 回 100 件でバッチ。対象 CVE は sync が `prepare()` で渡す |
| `sources/nvd.py` | NVD CVE API 2.0。`lastModStartDate/EndDate`（≤120 日に分割、10 分重複）、`resultsPerPage=2000` ページング、`apiKey` ヘッダ、待機 6 s（キーなし）/ 0.8 s（キーあり）、403/429/5xx は 30 s から指数バックオフ |
| `sources/ghsa.py` | GitHub `/advisories`（reviewed、`updated>=日付`、Link ヘッダでページング、トークン任意）。エコシステムを OSV 名に変換 |
| `sources/osv.py` | 資産ソフトウェア（ecosystem+product+version）だけを `querybatch`（≤1000）→ `/v1/vulns/{id}`。資産なしならスキップ |
| `sources/jvn.py` | MyJVN `getVulnOverviewList`（hnd / JVNRSS 3.2）。日付フィルタは JST、DTD 付き XML は拒否 |
| `sources/rss.py` | feedparser で RSS 1.0/2.0/Atom。`source=rss:<host>`、本文から CVE 抽出、HTML 除去 |
| `intel/store.py` | マージ（下記）、`upsert_items`（url_hash 重複排除）、一覧クエリ、EPSS 対象・資産パッケージの取得 |
| `intel/sync.py` | `@periodic("intel.sync")`、ソースごとの状態を `settings_kv["intel.sync_state"]`、エラー分離、手動同期のバックグラウンド実行 |
| `intel/cli.py` | `tokiwa intel sync [--source X] / status / show <id> [--json]` |
| `api/routes/intel.py` | `/intel/vulns`, `/intel/vulns/{id}`（エイリアスでも引ける）, `/intel/news`, `/intel/sources`, `POST /intel/sync`（監査ログに記録） |
| `tests/intel/*`, `tests/fixtures/intel/*` | 37 テスト中 29 件が intel（パース・パラメータ生成・マージ規則・同期のエラー分離・API 統合・CLI） |

### マージ方針（`store.FIELD_PRECEDENCE`、調整はここ）
- CVE を主キー。GHSA/JVNDB/OSV ID は aliases。CVE が無ければ自 ID。
  GHSA で先に保存→後から CVE 付与されたら CVE 行に畳み込み、`vuln_matches.vuln_id` も付け替え。
- CVSS/severity: nvd > ghsa > osv > jvn > research ／ description: nvd > ghsa > osv > kev > jvn ／
  title: kev > ghsa > osv > nvd > jvn ／ kev*: kev > nvd ／ epss*: epss のみ。
  どのソースが値を入れたかを `data["_prov"]` に記録し、同順位以上のソースだけが上書きできる。
- severity が無いレコードは自身の CVSS スコアから導出（スコアと重大度の組が別ソースにならないように）。
- `affected` は必ず `product` を持つ（CPE しか無い既存エントリは CPE から導出、導出不能なら破棄）。
- バージョン範囲は `SoftwareItem` で表せないので `data` に原形のまま保存:
  `data.nvd.cpe_matches`（versionStart/EndIncluding/Excluding）、`data.ghsa.vulnerabilities`
  （vulnerable_version_range / first_patched_version）、`data.osv.affected`（ranges/versions）。

### イベント `intel.vuln_updated`
ペイロードは `VulnRecord`、`data.update_reasons` に `kev_added` / `epss_spike`（DB には保存しない）。
- `kev_added`: kev が新たに true になり、`kev_date_added` が 14 日以内（初回の KEV 全件取り込みで ~1.5k 件
  流れるのを防ぐ）。
- `epss_spike`: 既知スコアが閾値（`intel.epss_alert_threshold`）を下から超えた、または閾値以上で +0.1 以上。
  初めて付いたスコアは基準が無いので対象外。1 回の upsert で最大 200 件。

## 調整できるところ
`nvd.py`（`CVSS_PREFERENCE`, 待機秒, `MAX_PAGES_PER_RUN`）、`ghsa.py`（ページ上限）、`epss.py`（バッチ・待機）、
`store.py`（`FIELD_PRECEDENCE`, `KEV_RECENT_DAYS`, `EPSS_SPIKE_DELTA`, 上限値）、`jvn.py`（待機・ページ上限）。
config.py は intel-advisor と共有のため触っていない。必要なら `IntelSettings` に昇格させる。

## TODO(verify)（サンドボックスから公式ドキュメントに直接アクセスできず、Web 検索の抜粋で確認した範囲）
確認できた: NVD のレート制限（5/30 s・50/30 s）、120 日上限、2000 件/ページ、`apiKey` ヘッダ、利用規約の表示文言 /
EPSS の `cve` 2000 文字上限・既定 limit 100・値が文字列 / KEV のフィールド名 / OSV querybatch ≤1000・id+modified のみ /
GHSA の `type`・`per_page` 最大 100・`sort` 値・`cvss` 非推奨（2025-10-01 削除告知）。
未確認:
1. GHSA の `updated` フィルタ名と意味（`modified` の方が適切かもしれない）。
2. MyJVN の日付パラメータ名（`datePublishedStart{Y,M,D}` 等）、`rangeDate*` との組み合わせ、`status:Status` の属性名。
   **IPA が 2026 年 4 月以降に JVN iPedia/MyJVN を刷新（JSON フィード・CVSS v4・レート制限）と告知**。
   旧 hnd フィードが廃止されていたら `jvn.py` の取得/パースを差し替える（VulnRecord への写像は流用可）。
3. EPSS の公式レート制限・`limit` の最大値・帰属表示の文言。
4. OSV のレート制限/フェアユース、データライセンス表記。
5. KEV ミラーのライセンス（CC0 と認識）と CDN が `If-Modified-Since` を返すか。
6. KEV から削除されたエントリの扱い（現状は kev フラグを落とさない）。

## 既知の制約
- GHSA はトークン無しだと 3 ページ（300 件）まで。新しい順に読むので一括再レビュー日は古い更新を取りこぼす
  （警告ログ）。`intel.github_token` 設定で 20 ページ。
- 非 CVE レコード → CVE 行への逆引きは aliases の LIKE 検索（件数が増えたら JSON インデックスを検討）。
- `/intel/sources` の `records` は「直近の実行で取得した件数」（DB 内の総数ではない）。

## 他モジュールへの依頼
- intel-advisor（matcher）: バージョン範囲は上記 `data.*` のキーにある。`intel.vuln_updated` を購読可。
- 統合担当: `bus.py` の docstring にトピック `intel.vuln_updated`（VulnRecord）を追記してほしい
  （共有ファイルのため未編集。architecture.md §6 と api-contract.md のインテル行は最小限更新済み）。
- frontend-intel: `/intel/sources` の追加フィールド（`attribution` に NVD の表示義務文言など）を UI に出してほしい。
  NVD 利用規約は「This product uses the NVD API but is not endorsed or certified by the NVD.」の表示を求めている。

## 次の一手
1. 実ネットワークのある環境で `uv run tokiwa intel sync` を各ソース単独で実行し、上記 TODO(verify) を潰す。
2. JVN の新 API 仕様を確認して `jvn.py` を追従。
3. 必要に応じてチューニング値を `IntelSettings` に昇格。
