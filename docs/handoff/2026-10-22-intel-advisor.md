# 2026-10-22 intel-advisor 作業ログ

担当: docs/tasks/intel-advisor.md（資産照合・LLM 脆弱性アドバイザ・0day Web リサーチ）
ブランチ: `worktree-agent-a1340f7f492a4d42f`（作成時は骨格コミット `c4881e1` より前だったため、まず `c4881e1` へ fast-forward した）

## やったこと

| ファイル | 内容 |
|---|---|
| `backend/src/tokiwa/intel/matcher.py` | CPE 2.3/2.2 照合 + 名前フォールバック（vendor/ecosystem 一致・別名表・汎用名ストップリスト）。バージョン範囲は NVD（`versionStart/End*`）、OSV（`introduced/fixed/last_affected`, `ranges[].events`, `versions`）、制約式（`>=1.0,<1.2 \|\| ...`）、glob に対応。自前の比較器 `compare_versions`（epoch・pre/post・OpenSSL の文字・distro revision）。`vuln_matches` へ upsert（confidence + reason 必須）、新規は `intel.vuln_matched` を publish、一致しなくなった open は `[auto-closed]` で mitigated にし、再一致で reopen。アナリストが付けた状態は上書きしない。トリガ: 資産 API（バックグラウンド）、`intel.vuln_updated`、定期ジョブ `intel.match` |
| `backend/src/tokiwa/intel/advisor.py` | 優先度の下限をルールで決める（KEV∧一致=P1、EPSS≥閾値∧一致=P2、一致=P3、不一致=P4）。LLM の提案と比べてより緊急な方を採用し、LLM による引き下げは不可。deep tier で `AdvisoryAnalysis`。`affected_assets` は入力 ID のみ、`references` は元レコードか信頼ドメインのみ。Sigma 提案は `tokiwa.detect.sigma.validate_rule` で検証し（無ければ YAML 構造チェック）、合格分だけ `rules(status=proposed, source=llm)` に保存し監査ログ `rule.proposed` を残す。LLM 失敗・Mock 時はテンプレート。同じ脆弱性 + 同じ資産集合なら 7 日間は再生成しない（より緊急になった場合と force 指定時は除く）。メタ情報は `analysis._meta`（API 応答からは除外） |
| `backend/src/tokiwa/intel/research.py` | `@periodic("intel.research")`（`research_enabled` かつ非 Mock プロバイダ時のみ）。`StructuredRequest(web_search=True, allowed_domains=DEFAULT_TRUSTED_DOMAINS)`。CVE 形式チェック、出典 URL を許可ドメインに限定、vulns に無い CVE は `sources=["research"]` の最小レコードで登録（既存は触らない）。関連の高い finding は Advisory 候補にする（一致済み CVE は advisor へ、資産の製品名を含む finding は `[Research]` アドバイザリへ）。生成数は 1 回あたり上限あり |
| `backend/src/tokiwa/intel/prompts.py` | `intel.advisory@1` / `intel.research@1`。外部テキストはすべて `untrusted_block`、system に `UNTRUSTED_DATA_POLICY` |
| `backend/src/tokiwa/enrich/asset_mapper.py` | 宛先 IP / hostname / Host ヘッダ / host / outbound の送信元から `event.asset_id` を付与。CIDR は最長一致。60 秒 TTL、資産 API が `invalidate_asset_index()` を呼ぶ |
| `backend/src/tokiwa/detect/detectors/vuln_exposure.py` | `alert.created` を購読。攻撃系カテゴリ（exploit_attempt / credential_attack / ai_agent / prompt_injection / ids）の証拠イベントの資産に、open な KEV/高 EPSS 一致（confidence ≥ 0.5）があれば critical アラートを出す。fingerprint は資産 + 送信元 IP で、エンジンの重複排除に乗る。検知器は登録済みで /detectors から無効化できる（`accepts()` は False） |
| `backend/src/tokiwa/api/routes/assets.py`, `intel_advice.py` | api-contract の該当部分 + `POST /intel/matches/rescan`, `GET /intel/research/{id}`、フィルタ追加（docs/api-contract.md 更新済み） |
| `backend/tests/intel_advisor/` | 75 テスト（matcher 単体・DB、advisor E2E、research E2E、API・権限、asset mapper、vuln_exposure） |

## 現在の状態
- `uv run pytest -q` 緑。`ruff check` / `ruff format --check` 緑。新規ファイルは `mypy` も通過。
- `tokiwa.detect.sigma` が未マージのため、テストは YAML フォールバック経路と「バリデータが使われること」（monkeypatch）の両方を検証している。テストの正例ルールは実バリデータでも通る想定の標準的な Sigma。

## 設計判断・調整できる箇所
- confidence の値・汎用名・製品/ベンダ別名: `matcher.py` 冒頭の定数（`CONF_*`, `GENERIC_PRODUCTS`, `PRODUCT_ALIASES`, `VENDOR_ALIASES`）。
- `packaging` は pytest 経由の dev 依存でしかない（`uv tree --invert`）。実行時依存に追加せず自前の比較器を使った。
- 優先度: LLM は優先度を上げられるが下げられない（CVE 説明文へのインジェクションで抑止されないため）。
- リサーチの信頼ドメイン: `research.DEFAULT_TRUSTED_DOMAINS`。実行時は `settings_kv["intel.research"] = {"allowed_domains": [...]}` で上書きできる（config.py の intel セクションは intel-feeds と共有のため触っていない）。
- 自動生成の流れ: P1/P2 は `intel.vuln_matched` / `intel.vuln_updated` で即時生成、P3 は定期ジョブ `intel.advise` が 1 回 5 件まで。
- 新しい定期ジョブ: `intel.match`, `intel.advise`（間隔は `sync_interval_minutes`）、`intel.research`。

## 他モジュールへの依頼
- **intel-feeds**: `VulnRow.affected` の各要素は `product` を入れてほしい（`SoftwareItem.product` は必須）。advisor は CPE だけの要素も許容するが、`VulnRecord.model_validate(row)` を直接呼ぶコードは失敗する。範囲は上記のキー（NVD camelCase / OSV）で dict に残せば matcher が読む。`intel.vuln_updated` の payload は VulnRecord / `{id}` / `{vuln_ids}` / id 文字列 / それらのリスト のどれでも受け付ける。
- **frontend-intel**: `/intel/matches` の要素に `asset_name, asset_criticality, vuln_title, kev, epss, cvss_score` を追加した（`types.ts` の `VulnMatch` に optional で追加をお願いしたい。共有ファイルなので未編集）。`POST /assets` は 201、`DELETE` は 204。
- **sigma**: `validate_rule(content) -> (valid, errors, title)` を `tokiwa.detect.sigma`（または `.parser`）から import できるようにしておいてほしい。proposed ルールは `meta.advisory_id / vuln_ids / rationale / validated_by` を持つ。
- **triage-correlate / api-core**: vuln_exposure アラートは `entities.asset_id / cve / trigger_alert_id` を持つ。ダッシュボードの `kev_matches` は `vuln_matches`（status=open）× `vulns.kev` で数えられる。

## TODO(verify)
- Anthropic の web_search ツールの `allowed_domains` について、サブドメインの扱いとリストの上限件数（`research.py` に TODO を記載）。
- 既定の信頼ドメイン一覧の妥当性（ベンダー PSIRT の URL は変わりやすい）。

## 次の一手
- sigma マージ後、実バリデータで `test_advisor.py` / `test_api_exposure.py` を再実行する。
- 実 LLM（費用あり）で `POST /intel/research/run` を 1 回試し、citations の形とドメイン制限を確認する。
- 大量の vulns（NVD 全件）に対する照合時間を測る。必要なら製品キーで SQL を事前に絞り込む。
