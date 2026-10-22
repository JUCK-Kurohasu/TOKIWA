# タスク: triage-correlate — 相関・インシデント化・LLM トリアージ

## 目的
FR-07/09: アラートを束ねてインシデントにし、LLM で根拠付きの判定（重大度・カテゴリ・AI 関与度・攻撃段階・
次の調査手順・対処提案）を出す。ルール主・LLM 補助。

## 担当範囲
- `backend/src/tokiwa/correlate/`（service.py, killchain.py, scoring.py）
- `backend/src/tokiwa/triage/`（service.py, prompts.py, fallback.py, evidence.py）
- `backend/src/tokiwa/api/routes/alerts.py`, `backend/src/tokiwa/api/routes/incidents.py`
- `backend/tests/triage/`, `backend/tests/correlate/`

## 要件
1. 相関（`@on_startup` で `alert.created` / `alert.updated` を購読）:
   - 既存のオープンなインシデントのうち、同一 source_ip / 同一 session_id / 同一エンティティ（host+port, cve）を
     `triage.incident_window_minutes` 内で持つものに紐付け。なければ新規作成。
   - インシデントの severity = max(alert)、ai_score = max、kill_chain = MITRE 戦術の順序付き集合
     （techniques → tactic の簡易マップを `killchain.py` に）、actor_type（AI スコア・検知器から推定）。
   - ブースト: (a) `ai_score >= ai_agent_threshold` → 1 段階引き上げ、(b) 関連エンティティの CVE が
     KEV（`vulns.kev=True`）なら引き上げ + タグ `kev`（P4 受け入れ基準）、(c) 新規 listener の直後
     （窓内）に同ポートへのリクエスト系アラート → `correlated:port_request`（FR-09 の例）。
   - `incident.created` / `incident.updated` を publish。
2. トリアージ（`alert.created`, `incident.created/updated` を購読、`auto_triage` 時）:
   - `min_severity_for_llm` 未満は LLM に送らず fallback（ルール）判定のみ。
   - 入力: アラート/インシデント要約 + 証拠イベント（最大 `max_evidence_events`、HTTP は path/query/body 先頭/
     主要ヘッダ/ステータス/タイミングに絞る）+ セッション特徴量 + 関連脆弱性。必ず `untrusted_block()` で包む。
   - fast tier → `confidence < escalate_confidence_below` または severity ≥ `escalate_severity` なら deep tier。
   - `evidence_ids` 検証: 渡したイベント ID 以外を含む → それを除外し `rejected_evidence_ids` に記録。
     有効な証拠が 0 件なら 1 回だけ再試行（「提示した ID のみを使え」と追記）、それでもダメなら fallback。
   - 結果は `TriageRecord` として alert/incident の `triage` 列に保存し status=triaged。
   - `recommended_actions` → `tokiwa.respond.service.propose_action()`（proposed_by=llm）。target が証拠に
     現れない IP の場合は提案しない。（respond 未実装でも落ちないよう NotImplementedError を握る）
   - 同時実行数 `max_concurrent`（Semaphore）。同じ対象の多重トリアージを防ぐ。
   - プロンプトは `triage/prompts.py` に `PromptTemplate(id, version, system)` として定義。日本語出力指示は
     `language_instruction()`。few-shot は短く。
3. fallback（`triage/fallback.py`）: ルールベースの `TriageResult` を生成（検知器のカテゴリ・重大度・ai_score から）。
   同じ関数を `@register_mock_responder(TriageResult)` にも登録して mock プロバイダでの E2E を意味のあるものにする。
4. API（docs/api-contract.md「アラート」「インシデント」）。PATCH は `record_audit`。強制トリアージ API は同期で結果を返す。

## 受け入れ基準
- 単体: 相関ルール（紐付け/新規/ブースト）、evidence 検証、エスカレーション判定、fallback。
- 統合（mock LLM）: ingest → alert → incident → triage 済みになる（`await bus.drain()` 後に検証）。
- 予算超過・refusal・invalid_output のとき fallback で triaged になり、`TriageRecord.tier == "rules"`。
