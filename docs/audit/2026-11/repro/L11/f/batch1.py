import json, subprocess, pathlib
M = pathlib.Path(__file__).resolve().parent.parent
F = [
dict(id="L11-04", title="取り込みは同期インライン処理で SQLite 上 約150〜240 events/s が上限。バッチ1000は p50 5.5 秒、並列化しても伸びない",
 area="ops", category="performance", severity="medium", confidence="confirmed",
 summary="POST /api/v1/ingest/events は enrich→検知→DB 保存→bus publish をリクエスト内で同期実行する（pipeline/service.py の docstring も『スループットが問題ならキューを置け』と明記）。実測で単一プロセス・SQLite は 100件バッチ 215〜236 ev/s、送信元/UA をローテーションすると 157 ev/s、1000件バッチは 172 ev/s・p50 5.5 秒・p95 7.3 秒、4 並列でも 199 ev/s で p95 5.6 秒に悪化する。スキャナ（数百 rps）1 台で上限に達し、Gate のキュー（L06-05）が溢れて古い順に破棄される。",
 evidence="scripts/loadgen.py（lab-mini.jsonl のテンプレから実的な gate.http イベント生成）で計測、結果 agents/L11/load_results.jsonl: b100c1 236 ev/s p50 0.40s p95 0.58s / r2-plain 215 ev/s p50 0.42 p95 0.80 / r2-rot(--rotate: 送信元IP・UA・ヘッダ名をランダム化) 157 ev/s p50 0.63 p95 0.83 / b1000c1 172 ev/s p50 5.53 p95 7.29 / b100c4 199 ev/s p50 1.45 p95 5.59 p99 7.66。4 コア共有環境・nice 10・loadavg 1.3〜4.8 のため絶対値は参考値。コード: pipeline/service.py:1-5,43-64（インライン処理）。さらにトリアージ/相関の bus タスクが同じイベントループで走るため取り込み後も CPU を奪い続ける（L11-02 参照）。",
 attack_scenario="AI エージェント（数十 rps）単体なら余裕があるが、Nuclei/ffuf 等のスキャナ（数百 rps）や、AI エージェントが並列ワーカーを起動した場合に 1 Gate で上限を超え、Gate 側でイベントが捨てられて検知の取りこぼしが起きる。攻撃者はノイズ（大量の無害リクエスト）で TOKIWA の処理能力を飽和させ、本命の操作を埋もれさせられる。",
 recommendation="取り込みを『受領→永続キュー（DB の staging テーブル or Redis Streams）→ワーカーで検知』に分離し、/ingest は受領のみで 202 を返す。DB 書き込みは executemany/バルク INSERT、検知は asyncio.to_thread かプロセスプールへ。docs/deploy.md に実測スループットとサイジング指針（1 プロセスあたり ~200 ev/s on SQLite）を記載し、取り込み遅延・キュー長のメトリクスを出す。",
 effort="L", known="none（pipeline/service.py docstring で将来課題として言及）", references=[], related=["L06-05","L07-06","L11-02"]),
dict(id="L11-05", title="送信元 IP/UA をリクエスト毎に回す1キャンペーンで、6300リクエスト→アラート約4600・インシデント約2700・対処提案約2100が生成される（アラート疲れ/提案洪水）",
 area="correlate", category="ops", severity="high", confidence="confirmed",
 summary="相関・重複排除・提案生成の単位がほぼ送信元 IP（＋UA）であるため、IP をリクエストごとに回す攻撃（プロキシローテーション、住宅プロキシ、IPv6 /64 内ローテーション）では 1 キャンペーンが数千件のアラート・インシデント・遮断提案に分裂する。人間承認が既定の設計（FR-12）では、承認待ち提案 2,000 件超は事実上レビュー不能で、運用者はキャンペーン全体を把握できない。",
 evidence="run2（mock LLM、SQLite）で固定 IP 系イベント 8,700 件の後、--rotate で 6,300 件（IP/UA/ヘッダ名をランダム化、内容は lab-mini の攻撃テンプレ）を 40 秒で投入。DB 集計（agents/L11/run2/data/tokiwa.db 読取専用）: alerts 4,707（固定 IP 区間 89 件 → ローテーション区間 4,618 件。ingest 応答の alerts_created 合計）、incidents 2,781、response_actions status=proposed 2,131、actor_sessions 6,308、llm_calls 10,656（triage 7,567 / incident 3,089）。検知器別: sigma 1,819、web.sqli 903、web.sensitive_file_probe 505、web.path_traversal 390、web.xss 309、deception.trip 152。",
 attack_scenario="ARTEX 等の AI エージェントが住宅プロキシ/クラウドの使い捨て IP を回しながら同じ脆弱性探索を行うと、SOC 画面は数千件の別インシデントで埋まり、本当に重要な 1 件（成功した侵害）が埋没する。遮断提案は /32 単位で数千件出るが攻撃者は次の IP に移っているため効果がない（L09-03）。LLM 費用も件数に比例して消費される。",
 recommendation="相関キーに IP 以外（ターゲットパス集合・ペイロード族・JA4/ヘッダ順フィンガープリント・時間窓・ASN/プレフィックス）を加えたキャンペーンクラスタリングを実装し、インシデント/提案はキャンペーン単位で集約する。IP ごとの新規アラートには集約閾値（例: 同一検知器×同一パス族で N 件/分を超えたら 1 件に畳む）を設ける。提案は同一キャンペーン内で CIDR/ASN 集約の 1 件にする。評価データセットに『IP ローテーション版』を追加して回帰監視する。",
 effort="L", known="wave2-scoring（アクター同定の改善は計画あり。件数の定量化は新規）", references=[], related=["L02-01","L04-03","L09-03","L11-02"]),
dict(id="L11-06", title="SQLite の書き込み競合で 'database is locked' が発生し LLM 監査レコードが失われる → 監査欠落と日次予算の過少計上",
 area="llm", category="reliability", severity="medium", confidence="confirmed",
 summary="LLM 呼び出しの監査行（llm_calls）は呼び出し後に別セッションで書かれ、失敗すると log.exception して捨てるだけ。日次予算（check_budget）は llm_calls.cost_usd の合計で計算するため、書き込みに失敗した呼び出しの費用は予算に計上されない。取り込み＋トリアージ＋相関が同時に書く負荷では SQLite の busy timeout(30 秒) を超え、実際にこの経路で OperationalError: database is locked が発生した。",
 evidence="agents/L11/run3/memprof_plain.txt: 'failed to write LLM audit record' → sqlite3.OperationalError: database is locked（INSERT INTO llm_calls、purpose=triage、latency_ms=14.8）。条件: in-process で 100件×数バッチ取り込み＋トリアージ/相関タスク並走（bus.drain(30) もタイムアウト）。コード: llm/gateway.py:339-344（例外を握りつぶし）、:106-119（予算は llm_calls の SUM）、db/session.py:38（timeout=30）,45（WAL）。",
 attack_scenario="攻撃者が大量のイベント（L11-05 の IP ローテーション等）でトリアージを多発させ DB 競合を起こすと、LLM 呼び出しの一部が監査にも予算にも残らない。実 LLM 構成では daily_budget_usd を超えて課金が続き、また『どのプロンプトに何を送ったか』の監査証跡が欠落する。",
 recommendation="予算はメモリ上のカウンタ（プロセス内）＋DB を併用し、監査書き込み失敗時はリトライ/バッファして後で書く。監査書き込み失敗をメトリクス化しヘルスに出す。SQLite 運用時は書き込みを単一ライタータスクに集約するか、本番は PostgreSQL を必須とする旨を docs/deploy.md に明記。",
 effort="M", known="none", references=[], related=["L08-01","L11-02","L11-04"]),
]
for d in F:
    p = M / "f" / f"{d['id']}.json"; p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    print(subprocess.run(["python3", str(M/"scripts/add.py"), str(p)], capture_output=True, text=True).stdout.strip())
