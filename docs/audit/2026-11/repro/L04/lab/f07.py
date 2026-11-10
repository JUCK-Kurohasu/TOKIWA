import json
M="docs/audit/2026-11/repro/L04"
ev=" (MYDIR=docs/audit/2026-11/repro/L04)"
f7={"id":"L04-07","title":"ai_agent_threshold は唯一の調整点だが、検知器ごとの固定 ai_score（0.45/0.5/0.6/0.74 等）と同じ尺度で比較され、重み・他ヘッド閾値はコード固定のため閾値を下げると正常監視が AI 判定される",
"area":"aidetect","category":"robustness","severity":"low","confidence":"confirmed",
"summary":"detection.ai_agent_threshold（config.py:127）は sessionizer の分類（aidetect/scoring.py:307）・ai.agent_session 発火・インシデントの AI ブースト（correlate/service.py:455-470）・ダッシュボード・評価指標をまとめて制御する。一方、他の AI 検知器のアラート ai_score は較正されていない定数（ai_semantic_recon.py:137,161 で 0.5/0.6/0.45、ai_natural_language_payload.py:66 で 0.55-0.85）で、同じ閾値と比較される。AI_WEIGHTS/AI_BIAS・SCANNER/HOSTILE 閾値（scoring.py:34-93）や Sessionizer.max_sessions（sessionizer.py:84）は設定不可で、現場での調整はコード改変が必要。NaN/ゼロ除算は features.py の分母ガード・_sigmoid のクランプで処理済み（問題なし）。",
"evidence":"全 variant（144 攻撃セッション）と benign 17 プロファイル（AI クローラ/アシスタント除く 180 セッション）の combined スコアで閾値掃引: th=0.7 recall 0.70 FP 0/180; th=0.6 recall 0.73 FP 6/180（fp_ci_contract_test, fp_multi_check_monitor — 行動スコアは 0.37-0.46 で、FP 要因は ai.semantic_recon の固定 0.6）; th=0.5 recall 0.88 FP 9/180（+fp_link_checker）。行動スコアのみでは th=0.6 で FP 0。データ: $MYDIR/exp/run-*/metrics.json, $MYDIR/expfp/run-*/metrics.json。"+ev,
"attack_scenario":"運用者が回避型エージェント（L04-02/03/04）を拾おうと閾値を 0.6 に下げると、合成監視・CI・リンクチェッカーが『AI エージェント』になりインシデント重大度がブーストされる一方、回避型の再現率はほぼ改善しない（+3pt）。",
"recommendation":"(1) アラート ai_score を行動スコアと同じ較正（評価データ上の Platt/isotonic）に揃えるか、インシデントの AI ブーストは ai.agent_session/canary 由来のスコアに限定する。(2) AI_WEIGHTS・AI_BIAS・SCANNER/HOSTILE 閾値・max_sessions を DetectionSettings のサブセクション（既定値は現行）で上書き可能にし、変更は監査ログへ。(3) wave2-scoring-tuning で閾値掃引表（本 evidence 形式）を CI 成果物にする。",
"effort":"M","known":"wave2-scoring-tuning","references":[],"related":["L04-02","L04-05"]}
f8={"id":"L04-08","title":"SessionTracker の LRU 上限 4096（設定不可）を超える単発セッションの洪水で、進行中の AI エージェントのセッションが追い出され特徴量がリセットされる",
"area":"aidetect","category":"robustness","severity":"low","confidence":"confirmed",
"summary":"ライブセッションは max_sessions=4096 の LRU（aidetect/sessions.py:166-169, enrich/sessionizer.py:84）。異なる IP または異なる UA/ヘッダ集合の 1 要求を約 4100 件送ると、静かにしている攻撃セッションが追い出されて確定され、以後の要求は新セッションで特徴量ゼロから再計算される。メモリは有界（4096 セッションで tracemalloc ピーク約 44 MB）で DoS にはならないが、断片化による回避（L04-03 と同型）の安価な手段になる。今回の 44 要求エージェントは断片 13+31 要求がそれぞれまだ ai_agent になったため、帰属喪失には繰り返しの洪水が必要（未計測）。",
"evidence":"`cd backend && .venv/bin/python $MYDIR/lab/evict.py`（ai_agent 1 セッション seed 3, 30% 時点で洪水）: flood=0 → 1 セッション 44 要求 peak 0.993; flood=4000 → 分割なし; flood=4200 → 2 セッション（13 要求 peak 0.875 / 31 要求 peak 0.890）, evicted=106, mem_peak 44.2 MB。"+ev,
"attack_scenario":"ボットネット/住宅プロキシ、または同一 IP から UA をランダム化した軽い GET を数千件撒いてから本攻撃を数要求ずつ進め、洪水を挟むたびにセッション特徴量をリセットする。洪水自体は 200 応答の GET / で検知されにくい。",
"recommendation":"(1) 追い出し時に AI 関連の累積カウンタ（spec 取得・変異・攻撃数・peak）を IP/指紋キーの軽量サマリ（数百バイト）として別 LRU に残し、同キーの新セッションに引き継ぐ。(2) 追い出し対象を『単発・低スコア』優先にする（スコア/要求数で重み付けた eviction）。(3) eviction 率をメトリクス化し急増時に警告。(4) max_sessions を設定可能に。",
"effort":"S","known":"none","references":[],"related":["L04-03","L04-01"]}
for f in (f7,f8): open(f"{M}/lab/f_{f['id']}.json","w").write(json.dumps(f,ensure_ascii=False))
