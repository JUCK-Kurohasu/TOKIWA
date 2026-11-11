import json
M="docs/audit/2026-11/repro/L04"
ev=" (MYDIR=docs/audit/2026-11/repro/L04)"
f3={"id":"L04-03","title":"送信元 IP を要求ごと/4 要求ごとにローテーションする AI エージェントは AI 帰属が 1/8・2/8 に低下（セッションが IP 単位で断片化し IP 横断の集約がない）",
"area":"aidetect","category":"detection-gap","severity":"medium","confidence":"confirmed",
"summary":"セッションキーは source_ip+クライアント指紋（aidetect/sessions.py:1-6）で、IP をまたぐアクター集約は無い（ip_tool_fingerprints も同一 IP 内のみ）。住宅プロキシ/クラウド関数/IPv6 /64 内のアドレス回転で 1 エージェントの行動が多数の 1-4 要求セッションに分かれ、MIN_REQUESTS_FOR_VERDICT 未満で unknown になる。UA/ヘッダは不変でも崩れる点で L02-01（UA ローテーション）とは別の根本原因（IP 次元）。回転 10 要求ごとなら 8/8 で検知されるので、閾値は『セッションあたり要求数 < ~5』付近。",
"evidence":"drive.py で v_rotate1 / v_rotate4 / v_rotate10（evasive.py Cfg.rotate, 100.64.0.0/10 から回転）を seed 1/2 で各 4 セッション: rotate1 AI 帰属 1/8, 行動 ai_score 0.08-0.17, 分類 unknown 4/4 (seed1); rotate4 2/8, 0.33-0.84; rotate10 8/8, 0.85-0.97。シグネチャ検知は全て 8/8。帰属された 1-2 件は alert 側 ai_score（ai.semantic_recon 等の 0.84）によるもので行動スコアではない。表: $MYDIR/variant_table.md"+ev,
"attack_scenario":"ARTEX 等を住宅プロキシ（要求ごとに出口 IP が変わる）経由で動かす、または IPv6 /64 内でアドレスを回す。各断片は数要求のため AI 判定もセッション単位の検知（ai.agent_session）も発火せず、Gate の IP ブロックも 1 IP ずつしか効かない。",
"recommendation":"(1) IP 横断の『アクターグループ』: 指紋（UA+ヘッダ集合+将来の JA4）・Cookie/Authorization・時間的連続性（前の断片の最終要求から数秒以内）・パスの連続性（列挙順序の続き）で断片を連結し、グループ単位で特徴量・スコアを再計算。(2) IPv6 は /64、IPv4 は ASN/ /24 単位の副次集約キーを追加し、一定時間内の『同一指紋×多数 IP×各 1-3 要求』自体を回避シグナルにする。(3) wave2-scoring-tuning 要件 4 は『同一送信元』の束ねのみなので IP 横断も対象に加える。評価データに rotate1/4 を追加。",
"effort":"L","known":"wave2-scoring-tuning","references":[],"related":["L02-01","L04-02"]}
f4={"id":"L04-04","title":"低速（low-and-slow）エージェント: 要求間隔 5-25 分（セッション内）で AI 帰属 1/8・human 誤分類、30 分超の間隔では全要求が単発セッションになり unknown",
"area":"aidetect","category":"detection-gap","severity":"medium","confidence":"confirmed",
"summary":"H1（burst→think リズム）は思考帯を秒〜数十秒と仮定し、長く不規則な間隔は sparse_irregular_pacing(-0.8) として AI 否定証拠になる。エージェントが 1 要求ごとに 300-1500 秒待つだけで、同じ攻撃内容（spec 取得→利用・変異・NL ペイロード）でも行動 ai_score は 0.17-0.50 で human 分類になる。間隔を session_idle_timeout_seconds（1800 s）超にすると要求ごとに新セッションとなり全て unknown。トークン課金や検知回避を気にする攻撃者にとってコストは時間だけ。",
"evidence":"drive.py: v_slow_in_session（各要求間 uniform 300-1500 s）seed1 beh=[0.168,0.401,0.401,0.332] confusion {human:4}; seed1+2 合計 AI 帰属 1/8（alert 側 0.84 による）。v_slow_split（1900-3600 s）beh 0.08-0.17, unknown 4/4, 帰属 1/8。シグネチャ検知 8/8。重み aidetect/scoring.py:56-57, 212-213（sparse_irregular_pacing）。idle は config.py:125。表: $MYDIR/variant_table.md"+ev,
"attack_scenario":"夜間に数時間かけて 1 要求/10-40 分で偵察・列挙・試行を進める自律エージェント（スケジューラ起動や API レート制限を口実に自然に起きる）。各要求は単発のシグネチャアラートとして散発し、AI キャンペーンとして束ねられない。",
"recommendation":"(1) 長期プロファイル: IP/指紋ごとに数日窓の軽量集計（列挙順序・spec 取得後の利用・攻撃ファミリー数）を別ストアに保持し、セッション切れを跨いで H3/H2 を評価。(2) sparse_irregular_pacing は攻撃ペイロード比率が高いセッションでは無効化（攻撃中に長く間を空けるのは人間とも限らない）。(3) 複数の単発セッションを correlate 段で『同一アクター・低速キャンペーン』にまとめる（アラート数/日の閾値）。(4) wave2 の評価データに low-and-slow を追加。",
"effort":"M","known":"wave2-scoring-tuning","references":[],"related":["L04-02","L04-03"]}
for f in (f3,f4): open(f"{M}/lab/f_{f['id']}.json","w").write(json.dumps(f,ensure_ascii=False))
