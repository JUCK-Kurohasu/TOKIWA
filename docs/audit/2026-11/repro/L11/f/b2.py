import json, subprocess, pathlib
M = pathlib.Path(__file__).resolve().parent.parent
F=[
dict(id="L11-08", title="DB 増加量の実測: 通常トラフィックで約 2.6KB/イベント、IP ローテーション攻撃時は LLM 監査行が支配的で約 13KB/イベント（10万件で約 1.3GB）、保持/パージ機構は未実装",
 area="ops", category="ops", severity="medium", confidence="confirmed",
 summary="保持期間とパージジョブは wave2-config-ops で計画済みだが未実装（tokiwa/retention.py なし）。実測では DB サイズは取り込みイベント数より『アラート数×LLM 呼び出し数』に比例し、llm_calls 1 行あたり約 10KB（request_redacted 平均 8.2KB、上限 100,000 文字×2 列）が最大の容量要因。攻撃者がアラート多発（L11-05）を起こすと DB は 1 時間あたり数 GB のペースで増え、SQLite のディスクを埋める。",
 evidence="run2（SQLite、mock LLM、トリアージ完了後）dbstat 集計: 合計 196MB / events 15,000。内訳 llm_calls 105.7MB（10,656 行≈9.9KB/行）、events 26.7MB（≈1.8KB/件、events 系インデックス計 約3.1MB）、actor_sessions 25.9MB（6,308 行≈4.1KB/行）、alerts 19.7MB（4,707 件≈4.2KB/件）、incidents 7.5MB（2,781 件）。固定 IP 区間のみ（8,700 件時点）の DB は 22.4MB（≈2.6KB/件 → 10 万件 ≈ 260MB）。ローテーション混在全体では ≈13KB/件 → 10 万件 ≈ 1.3GB。WAL は 13.3MB で頭打ち（自動チェックポイントは機能）。コード: llm/gateway.py:336-337（各 100,000 文字まで保存）。",
 attack_scenario="ノイズの多いスキャナや IP ローテーション型 AI エージェントが 200 ev/s を継続すると、ローテーション時の比率で約 2.6MB/s ≈ 9GB/時。ディスク枯渇で SQLite 書き込みが失敗し、以降の検知・監査がすべて止まる（L11-07 の通り外形監視では気づけない）。",
 recommendation="wave2-config-ops の保持/パージ実装時に llm_calls の本文（request_redacted/response_text）を短期保持＋別テーブル/圧縮にし、メタデータのみ長期保持する。アラートの集約（L11-05）で LLM 呼び出し自体を減らす。ディスク残量・DB サイズをヘルス/メトリクスに出し、閾値で取り込みを劣化モード（LLM トリアージ停止）へ切替える。docs/deploy.md にサイジング表（上記実測）を追加。",
 effort="M", known="wave2-config-ops（保持/パージ計画。容量の定量化は新規）", references=[], related=["L11-05","L11-07","L12-03"]),
dict(id="L11-09", title="相関・検知状態がすべてプロセス内メモリにあり、再起動で消え、複数ワーカー/複数レプリカでは分断される（水平スケール不可・再起動で閾値検知がリセット）",
 area="ops", category="reliability", severity="medium", confidence="likely",
 summary="検知のスライディングウィンドウ/TTL 状態（detect/context.py の DetectionContext・TTLStore）、SessionTracker（aidetect）、通知の重複抑止（notify/service.py _Deduper・_incident_severity）、トリアージの重複署名とバックログ（L11-02）、bus の購読タスクはすべて単一プロセスのメモリ上にある。再起動・クラッシュでは (a) レート/スキャン/ブルートフォース系の閾値カウンタが 0 に戻り、(b) 通知の重複抑止が消えて同じインシデントの通知が再送され、(c) 未処理のトリアージ/相関タスクが消える（再走査ジョブなし）。また uvicorn --workers>1 や複数レプリカにすると状態が分断され、攻撃が各ワーカーに分散して閾値未満になる。",
 evidence="detect/context.py:22-58（TTLStore、sweep は set 時のみ・既定 TTL 3600 秒）,:96-118（_windows dict、GC は件数が 2000 の倍数のときのみ）; detect/detectors/web_rate.py:10（docstring に『state is in-memory and per process』と明記）; notify/service.py:88-125（_MAX_TRACKED=10,000 のメモリ内 dedup）; enrich/sessionizer.py:147-148（グレースフル停止時のみフラッシュ、クラッシュ時は最大 flush 間隔ぶん消失）; runtime.py の @periodic に未トリアージ再走査なし。実測関連: 単一プロセス RSS が 8,700 件取り込みで 134MB→521MB（run2）、run1 では 398→835MB（原因の内訳は未特定、in-process tracemalloc はトリアージ滞留で bus.drain がタイムアウトし計測未完 → run3/memprof_plain.txt）。",
 attack_scenario="AI エージェントがレート系検知を避けるため、TOKIWA のメンテナンス再起動や OOM 再起動の直後に攻撃を集中させる（カウンタがリセットされる）。可用性のために複数レプリカ構成にした運用者は、検知閾値が実質レプリカ数倍に緩む。メモリ増加（上記 RSS）でコンテナのメモリ上限に当たると OOM→再起動→状態消失のループになる。",
 recommendation="単一プロセス前提を docs/deploy.md に明記（workers=1、レプリカ不可）。中期的には状態ストアを抽象化（Redis 等）し、検知ウィンドウ・dedup・セッションを共有/永続化。起動時に『未トリアージ/未相関アラートの再走査』ジョブを追加。RSS 増加の原因特定（tracemalloc をトリアージ無効で再計測）と、メモリ上限・状態サイズのメトリクス化。",
 effort="L", known="none（web_rate.py docstring で単一プロセス制約のみ言及）", references=[], related=["L04-08","L11-02","L11-07"]),
]
for d in F:
    p = M / "f" / f"{d['id']}.json"; p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    print(subprocess.run(["python3", str(M/"scripts/add.py"), str(p)], capture_output=True, text=True).stdout.strip())
