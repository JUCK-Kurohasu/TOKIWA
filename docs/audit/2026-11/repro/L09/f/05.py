F = {"id":"L09-05","title":"tarpit はリクエストごとに Gate のコルーチン/接続を最大 30 秒保持し、同時数の上限もクライアント切断時の中断も無い",
"area":"gate","category":"robustness","severity":"low","confidence":"likely",
"summary":"tarpit 対象 IP の要求は _dispatch 内で asyncio.sleep(最大 30 s) してから処理を続ける。IP ごとの同時保持数の上限、Gate 全体の tarpit 同時数の上限、uvicorn の limit_concurrency 設定は無く、クライアントが切断しても sleep は継続する（切断検知なし）。tarpit を共有 IP や多数の IP に適用すると、保持中のリクエスト（ソケット・Exchange・キャプチャバッファ）が Gate 側に積み上がる。攻撃者側の負担は送信だけ（撃ちっ放しでも Gate 側のタスクは 30 秒残る）なので、tarpit は攻撃者よりも防御側の資源を消費しやすい。",
"evidence":"backend/src/tokiwa/gate/app.py:288-293（tarpit: await self._sleep(delay_ms/1000) 切断検知なし）, gate/cli.py:136-148（uvicorn.run に limit_concurrency / backlog 指定なし）; respond/validate.py:44（MAX_TARPIT_MS=30000）",
"attack_scenario":"tarpit された AI エージェント（または同じ出口 IP の攻撃者）が数百〜数千の並列リクエストを撃ちっ放しで送る→Gate に 30 秒ずつ sleep するタスクが滞留し、メモリ/FD/キャプチャキューを圧迫して正規利用者の応答も遅くなる。",
"recommendation":"tarpit 中の同時保持数を IP（または一致エントリ）ごとに上限化し、超過分は 429 か即時 403。sleep を http.disconnect 受信で中断。Gate に全体の tarpit スロット上限と uvicorn limit_concurrency を設定可能に。docs/response.md に『tarpit は防御側の資源も消費する』旨を記載。",
"effort":"S","known":"none","references":[],"related":["L06"]}
