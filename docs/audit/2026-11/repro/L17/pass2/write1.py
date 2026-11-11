import json
F="findings/L17-privacy.jsonl"
LEGAL_NOTE="確認が必要な論点（法的結論ではない）: 目的の特定・利用目的の範囲、データ最小化、保存期間、安全管理措置。一次資料 URL はこの環境から開けなかった（eur-lex.europa.eu / www.ppc.go.jp が名前解決不可）ため 未確認。"
fs=[
{"id":"L17-01","title":"Gate が氏名・電話番号・生年月日・住所・ログイン ID・URL エンコードされたメールを events.data に平文で保存し、データ種別ごとに収集を止める設定が無い",
"area":"gate","category":"security","severity":"medium","confidence":"confirmed",
"summary":"Gate はリクエストのクエリ・パス・Referer・許可リスト外ヘッダ（X-Forwarded-User 等）・テキスト系ボディ先頭 4096 バイトを保存する（応答ボディは保存しない。Cookie/Authorization 等の値は伏字）。マスキング（llm/redact.py）は秘密値・Luhn を満たすカード番号・生のメール形式のみが対象で、氏名・電話番号・生年月日・住所・ログイン ID（username）・%40 でエンコードされたメールは平文で events.data に残る。運用者が使える制御は capture_body_bytes（ボディ全体の有無）と redaction.enabled/mask_emails/mask_ips の全体スイッチだけで、『クエリは残すがフォームの個人項目は捨てる』『特定パラメータを常に伏字』といったフィールド単位の指定手段が無い。",
"evidence":"コード: gate/capture.py:216-243（query/path/referer/headers/request_body を redact_text のみで保存）、llm/redact.py:15-37,77-81（パターン一覧。電話・氏名・住所なし）、config.py:45-61（RedactionSettings）、config.py:246（capture_body_bytes=4096）。実測（run1, ポート 22700-22703, 偽データ）: POST /api/login form → events.data.http.request_body = `username=hanako.fake%40example.com&password=[REDACTED:secret]&fullname=Yamada+Hanako&tel=090-1234-5678`。JSON ボディ → `\"phone\":\"+81 90 9876 5432\",\"name\":\"Taro Fakeuser\",\"dob\":\"1990-01-02\",\"address\":\"Tokyo-to Fake-ku 1-2-3\"` が平文。GET クエリ `q=Yamada%20Hanako&email=hanako.fake%2Bx%40example.com&phone=09012345678` が平文、ヘッダ x-forwarded-user: `Taro Fakeuser` が平文（x-user-email は生メールなので [REDACTED:email]）。Cookie は `[REDACTED:cookie]`。また 3 文字未満の password 値（`password=x`）は伏字にならない。スクリプト: agents/L17/pass2/run1/ 配下。",
"attack_scenario":"運用で通常利用者のログイン・会員登録・問い合わせフォームが Gate を通るたびに、検知に不要な個人項目が無期限（保持機構なし: L11-08）に SQLite に蓄積される。DB ファイルやバックアップの漏えい時（L14-09 で 0644）に影響範囲が大きくなる。"+LEGAL_NOTE,
"recommendation":"(1) gate.capture に『保存しないパラメータ名/JSON キー』と『常に伏字にするパラメータ名』の設定を追加（既定に name, fullname, tel, phone, address, dob, birth 等）、(2) 電話番号（国内/E.164）・URL エンコード後のメールをパターンに追加（L08-02 と同じ修正点）、(3) 正常応答（2xx/3xx かつアラート無し）のボディは保存しない or 短期保持にするモード、(4) どの項目が保存されるかを docs/wiki に明記。",
"effort":"M","known":"none","references":[],"related":["L08-02","L11-08","L14-09","L05-01"]},
{"id":"L17-02","title":"viewer ロールでも生イベント（リクエストボディ・クエリ全文）を閲覧でき、LLM 呼び出し詳細（admin 限定）との権限が不整合",
"area":"api","category":"security","severity":"medium","confidence":"confirmed",
"summary":"GET /api/v1/events・/api/v1/events/{id}・/api/v1/sessions は CurrentUser（全ロール）で、viewer がフォーム本文・クエリ・ヘッダを含む生イベントを取得できる。一方、同じ内容を含む LLM 監査の詳細 GET /api/v1/llm/calls/{id} は AdminUser 限定（403）。生データ閲覧を analyst 以上に限る、または viewer には本文を伏せるといった区別が無い。Copilot も CurrentUser で使え、search_events ツールが request_body_excerpt（300 文字）を LLM に渡す（copilot/tools.py:455-483）。",
"evidence":"コード: api/routes/events.py:88,158-159（CurrentUser）、api/routes/llm.py:142-145（一覧 CurrentUser）・170-171（詳細 AdminUser）、api/deps.py:81-82。実測: admin で viewer1（role=viewer）を作成→ viewer の JWT で GET /api/v1/events?limit=50 → 200、20 件、request_body に `username=hanako.fake%40example.com...&tel=090-1234-5678&name=Yamada+Hanako` を含む。GET /api/v1/llm/calls/{id} → 403、GET /api/v1/audit → 403、GET /api/v1/sessions → 200。",
"attack_scenario":"閲覧専用アカウント（外部委託 SOC、経営向けダッシュボード閲覧者など）に配ったつもりの権限で、利用者の個人項目・平文で残った秘密（L08-02）を一括取得できる。viewer アカウントが乗っ取られた場合（L07-03 ロックアウト無し）の被害範囲も同じ。",
"recommendation":"イベント本文（http.request_body, query, headers, raw）を返す API を analyst 以上に限定するか、viewer には伏字済み射影を返す。Copilot の利用可否もロールで設定可能にする。権限表を docs/wiki に記載。",
"effort":"S","known":"none","references":[],"related":["L17-03","L08-02","L07-03"]},
{"id":"L17-03","title":"『誰が何を閲覧したか』が記録されない: audit_log は変更操作のみで、生イベント・セッション・Copilot の閲覧/検索は監査対象外",
"area":"api","category":"security","severity":"low","confidence":"confirmed",
"summary":"record_audit の呼び出し元は alerts/assets/detectors/hosts/incidents/intel/llm(config)/rules/system/tokens/users/deception/notify/respond の変更系のみで、events・sessions・llm/calls 一覧・copilot（会話作成・ツール実行）には無い。ログイン成功も記録されない。個人データを含む生イベントの大量閲覧や Copilot 経由の検索を事後に追跡できない。エクスポート API は存在しない（したがってエクスポート記録も無い）。",
"evidence":"コード: grep -rn record_audit（呼び出し元ファイル一覧は上記。api/routes/events.py・sessions.py・copilot.py には 0 件）、audit.py:14-30。実測: viewer で events 50 件・sessions を取得後、admin で GET /api/v1/audit?limit=100 の action 集合 = ['deception.seed','response.propose_rejected','user.create']（閲覧・ログインの行なし）。",
"attack_scenario":"内部不正や乗っ取られたアカウントが特定人物の行動（IP・ログイン ID）を検索しても痕跡が残らず、インシデント時に『どのデータが誰に見られたか』を説明できない。",
"recommendation":"events/sessions の一覧・詳細・Copilot ツール実行・LLM 呼び出し詳細の閲覧を軽量な access ログ（actor, route, filter, 件数）として記録（audit_log とは別テーブル or 同テーブルの action=read.*）。ログイン成功/失敗も記録（L07-03 と合わせて）。",
"effort":"S","known":"none","references":[],"related":["L17-02","L07-03"]},
]
with open(F,"a",encoding="utf-8") as f:
    for o in fs: f.write(json.dumps(o,ensure_ascii=False)+"\n")
print("ok")
