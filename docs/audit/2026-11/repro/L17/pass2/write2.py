import json
F="findings/L17-privacy.jsonl"
UNV="一次資料 URL はこの環境から開けなかった（eur-lex.europa.eu / www.ppc.go.jp が名前解決不可）ため 未確認。"
fs=[
{"id":"L17-04","title":"特定の IP・利用者・セッションに関するデータを一括削除/エクスポートする手段が無く、同じ個人データが events・llm_calls・deception_trips 等に重複保存される（IP の仮名化も無い）",
"area":"api","category":"ops","severity":"medium","confidence":"confirmed",
"summary":"API の DELETE は users/tokens/rules/assets/deception assets/copilot 会話/host baselines/notify channels のみで、events・alerts・incidents・actor_sessions・llm_calls を対象者単位で削除・抽出する API/CLI は無い。保持パージも未実装（L11-08）。1 件のフォーム送信の個人項目は events.data に加え、トリアージ/インシデント分析の llm_calls.request_redacted（evidence_events.body_head）に複数回コピーされるため、仮に events を消しても他テーブルに残る。redaction.mask_ips は LLM 送信テキスト中の IPv4 文字列にしか効かず、events.source_ip・alerts・incidents.source_ips・actor_sessions の IP は常に生値（仮名化/ハッシュ化オプション無し）。",
"evidence":"コード: grep '@router.delete' api/routes/（上記 8 種のみ）、gate/capture.py:248（source=_endpoint(ex.client_ip) を伏字処理せず保存）、llm/redact.py:79-80（mask_ips はテキスト置換のみ）、deception/service.py:563（トリップ行はイベント削除後も残る設計）。実測（run1）: 偽 PII マーカーで全テーブルを走査 → 'Hanako'/'090-1234-5678' 等が events.data に 7 行、llm_calls.request_redacted に 13 行（同一フォーム値が triage と incident の両 purpose に重複）。alerts/incidents/audit_log には該当なし。",
"attack_scenario":"利用者から自分のデータの削除・開示を求められた、あるいは誤って本番の顧客データを大量に取り込んだ場合に、運用者は SQLite を直接編集するしかなく、llm_calls の写しを見落としやすい。確認が必要な論点（法的結論ではない）: 本人からの開示・削除請求への対応手順、保存期間の設定。"+UNV,
"recommendation":"`tokiwa data purge --ip/--session/--before` と `tokiwa data export --ip ...`（admin 限定、監査記録付き）を追加し、events・llm_calls（related/本文検索）・actor_sessions・alerts.details・deception_trips を横断する。llm_calls.request_redacted は短期保持（例 7 日）で本文のみ NULL 化する別ポリシーを持たせる。IP の鍵付きハッシュ化（表示用）オプションを検討。",
"effort":"M","known":"wave2-config-ops（保持/パージのみ。対象者単位の削除・エクスポートは計画外）","references":[],"related":["L11-08","L17-01"]},
{"id":"L17-05","title":"自動トリアージ（既定 ON）がアラートごとに生の送信元 IP・UA・ボディ先頭（氏名・電話番号を含む）を外部 LLM 提供者へ送り、送信項目を種別ごとに止める設定が無い",
"area":"llm","category":"security","severity":"medium","confidence":"confirmed",
"summary":"triage.auto_triage=True・llm.provider=auto（API キーがあれば Anthropic）が既定で、アラートが出るたびに evidence_events（src/dst IP, header_order, user_agent, body_head, query 等）を含むプロンプトが送られる。mock 実行で llm_calls.request_redacted（= 送信されるはずの本文）を確認すると、正常利用者の氏名・電話番号・URL エンコードメール・送信元 IP が含まれていた。止める手段は auto_triage 全体・provider・mask_ips/mask_emails・capture_body_bytes の全体スイッチのみで、『ボディは LLM に送らない』『クエリ値は送らない』のような項目単位の制御や、ローカル LLM（openai_compat）以外への送信を明示的に許可させる仕組みは無い。L08-02 は伏字パターンの漏れ、本件は送信項目の最小化・選択手段の欠如という別の根本原因。",
"evidence":"コード: config.py:64-67（provider auto）, 131-132（auto_triage=True）, 60（mask_ips=False）; triage の証拠ブロックに body_head を含める。実測（run1, mock）: llm_calls purpose=triage 13 件（平均 8.4KB）・incident 4 件（平均 11.9KB）。うち 13 件の request_redacted に 'Hanako','Yamada','090-1234-5678' 等、'127.0.0.1' と user_agent を含む。抜粋: `<untrusted_data name=\"evidence_events\"> [{... \"body_head\": \"username=hanako.fake%40example.com'%20OR%20'1'='1&password=x&tel=090-1234-5678&name=Yamada+Hanako\" ...`。正常な（アラートの出なかった）JSON ログイン（生年月日・住所入り）は LLM に送られていない。",
"attack_scenario":"攻撃者は正規利用者のフォーム送信に紛れて検知を誘発する（またはプロンプトインジェクション検知が利用者の通常チャットに反応する）だけで、その時点の利用者データが第三者の LLM 提供者に送られる。確認が必要な論点（法的結論ではない）: 外部（国外含む）提供者への提供・委託の整理、利用目的の通知、提供者側の保存期間。"+UNV,
"recommendation":"llm.send_fields（例: body_head / query / headers / user_agent / ip をそれぞれ on/off）を追加し、既定でボディ・クエリ値は『パラメータ名と検知箇所の前後数十文字のみ』に縮約。IP は LLM 送信時のみ仮名化（同一 IP は同一トークン）する選択肢。初回設定時に外部 LLM 送信を明示的に有効化させ、送信データの種類を docs/wiki に記載。",
"effort":"M","known":"none","references":[],"related":["L08-02","L17-01","L17-04"]},
{"id":"L17-06","title":"通知（Webhook/Slack/Discord/メール）には送信元 IP と検知ルール文言のみが載るが、LLM が書くインシデント要約（最大 600 文字）が重大度上昇時に外部チャネルへ転送され、証拠中の個人項目が混入しうる",
"area":"notify","category":"security","severity":"low","confidence":"hypothesis",
"summary":"mock 実行では通知 14 通に本文・クエリ・パス中の偽 PII（氏名・電話番号）は一切含まれず、外部に出たのは source_ip(s)・アラートタイトル（LLM アプリのパス名を含む）・ルール説明だった。ただし triage/service.py:305 で LLM の result.summary が incident.summary に保存され、notify/render.py:119-130 で重大度上昇通知の本文に最大 600 文字入る。実 LLM が証拠中の氏名等を要約に書けば Slack/Discord 等の第三者サービスに流れる。通知に載せる項目（IP・要約）を選べる設定は無い。",
"evidence":"実測（run1, 受信器 127.0.0.1:22703）: クエリ `user=Yamada%20Hanako%20090-7777-8888`、パス `/api/users/Jiro%20Fakename%20070-3333-4444/..%2f..`、ボディ中の氏名電話を送信 → hook.jsonl の 14 通に 'Jiro','070-3333','090-7777','Hanako' は 0 件。ペイロードのキー: source, kind, severity, title, text, url, fields, data, sent_at。data に source_ip。コード: triage/service.py:305, notify/render.py:104-151, notify/service.py:225-234。実 LLM での要約内容は未確認。",
"attack_scenario":"LLM が『ユーザー Yamada Hanako（090-...）のアカウントに対する SQLi』のように要約し、それが社外 SaaS のチャネルにそのまま転送・保存される。確認が必要な論点: 通知先 SaaS への提供の整理（"+UNV+"）",
"recommendation":"notify.include_summary（既定 false か、redact_text + 電話/氏名マスク後のみ）と notify.include_source_ip の設定を追加。要約生成プロンプトに『個人名・連絡先を書かない』指示を加える。",
"effort":"S","known":"none","references":[],"related":["L17-05","needs-live-llm"]},
{"id":"L17-07","title":"運用者向け文書に『何の個人データを収集・保存・外部送信するか、何日保持するか、誰が見られるか』の説明が無い",
"area":"docs","category":"docs","severity":"low","confidence":"confirmed",
"summary":"docs/wiki で redaction に触れているのは Configuration.md の設定キー列挙（`redaction.*`）と Deception.md の注意 1 行のみで、Gate が保存する項目（クエリ・ボディ先頭 4096B・ヘッダ 64 個、応答ボディは保存しない）、LLM 提供者・通知先へ送る項目、保持期間（現状無期限）、ロール別の閲覧範囲、本人対応の手順についての記述が無い。個人情報・プライバシーに触れる文書は docs/requirements-v0.1-original.md と wave2 計画のみ。",
"evidence":"grep -rli '個人情報|privacy|プライバシー|personal data|保持期間|retention' docs README* HANDOFF.md → requirements-v0.1-original.md, docs/tasks/wave2-*.md, docs/audit/... のみ。grep redaction docs/wiki → Configuration*.md:65, Deception*.md:71 のみ。",
"attack_scenario":"導入者が個人データの取扱い（委託先・保存期間・閲覧者）を社内で説明・審査できず、既定値のまま本番トラフィックを流す。",
"recommendation":"docs/wiki に『データの取扱い（Data handling）』ページを追加: 収集項目表（保存/伏字/非保存）、外部送信先と止め方、保持設定（実装後）、ロール別閲覧範囲、本人対応手順、運用者が確認すべき論点の一覧（法的判断は利用者側で行う旨）。",
"effort":"S","known":"none","references":[],"related":["L17-01","L17-04","L17-05"]},
]
with open(F,"a",encoding="utf-8") as f:
    for o in fs: f.write(json.dumps(o,ensure_ascii=False)+"\n")
