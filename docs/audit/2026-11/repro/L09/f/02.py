F = {"id":"L09-02","title":"却下・取り消しが記憶されず、同じ対象が次のアラートで再提案され、自動承認時は取り消した誤遮断が即座に再適用される",
"area":"respond","category":"reliability","severity":"medium","confidence":"likely",
"summary":"重複判定は (action_type, 正規化 target) が proposed/approved/active の行だけを対象にしており、rejected/reverted/expired/failed は考慮されない。アナリストが『共有 IP なので遮断しない』と却下・取り消しをしても、その IP から次の high 以上のアラートが来ればトリアージが同じ提案を新規作成する。auto_approve が有効な型では、取り消した直後の次のアラートで同じ遮断が自動承認されて再び active になる（取り消しが効かないフラッピング）。抑止（suppress / do-not-act）や許可リストへの登録導線も無い。",
"evidence":"backend/src/tokiwa/respond/service.py:57（OPEN_STATUSES = proposed/approved/active）, :149-160（重複検索はこの 3 状態のみ）, :212-214（新規行なら auto_approve_allowed で即承認）; triage/service.py:250,316（アラート・インシデントのトリアージ毎に _propose_actions）",
"attack_scenario":"攻撃者が NAT/プロキシ共有 IP から断続的にデコイを叩き続けると、アナリストが誤遮断を取り消すたびに再提案（承認依頼通知も再送）され、自動承認構成では正規利用者の遮断が繰り返し復活する。運用者は auto-approve 自体を切るしかなくなる。",
"recommendation":"却下・取り消し時に『抑止』（対象＋型＋期限、理由付き）を記録し、propose 時に一致すれば新規作成せず監査のみ（自動承認も禁止）にする。UI の却下/取り消しダイアログに『この対象を N 時間/恒久的に再提案しない』『known-good に追加』を追加。テスト: 取り消し後の再提案が自動承認されないこと。",
"effort":"S","known":"none","references":[],"related":["L09-01"]}
