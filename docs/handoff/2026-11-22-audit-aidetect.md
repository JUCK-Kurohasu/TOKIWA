# 2026-11 監査対応: aidetect レーン（系統 C「AI 判定・相関」の工数 S）

担当 Issue（この順）: #19 (high), #88, #124 + #115 + #85（UA 表）, #125。指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`
（#19=L04-01, #88=L04-08, #124=L02-06, #115=L02-05, #85=L01-08, #125=L02-07）。再現は `docs/audit/2026-11/repro/L04/lab/`。

チェック（9d7bd32 時点）: backend 全体 1522 passed（失敗 0。respond の既存テストで aiosqlite の「Event loop is closed」スレッド警告が
出るが本レーンとは無関係）、ruff check / format 緑、mypy は既知 4 件のみ、`check_wiki.py` OK。フロントは触っていない。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #19 | 部分（残り: センサー別の時計ずれのメトリクス化と UI 警告） | (1) ingest で未来方向のスキュー上限（`detection.max_future_skew_seconds`、既定 120 秒）を超えた timestamp を受信時刻に置き換え、タグ `clock_skew`・ラベル `ingest.original_timestamp`（サーバー所有の `ingest.*` なので送信側は事前に入れられない）。バッチごとに WARNING ログ、監査 `ingest.clock_skew` はトークンごとに 10 分に 1 回。過去方向は変更しない。naive な timestamp は比較時のみ UTC として扱う。(2) `SessionTracker` の基準時刻 `max_event_ts` を「壁時計 + スキュー上限」で頭打ち（in-process の呼び出し元＝eval ハーネス等にも効く）。壁時計は注入可能（`clock=`）。統計 `future_capped`。(3) 再現（ts_poison.py の +31 分 / +1 日 / +70 年）を `tests/aidetect/test_ai_clock_skew.py` に移植。repro のイベントは 2026-10-01 起点（過去）なので、壁時計をトラフィックに追従させて注入し、毒は同じ `sensor_id` で送る。上限を外すと再び分断されることも確認するテスト付き。(4) expire_idle の基準をセンサー別にした: `sensor_id` ごとに（上限付きの）最大時刻を持ち（LRU 256 個、溢れたら全体の値）、セッションは最新の活動を観測したセンサーの時計で失効判定。別センサーが 3 時間前のバックログを再送しても、ライブのセンサーの時計で毎フラッシュ失効・分断されなくなった（旧挙動ではバラバラになることもテストで固定） | b901d1c, b2ceaa2 |
| #88 | 部分（(2)(3)(4) 済み。(1) 追い出し時のサマリ引き継ぎは未実装） | (4) 上限を設定化: `detection.max_live_sessions`（既定 4096 = 旧固定値、`Sessionizer.max_sessions` クラス属性は None なら設定を読む）。(2) 追い出しを重み付きに: LRU の古い側から最大 `EVICT_SCAN`=128 件を見て、1 リクエスト・低スコア（< 0.35）のものを見つけ次第追い出す（古い側が安いうちは従来の LRU と同じ）。AI 判定・スコア ≥ しきい値・カナリア/デコイ接触のあるセッションは「二度目の機会」として LRU の末尾へ回す。安いものが無ければ (要求数 min(n,5), スコア) が最小のもの、全部保護対象ならスコア最小の保護対象。作成直後（要求数 0）のセッションは候補から除外。(3) 統計 `evicted_valuable`（5 要求以上または証拠ありを追い出した数）を追加し、Sessionizer のフラッシュ時に 60 秒窓で追い出し数が `max(64, 上限/4)` 以上または `evicted_valuable` > 0 なら WARNING（5 分に 1 回）。テスト `tests/aidetect/test_ai_eviction.py`: 容量 64 に 1 リクエスト客 ×192 を挟んでも AI セッションが 1 つのまま（旧 LRU では 2 つに割れることも同じテストで固定）、6 リクエスト客の洪水でも AI セッションが残る、全部保護対象でも上限を守る、設定の読み込み、警告の間引き | f7dcbb0 |
| #124 | 部分（残り: katana・httpx(PD)・wapiti・wafw00f・arjun・dalfox の UA を一次情報で確認して追加。TODO(verify)、下記 未検証） | UA 表を `aidetect/ua_catalog.py` の `UA_RULES` 1 つにまとめ、`fingerprints._UA_RULES`（全ファミリ、順序どおり）と `web_recon._TOOLS`（`alert` 付き＝スキャナ系のみ）をそこから生成。各ツールのパターンは旧 2 表の和集合（旧来一致したものは一致し続ける）。Web 側は 1 本の大文字小文字無視の選択（グループ名 `t<i>`、元 UA の位置で切り出し）。既存アラートの名前は維持（`alert_name`: invicti→`netsparker`、zap→`owasp_zap`。`client_tool` も旧 id のまま）。AI 判定側に新たに入ったスキャナ: commix, havij, xsstrike, hydra, dirsearch, joomscan, skipfish, qualys, appscan, webinspect, paros, jaeles, fimap, morfeus, zmeu, jorgee, censys（→ `scanner_client` の反証が効く）。テスト `tests/aidetect/test_ua_catalog.py`: スキャナ集合 = Web 検知器の集合 = 見本 UA の集合、見本ごとに両方が同じツールと判定 | b94ef36 |
| #115 | 部分（残り: robots.txt→同一 UA で本体を取る逐次パターンの特徴化、OpenAI-Operator 等の他の自己申告 UA の棚卸し） | `ModelContextProtocol/… (Autonomous` → `mcp-fetch-autonomous`、`(User-Specified` → `mcp-fetch-user-specified`、その他 `ModelContextProtocol/` → `mcp-fetch`（いずれも AI_AGENT。`ai.llm_client_fingerprint` が LOW で鳴る）。AI 信号の強さを `scoring.DECLARED_CLIENT_STRENGTH` でツール別に（1.0 / 0.6 / 0.8） | 同上 |
| #85 | 完全 | `artex-enrich/` → `artex-enrich`、`spa-api-recon` → `artex-api-recon`、`artex[-_]…` → `artex`（AI_AGENT、強さ 0.6）。`spa-api-recon` は UNKNOWN 時代に付いていた `nonstandard_mozilla_ua`（自動化クライアント）を失わないよう、エンジントークン（AppleWebKit/Gecko/Trident/Presto）の無い Mozilla 接頭辞の AI_AGENT にも付けるようにした（ChatGPT-/Claude-User は対象外）。`docs/detection/ai-attacks.md` に既知 UA を追記 | 同上 |
| #125 | 部分（文書化のみ。評価のアブレーションと公開事例での検証は未実施） | `docs/detection/ai-attacks.md` §2.1 と §7-12 に「`x-stainless-*` / MCP ヘッダは LLM アプリ→プロバイダ・MCP クライアント→サーバー区間のもので、`llm_sdk_headers` は LLM アプリの API や MCP エンドポイントを守るときだけ有効。来ないことは AI でない証拠にならない」と明記。`fingerprints.py` のヘッダ定義にも同じ注記。**重み（+1.0）は変えていない**（変える根拠となる実トラフィックが無い。前提違いなら「載らないので効かない」だけで誤検知は増えない） | 9d7bd32 |

## 評価（`tokiwa eval run --dataset eval/datasets/lab-mini.jsonl --llm mock`）

- 変更前（672f7a5）: 攻撃セッション検知 5/5、正常 FPR 0/3、alerts 87（precision 1.0）、AI 帰属 P 2/2・R 2/2・AUC 1.0。
  混同行列: ai_agent→ai_agent 2、automated_scanner→automated_scanner 1、benign→benign 3、human→benign 1・human 1。
- #19・#88・#124/#115/#85 の後: **変化なし**（同じ値・同じ混同行列、検知器別の集計も一致）。mock の推定費用（実行しない場合の見積り）だけ
  $1.0892 → $1.0910 と微差（プロンプト文字数の差。検知結果は同一）。lab-mini のイベントは 1 センサー（`sim`）・過去日付を now に寄せる
  再生なので、時刻の上限・センサー別の時計・追い出し（8 セッション）はいずれも働かない。

## UA の重み（#115 / #85、2026-11-22 実測）

6 回の行儀よい GET（robots → ページ）セッションの AI スコア（しきい値 0.7）:

| UA | 変更前 | 変更後 |
|---|---|---|
| 未知の UA（`someclient/1.0` 等） | 0.20 benign | 0.20 benign |
| `ModelContextProtocol/1.0 (Autonomous; …)` | 0.20 benign | 0.51 benign |
| `ModelContextProtocol/1.0 (User-Specified; …)` | 0.20 benign | 0.37 benign |
| `artex-enrich/1.0` | 0.20 benign | 0.37 benign |
| `Mozilla/5.0 (spa-api-recon[ spider])` | 0.34 unknown | 0.54 unknown |
| `dirsearch/0.4.3` / `commix/3.9` | 0.20 benign | 0.03 human（scanner_client） |

UA だけでは AI 判定（0.7）に届かない（テストで固定）。同じ UA で synth の AI エージェント挙動にすると 0.94〜0.999 で ai_agent のまま
（スキャナ UA でも 0.993 → 0.944 に下がるだけ）。数値は `DECLARED_CLIENT_STRENGTH`（scoring.py）で調整できる。

## 要判断

- **#19 既定動作の変更**: 既定で未来 120 秒超の timestamp を受信時刻に置き換える（(b) 既定を変えた側。元の時刻はラベルに残るので情報は失わない）。
  時計が 2 分以上進んだセンサーは、そのイベントの時刻がすべて受信時刻になる（＝バッチ内の間隔が 0 になり、AI 判定のタイミング特徴
  （burst/think）がそのセンサーでは効かなくなる）。試算: synth の AI エージェント 25 要求を全部同時刻にすると ai 0.09・
  `automated_scanner` 判定になる（クラッシュはしない）。NTP を直すのが本筋で、タグ `clock_skew` が付いたイベントが出たらセンサーの時計を疑う。上限を広げたい場合は `detection.max_future_skew_seconds` を上げる。
- **#19 センサー別の失効判定は攻撃への防御ではない**（未バインドの ingest トークンは任意の `sensor_id` を名乗れる。偽装時刻を抑えているのは
  壁時計の上限の方）。副作用: 送信が止まったセンサーのセッションは、そのセンサーが再び送るか LRU で追い出されるまでライブに残る
  （永続化は変わらない。#88 の「高スコアは追い出しにくい」と合わせると、止まったセンサーの AI セッションがしばらく枠を占める）。
  同一センサー内での過去時刻の混在（再起動直後のスプール放出など）は従来どおり（ライブの時計で失効）。
- **#88 保護の副作用**: 保護対象（AI 判定・デコイ接触）は追い出されにくいので、攻撃者が多数の IP からデコイを 1 回ずつ踏めば
  「保護されたセッション」で枠を埋められる。その場合も 1 回の追い出しで見るのは最大 128 件で、全部保護対象ならスコア最小のものを
  追い出すので上限は守られる（テスト済み）。ただしその状態では AI セッションも追い出され得る。追い出し 1 回あたりの計算量は最大 128 件の走査。
- **#88 (1) サマリ引き継ぎを入れていない理由**: 同じキー（IP+指紋）の新セッションに id・カウンタ・ピーク・カナリア数を引き継ぐ設計
  （追い出し → アイドル時間内に再来 → 同じ id で継続）までは詰めたが、時間の都合で未実装。洪水の大半は (2) で防げる。
- 監査ログの間引き（トークンごとに 10 分）はプロセス内の状態（複数ワーカーではワーカーごと）。時計ずれのセンサー別メトリクスと UI 警告（recommendation の後半）は未実装。

## 既定動作の変更

- `detection.max_future_skew_seconds`（新設、既定 120）: ingest で未来時刻をクランプ、タグ `clock_skew`、ラベル `ingest.original_timestamp`。
- `detection.max_live_sessions`（新設、既定 4096 = 旧固定値なので容量は不変）。追い出し順が純粋な LRU から「1 リクエスト・低スコア優先、証拠ありは後回し」に変わった。
- UA 分類: 旧 Web 表だけにあった 17 ツールが AI 判定でも `scanner` に、MCP fetch / ARTEX の UA が `ai_agent`（`ai.llm_client_fingerprint` が LOW で鳴る）に。
  Web 側は各ツールのパターンを和集合にしたので、`\b` 境界が外れたもの（例 `sqlmap` が `xsqlmapx` にも一致）や `ZAP/` の追加でわずかに広がった。

## 失敗した試み

- なし

## 担当外の変更

- `backend/src/tokiwa/config.py`: `DetectionSettings` にフィールド追加のみ（`max_future_skew_seconds`, `max_live_sessions`）。
- `backend/src/tokiwa/api/routes/ingest.py`: timestamp 検証（`clamp_future_timestamp` / `_report_clock_skew`）の追加のみ。`stamp_provenance` の後に実行（前に入れると `ingest.*` ラベルが消される）。
- `docs/wiki/Configuration*.md`（4 言語）: 表に 2 行追加。
- `backend/src/tokiwa/detect/detectors/web_recon.py`: `web.scanner_ua` の UA 表（`_TOOLS`）を `ua_catalog` からの生成に置換し、照合を
  `match_scanner_ua()` に（他の検知器・マーカーヘッダ・OAST は不変）。`docs/detection/web.md` の 1 行。

## 他レーンへの依頼

- なし

## 未検証事項

- 実センサー（nginx アダプタ・Gate）の時計ずれでの挙動は未観測（テストは注入時刻）。
- **追加しなかった UA（TODO(verify)）**: katana、httpx（ProjectDiscovery）、wapiti、wafw00f、arjun、dalfox、Burp/Caido 系。
  一次情報（各 README・ソース）を確認できなかった（このサンドボックスは外部に出られない）。確認できたら `ua_catalog.py` に
  スキャナ（`alert` 付き）として足し、`tests/aidetect/test_ua_catalog.py` に見本 UA を足す。
  なお `nuclei` のパターンは旧 Web 表から `projectdiscovery` を含むので、PD 製ツールの UA にこの語が入っていれば nuclei と表示される（未確認）。
- MCP fetch サーバーの UA 文字列は監査（L02-05）が公式ソースで確認したものをそのまま使った。ここでは再確認していない。
- OpenAI-Operator / ChatGPT Agent 等の他の自己申告型 UA の棚卸し（#115 の recommendation 後半）は未実施（一次情報が要る）。
- テストの見本 UA（`SCANNER_SAMPLES`）はパターンを通すための文字列で、各ツールの現在の既定 UA だという主張ではない。

## 他レーン・後続への申し送り

- 3 つ目の UA リスト `rules/sigma/web/web_scanner_useragent.yml`（Sigma）は今回統合していない（Sigma ルールはデータとして別系統。
  `web.scanner_ua` と重複して鳴る）。統合するなら Sigma 側を削るか、`ua_catalog` から生成するかを決める。
