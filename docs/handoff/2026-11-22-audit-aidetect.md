# 2026-11 監査対応: aidetect レーン（系統 C「AI 判定・相関」の工数 S）

担当 Issue（この順）: #19 (high), #88, #124 + #115 + #85（UA 表）, #125。指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`
（#19=L04-01, #88=L04-08, #124=L02-06, #115=L02-05, #85=L01-08, #125=L02-07）。再現は `docs/audit/2026-11/repro/L04/lab/`。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #19 | 部分（残り: センサー別の時計ずれのメトリクス化と UI 警告） | (1) ingest で未来方向のスキュー上限（`detection.max_future_skew_seconds`、既定 120 秒）を超えた timestamp を受信時刻に置き換え、タグ `clock_skew`・ラベル `ingest.original_timestamp`（サーバー所有の `ingest.*` なので送信側は事前に入れられない）。バッチごとに WARNING ログ、監査 `ingest.clock_skew` はトークンごとに 10 分に 1 回。過去方向は変更しない。naive な timestamp は比較時のみ UTC として扱う。(2) `SessionTracker` の基準時刻 `max_event_ts` を「壁時計 + スキュー上限」で頭打ち（in-process の呼び出し元＝eval ハーネス等にも効く）。壁時計は注入可能（`clock=`）。統計 `future_capped`。(3) 再現（ts_poison.py の +31 分 / +1 日 / +70 年）を `tests/aidetect/test_ai_clock_skew.py` に移植。repro のイベントは 2026-10-01 起点（過去）なので、壁時計をトラフィックに追従させて注入し、毒は同じ `sensor_id` で送る。上限を外すと再び分断されることも確認するテスト付き。(4) expire_idle の基準をセンサー別にした: `sensor_id` ごとに（上限付きの）最大時刻を持ち（LRU 256 個、溢れたら全体の値）、セッションは最新の活動を観測したセンサーの時計で失効判定。別センサーが 3 時間前のバックログを再送しても、ライブのセンサーの時計で毎フラッシュ失効・分断されなくなった（旧挙動ではバラバラになることもテストで固定） | b901d1c, （次のコミット） |
| #88 | 未着手 | | |
| #124 + #115 + #85 | 未着手 | | |
| #125 | 未着手 | | |

## 評価（`tokiwa eval run --dataset eval/datasets/lab-mini.jsonl --llm mock`）

- 変更前（672f7a5）: 攻撃セッション検知 5/5、正常 FPR 0/3、alerts 87（precision 1.0）、AI 帰属 P 2/2・R 2/2・AUC 1.0。
  混同行列: ai_agent→ai_agent 2、automated_scanner→automated_scanner 1、benign→benign 3、human→benign 1・human 1。

## 要判断

- **#19 既定動作の変更**: 既定で未来 120 秒超の timestamp を受信時刻に置き換える（(b) 既定を変えた側。元の時刻はラベルに残るので情報は失わない）。
  時計が 2 分以上進んだセンサーは、そのイベントの時刻がすべて受信時刻になる（＝バッチ内の間隔が 0 になり、AI 判定のタイミング特徴
  （burst/think）がそのセンサーでは効かなくなる）。試算: synth の AI エージェント 25 要求を全部同時刻にすると ai 0.09・
  `automated_scanner` 判定になる（クラッシュはしない）。NTP を直すのが本筋で、タグ `clock_skew` が付いたイベントが出たらセンサーの時計を疑う。上限を広げたい場合は `detection.max_future_skew_seconds` を上げる。
- **#19 センサー別の失効判定は攻撃への防御ではない**（未バインドの ingest トークンは任意の `sensor_id` を名乗れる。偽装時刻を抑えているのは
  壁時計の上限の方）。副作用: 送信が止まったセンサーのセッションは、そのセンサーが再び送るか LRU で追い出されるまでライブに残る
  （永続化は変わらない。#88 の「高スコアは追い出しにくい」と合わせると、止まったセンサーの AI セッションがしばらく枠を占める）。
  同一センサー内での過去時刻の混在（再起動直後のスプール放出など）は従来どおり（ライブの時計で失効）。
- 監査ログの間引き（トークンごとに 10 分）はプロセス内の状態（複数ワーカーではワーカーごと）。時計ずれのセンサー別メトリクスと UI 警告（recommendation の後半）は未実装。

## 既定動作の変更

- `detection.max_future_skew_seconds`（新設、既定 120）: ingest で未来時刻をクランプ、タグ `clock_skew`、ラベル `ingest.original_timestamp`。

## 失敗した試み

- なし

## 担当外の変更

- `backend/src/tokiwa/config.py`: `DetectionSettings` にフィールド追加のみ（`max_future_skew_seconds`）。
- `backend/src/tokiwa/api/routes/ingest.py`: timestamp 検証（`clamp_future_timestamp` / `_report_clock_skew`）の追加のみ。`stamp_provenance` の後に実行（前に入れると `ingest.*` ラベルが消される）。
- `docs/wiki/Configuration*.md`（4 言語）: 表に 1 行追加。

## 他レーンへの依頼

- なし

## 未検証事項

- 実センサー（nginx アダプタ・Gate）の時計ずれでの挙動は未観測（テストは注入時刻）。
