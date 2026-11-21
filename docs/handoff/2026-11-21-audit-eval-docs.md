# 2026-11-21 監査対応レーン `eval-docs`（系統 K「評価・文書」）

担当 Issue: #177 → #178 → #176 → #175 → #72/#83/#26 → #107 → #127 → #174（この順）。
所有: `backend/src/tokiwa/eval/`, `eval/`, `backend/tests/eval/`, `docs/purple-team.md`, `lab/README.md`,
`docs/wiki/Lab-and-Evaluation*.md`, `config.py` の `DetectionSettings.sigma_rule_dirs` 既定値。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #177 Sigma 既定パス | 完全（/health の degraded 表示のみ他レーン依頼） | `config.default_sigma_rule_dirs()`: パッケージ位置基準の絶対パス（ソース → `<repo>/rules/sigma`、インストール → `<venv>/../rules/sigma` = Docker の `/app/rules/sigma`）。ローダは見つからないディレクトリを ERROR（ストアごとに 1 回）+ `SigmaRuleStore.missing_dirs`。eval: `RunResults/metrics.pipeline.sigma_rules_loaded`・`sigma_rule_dirs_missing`、0 件・欠落時は note。report.md ヘッダに件数。wiki Configuration 4 言語の既定値行 | 9a7c6e4 |
| #178 compare の比較可能性 | 完全 | metrics.json に `comparability`（dataset sha256・meta の seed/mix/generator_version・llm_mode/provider・detectors_enabled・sigma_rules_loaded・replay バッチ設定・detection/triage/deception 設定値）。`compare_runs` が `comparable`/`mismatches` を返し、CLI は `NOT COMPARABLE` を表示、`--fail-on-regression` で終了コード 3（`--allow-mismatch` で 1/0 判定）。KEY_METRICS に `detection.attack_session_rate_medium_plus`・`alerts.total`（stable, 相対 10%・最低 2）・`alerts.by_detector[<id>]`（stable, 相対 20%・最低 2）。`MetricSpec` NamedTuple 化。report.md に比較不能の明示。CLI wiki 4 言語・eval/README | (下記) |
| #176 mock LLM の明示 | 未着手 | | |
| #175 区間・分母・medium+ | 未着手 | | |
| #72 / #83 / #26 ARTEX 取り込み | 未着手 | | |
| #107 ラボ文書 | 未着手 | | |
| #127 実ツール形プロファイル | 未着手 | | |
| #174 生成器別の報告 | 未着手 | | |

## ベースライン（変更前, worktree HEAD fad4626, backend/ から, mock LLM）

`tokiwa eval run --dataset ../eval/datasets/lab-mini.jsonl --llm mock` を 2 回:
attack sessions 5/5, benign FPR 0.0, alerts 87 (precision 1.0), AI P=R=AUC=1.0, LLM calls 154,
by_tier {deep 64, fast 22, rules 6}, event_recall 0.9617, per_detector 29 行。tokens_per_alert は 5738.8 / 5753.7 と
実行ごとに揺れる（プロンプトに時刻が入るため）。リポジトリ直下から実行しても editable install なら 87 / 154（下記 #177）。
監査時の 156 calls との差は未調査（同一コードで 2 回とも 154 なので決定的）。

mypy: 既知の 4 エラー（detect/context.py:51, db/session.py:39,43, intel/sources/_common.py:311）。

## 要判断

- **#178 comparability の無い古い metrics.json との比較は「比較不能」扱い**（`--fail-on-regression` で終了コード 3）。
  既存ベースラインは取り直しが必要。CI 未導入（wave2）なので影響は小さいと判断。緩めるなら
  `report.comparability_mismatches` の先頭分岐を「警告のみ」に変える。
- **#178 `stable` 指標（alerts.total・検知器別件数）は増加も回帰扱い**（status `changed`）。同一データ・同一設定で
  アラート量が動くのは説明が要る変化なので。誤検知削減で減らした場合も止まるため、その時はベースラインを更新する。
  許容幅は lab-mini 2 回実行で alerts 87/87・検知器別も同一（決定的）だったので相対 10%/20%・最低 2 件とした。
- **#178 終了コード 3 = 比較不能**（2 は既存の EvalError / 引数エラーで使用済み）。

- **#177 既定値の変更（方式 b: 既定を変え docs・wiki・テストを同時に直す）**: `detection.sigma_rule_dirs` の既定を
  CWD 相対 `../rules/sigma` から「パッケージ位置から解決した絶対パス」に変更。理由: 旧既定はソースチェックアウト以外
  （コピーしたソース・非 editable インストール）で CWD が backend/ でないと黙って Sigma 全停止したため。明示設定は
  従来どおり優先し、相対パスはローダが CWD → backend/ の順で解決する（旧設定ファイル・環境変数はそのまま動く）。
  editable install（`uv sync`）では旧既定と同じディレクトリを指すので数値は変わらない（lab-mini: alerts 87 のまま）。
  フォールバック順: (1) `tokiwa` が `<repo>/backend/src/tokiwa` から import されていれば `<repo>/rules/sigma`、
  (2) `<sys.prefix>/../rules/sigma`（Docker: `/app/.venv` → `/app/rules/sigma`。イメージは環境変数でも指定済み）、
  (3) どちらも無ければ (1)（無ければ (2)）のパスをそのまま返し、ローダが起動時 ERROR を出す。

## 失敗した試み

## 担当外の変更

- `backend/src/tokiwa/detect/sigma/loader.py`（sigma モジュール）: `rule_dirs()` の「not found」を WARNING → ERROR
  （ストアごとに 1 回）にし、`self.missing_dirs: list[str]` を追加（#177）。ロジックは不変。
- `backend/src/tokiwa/config.py`: `import sys` と `default_sigma_rule_dirs()` 関数を `DetectionSettings` の直前に追加
  （所有範囲の `sigma_rule_dirs` 既定値のため）。
- `docs/wiki/Configuration*.md`（4 言語）: `sigma_rule_dirs` の既定値の行のみ。

## 他レーンへの依頼

- **http-hardening（health.py 所有）**: `/api/v1/health` で Sigma ルールディレクトリ欠落を degraded 表示してほしい（#177）。
  契約: `from tokiwa.detect.sigma.loader import get_rule_store`; `store = get_rule_store()`;
  `store.missing_dirs: list[str]`（設定どおりの文字列。空 = 全ディレクトリあり。起動フック `_sigma_startup` 後に有効）、
  `sum(1 for r in store.rules() if r.origin == "file")` = ロード済みファイルルール数。
  提案: `missing_dirs` が空でない、またはファイルルール 0 件なら `{"status": "degraded", "checks": {"sigma": {...}}}`。
  HTTP ステータスを 200 のままにするか 503 にするかは Docker HEALTHCHECK（deploy/healthcheck.py）との兼ね合いで判断を。

## 未検証事項
