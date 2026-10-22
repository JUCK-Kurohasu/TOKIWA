# タスク: sigma — Sigma ルール評価器・ルール管理・検知器管理 API

## 目的
Sigma 形式のルールを TOKIWA の `Event` に対して直接評価する（pySigma はバックエンド変換用で、ここでは
インメモリ評価が必要なため自前実装する）。ルールはファイル（`rules/sigma/`）と DB（`rules` テーブル）の両方から。
LLM が提案したルール（intel-advisor）も検証してここに `proposed` で入る。

## 担当範囲
- `backend/src/tokiwa/detect/sigma/`（新規: parser.py, evaluator.py, fieldmap.py, loader.py）
- `backend/src/tokiwa/detect/detectors/sigma.py`（Detector 実装）
- `backend/src/tokiwa/api/routes/rules.py`, `backend/src/tokiwa/api/routes/detectors.py`
- `rules/sigma/**/*.yml`（初期ルールセット 15 本以上）
- `backend/tests/sigma/`、`docs/detection/sigma.md`

## 要件
1. Sigma 仕様サブセット: `title,id,status,level,description,tags,logsource,detection,falsepositives`。
   detection: 複数 selection（map / list of maps）、修飾子 `contains|startswith|endswith|re|all|cidr|base64|
   base64offset|windash|lt|lte|gt|gte|exists`（未知の修飾子は検証エラー）、ワイルドカード `*` `?`、
   condition 式（`and/or/not/()/1 of selection*/all of them/1 of them`）。大文字小文字は Sigma 既定（非区別）に従う。
2. フィールドマッピング（`fieldmap.py`）: Sigma の慣用フィールド（`cs-uri-query`, `cs-uri-stem`, `c-uri`,
   `c-useragent`, `cs-method`, `sc-status`, `c-ip`, `cs-host`, `cs-referer`, `request_body` 等）と ECS 名
   （`url.path`, `http.request.method`, `source.ip`, `user_agent.original` ...）を `Event` の属性に対応付け。
   logsource（`category: webserver|proxy`, `product: tokiwa`）で適用イベント種別を絞る。
3. ローダ: `settings.detection.sigma_rule_dirs` の YAML と DB `rules`（status=active）を読み込み、コンパイル済み
   ルールをキャッシュ。DB 変更時に再読込（routes から `reload()` を呼ぶ）。不正ルールはスキップしてログ。
4. Detector `sigma`: 一致したルールごとに AlertDraft（`rule_id="sigma:<id>"`, level→Severity, tags から
   MITRE（`attack.t1190` → `T1190`）を抽出）。`RuleRow.hit_count` の更新はバッチでまとめる（毎イベント DB 書込しない）。
5. API（docs/api-contract.md の「検知・ルール」）: rules CRUD、`/rules/validate`、`/rules/{id}/approve`、
   detectors 一覧と有効/無効切替（`settings_kv["detection.overrides"]` に保存し、`@on_startup` で
   `get_detection_engine().overrides` に復元）。変更は `tokiwa.audit.record_audit` に記録。
6. 初期ルール（`rules/sigma/web/`, `rules/sigma/ai/`, `rules/sigma/llm_app/`）: 一般的な Web 攻撃に加え、
   AI エージェント特有の痕跡（例: `/.well-known/ai-plugin.json` / `/openapi.json` 探索、MCP エンドポイント探索、
   LLM 系 UA）、LLM アプリへのプロンプトインジェクション定型句など。各ルールに falsepositives を書く。

## 受け入れ基準
- パーサ/評価器の単体テスト（修飾子・condition・ワイルドカード・不正ルール）と、ルールセットの陽性/陰性テスト。
- `POST /api/v1/rules` で不正 YAML は 422、正しいルールは即時に検知へ反映（統合テスト: ルール作成 → ingest → アラート）。
- detectors API で無効化した検知器が発火しないこと、再起動相当（engine リセット + startup）後も保持されること。
