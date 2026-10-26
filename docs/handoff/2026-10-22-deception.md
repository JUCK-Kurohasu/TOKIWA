# 2026-10-22 deception（Mirage）作業ログ

ブランチ: `worktree-agent-a25a08a6567b76bec`（開始時 main=0efcd24 から作られていたため、骨格 c4881e1 へ fast-forward してから作業）

## やったこと
- `deception/tokens.py`: redact に当たらないトークン形式（`[A-Za-z0-9_]`、非ベンダー接頭辞、偽 AWS ID 24 文字・
  シークレット 42 文字）。同一デコイ内の他の値はサーバー秘密由来の鍵で HMAC 派生。ユーザー指定トークンの検証。
- `deception/templates.py` / `render.py`: デコイ本文（.env / SQL / PHP / git config / YAML / JSON / HTML / テキスト）、
  ハニートークンファイル、AI カナリアページ（robots / OpenAPI / llms.txt / HTML）、HTML 挿入スニペット、
  カナリア着地ルート `/api/internal/<値>*`、プレビュー。カナリア値は自然文中にのみ出す。
- `deception/labyrinth.py`: 決定的・有界な迷路（40 ページ事前描画 + ワイルドカード）。
- `deception/matcher.py` + `detect/detectors/deception_trip.py`: デコイパス（正規化）、全フィールドのトークン走査、
  AI カナリア followed（ヘッダ / 組み立てパス / Referer）→ `ai_agent` 0.99、observed → 0.85。
- `deception/service.py`: CRUD、冪等シード、インデックス/描画キャッシュ（コミット後に世代更新）、
  `event.ingested` 購読でトリップ記録（`deception_trips`）・`trip_count/last_tripped` 更新・`deception.tripped` publish。
  他モジュール向け: `create_asset(DeceptionAssetIn)`, `delete_asset(id)`, `disable_asset(id)`。
- `deception/policy.py::build_gate_decoys()` 実装（有効資産のみ）。`api/routes/deception.py`。
- テスト `backend/tests/deception/`（5 ファイル, 95 件）。docs/deception.md（倫理・法的配慮含む）。

## 現在の状態
- `uv run pytest -q` 緑 / `ruff check` / `ruff format --check` 緑。mypy（新規ファイル）緑。

## 共有ファイルの変更（最小限）
- `backend/src/tokiwa/config.py`: **DeceptionSettings（自セクション）のみ** に `labyrinth_prefix`, `html_injection`,
  `canary_header`, `canary_language` を追加。
- `docs/api-contract.md`: デセプション節のみ更新（GET /assets/{id}、クエリ、PATCH/Preview の型）。
- 新規ファイル（拡張ポイント）: `db/models/deception.py`（`deception_trips` テーブル）、`schemas/deception.py`
  （`DeceptionAssetUpdate`, `DeceptionPreview`）。

## 他モジュールへの依頼
- **gate**: 完全一致ルート優先 → 最長前方一致。デコイ応答は 1 リクエスト 1 イベント（`kind=deception`,
  `deception.asset_id`, `http` 付き）。`X-Debug-Auth` を秘匿ヘッダ扱いしないこと（redact 設定に従えば OK）。
- **respond**: deploy_canary は `service.create_asset(DeceptionAssetIn(...))`、revert は `disable_asset(id)` か
  `delete_asset(id)`。検証エラーは `DeceptionError`（ValueError, `.status_code`）。
- **frontend-ops / frontend-core**: `frontend/src/api/types.ts` に `DeceptionAssetUpdate`, `DeceptionPreview`
  （上記フィールド）を追加してほしい（共有ファイルのため未編集）。トリップ一覧は `Event.deception.detail` に
  trip_type が入る。
- **detect-web / 統合**: `/.env` 等は `deception.trip`（critical）も発火する。アラート件数を厳密に数えるテストは
  `engine.overrides["deception.trip"] = False` で切るか件数を調整。
- **lab-eval**: ai_agent プロファイルで HTML の隠し指示を読み `X-Debug-Auth` を付けるとカナリア追従として検知される。

## 未完・次の一手
- Gate 実装と結合した E2E（デコイ配信 → DECEPTION イベント → トリップ）を統合時に確認。
- 迷路のワイルドカード部はページが同一（Gate が静的配信のため）。動的描画が必要なら Gate に描画 API を設ける案。
- トリップ履歴の保持期間（イベントのパージと合わせる）。

## 要判断事項（ユーザー）
- AI カナリアの文言の強さ・言語（`templates.canary_sentences()`、既定は日英併記）。
- robots.txt / llms.txt カナリアを既定で有効にするか（上流ファイルを置き換えるため既定 OFF）。
- `TODO(verify)`: 日本国内運用での法務確認（docs/deception.md §9）。
