# 2026-11 監査対応: llm-triage レーン（系統 F「LLM・トリアージ」）

担当 Issue（この順）: #35, #96, #98, #172, #62。指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`
（#35=L08-01, #96=L08-04, #98=L08-10, #172=L18-07, #62=L08-08）。再現は `docs/audit/2026-11/repro/L08/`。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #35 | 完全 | (1) 単価表にないモデルは **最も高い既知単価**（トークン種別ごとの最大。`llm.pricing` の上書きも含む）で見積もる fail-closed（`llm/pricing.py::price_for` / `unpriced_rates`）。(2) モデル名の正規化 `normalize_model`: 小文字化、Bedrock 形式の接頭辞（`anthropic.` / `us.anthropic.` / `global.anthropic.`）と `anthropic/`、スナップショット形の接尾辞（`-YYYYMMDD` / `@YYYYMMDD` / `-vN[:N]` / `-latest`）だけを除く。汎用の前方一致はしない（`claude-opus-5-9` を兄弟モデルの単価で推測しない＝未知扱い）。(3) 各呼び出しに `llm_calls.cost_basis`（nullable 列。`table` / `snapshot` / `unpriced` / NULL=課金なし）を書き込み時に記録（structured・chat の両経路。サーバー側フォールバックの served model も正規化）。トークン 0（予算超過・エラー）は NULL で「料金不明の呼び出し」に数えない。(4) `/llm/usage` に日別 `unpriced_calls` と期間の `unpriced_models`、`/llm/config` に `unpriced_models`（設定中のモデルで単価なし。mock は空）、`LLMCall.cost_basis`。使用量タブに警告文、設定タブの予算メーター下に警告、呼び出し履歴の費用に `*`（見積もり）。ゲートウェイ生成時と見積もり時に WARNING。(5) 整合テスト: `BUILTIN_ANTHROPIC_MODELS` と既定モデルが全部 `table` で引けること、表のキーが正規形であること。表に `claude-fable-5` / `claude-opus-4-6` / `claude-sonnet-4-6` を追加（出典は claude-api リファレンスのモデル表＝キャッシュ 2026-11-03、`TODO(verify)`）。wiki LLM ×4、api-contract | 68e8ea8 |
| #96 | 部分（ノンス以外は完全） | `llm/prompting.py` を書き直し。(1) `max_chars` を **エスケープ後** の長さで判定。超えたら長い文字列を 4096→1024→256→64 文字に段階的に切り詰め（JSON は有効なまま・全イベントが残る）、それでも超えるときだけ `\uXXXX` やサロゲート対を分断しない位置で切る（`fit_json` / `_hard_cut`）。(2) ゲートウェイの `_cap_input` を `cap_prompt()` に置換: 先頭と末尾（最大 8,000 文字）を残し、切れ目の前後で封筒を閉じ直す / `name="truncated"` で開き直す（データが封筒の外に出ない・閉じタグと末尾の指示が残る・タグを分断しない）。triage は `LLMGateway.max_input_chars()`（実行時オーバーレイ込み）に合わせてブロック予算を比例配分し（`build_user_prompt(..., max_chars=)`）、通常はゲートウェイで切られない。データの **後** にも指示を置き（trailer）、再試行の注意書き（RETRY_NOTE）は末尾の指示に含めた（追記ではない）。プロンプト版 `triage.alert@2` / `triage.incident@2`。(3) NFKC + 不可視文字除去後に `untrusted[_- 空白]*data` を含む文字列（値・キー）の語を `[TOKIWA:envelope-tag-lookalike]` に置換。Cc / Cf / Cs / Co / Zl / Zp・ハングルのフィラー・異体字セレクタを `\u` エスケープ（可逆。孤立サロゲートで UTF-8 送信が落ちる問題も解消。フロントの invisible.ts と同じ集合 + 異体字セレクタ + 私用領域）。封筒名の不正文字も `_` に置換。テスト `tests/llm/test_llm_prompting.py`（110 件。PoC の Variant B・Unicode 版を回帰テスト化、切断位置を総当たり）。docs/security/llm-safety.md | 4551664 |
| #98 | 部分（(1)(2) は完全。(3) 通知・(4) 暗号化・DNS 解決先の検査は未） | 新規 `llm/endpoints.py::validate_runtime_base_url`: 実行時に設定する base_url は https 必須（http は `localhost` / 127.0.0.0/8 / `::1` のみ）、リンクローカル・メタデータ（169.254.169.254・`fd00:ec2::254`・100.100.100.200・`metadata.google.internal` 等）・0.0.0.0/8・マルチキャスト・ブロードキャストを拒否。数値の別表記（`2852039166`・`0xa9.0xfe.0xa9.0xfe`・8 進・`169.254.43518`・`::ffff:169.254.169.254`）は `socket.inet_aton` / IPv4 射影で正規化して判定。`LLMConfigUpdate` の検証と、保存済みの行を読むとき（`clean_overlay`）の両方で適用。**キーと宛先の束縛**: URL を変えるとそのプロバイダの保存済みキーを破棄（同じ更新で新キーが来たら新キーを束縛）、overlay の `_key_bound_to` に「どの URL 用に入力されたキーか」を保存し、実行時 URL があるときは束縛が一致するキーだけを使う。キーが無ければ空キー（`SecretStr("")`）で上書きし、静的キー・`ANTHROPIC_API_KEY` も送らない（Anthropic SDK には `api_key` を明示して渡しているので SDK 側の環境変数チェーンも働かない。キーが無ければクライアント自体を作らない）。`GET /llm/config` に `api_key_rebind_required`、設定画面に警告と URL 欄の説明。テスト `tests/llm/test_llm_endpoint_binding.py`（監査シナリオ: env にキー → URL だけ攻撃者ホストへ → 接続テストでクライアントが作られないこと）。wiki LLM ×4・llm-safety・api-contract | (この行のコミット) |
| #172 | 未着手 | | |
| #62 | 未着手 | | |

## 要判断

- **#96 封筒名のノンス化（推奨 (4)）は未実装** → #96 は「部分」。理由: `<` のエスケープと類似タグの置換で、データから封筒を閉じる・偽装する
  経路は塞いだ。ノンスはタグ名を呼び出しごとに変えるため、コパイロット / intel のプロンプト文言（`<untrusted_data>` を名指し）、
  mock / ルールフォールバックの封筒パーサ（`triage/fallback.py::_BLOCK_RE`）、監査ログの見た目に波及し、実 LLM での効果確認
  （needs-live-llm）も要る。入れるなら `untrusted_block` に `nonce` 引数を足し、`UNTRUSTED_DATA_POLICY` を「untrusted_data で始まる要素」に変える。
- **#98 束縛情報の無い旧形式の行は fail-closed**: アップグレード前に UI で「base_url + API キー」を保存していた環境では、そのキーは
  無視され、設定画面で再入力が必要（`api_key_rebind_required` に出る）。base_url を UI で変えていない（キーだけ保存）環境は従来どおり動く。
  旧形式の行を「信頼して束縛済みとみなす」移行も可能だが、攻撃者が既に書き換えた行を正規化してしまうので採らなかった。
- **#98 UI からは平文 HTTP の非 localhost を指定できなくなった**（`http://ollama:11434/v1` など compose 内のサービス名）。
  環境変数 / YAML（静的設定）は制限していないので、そちらで設定する。許可ホストの一覧設定（推奨 (2) の後半）は作っていない。

- **#35 無料のローカル LLM（openai_compat の Ollama 等）の扱い**: fail-closed なので、単価表に無いモデル名は最も高い既知単価
  （現状 Fable 5.1 の $10 / $50 per 1M）で見積もられ、既定の日次予算 $5 に達するとルールベースに切り替わる。回避は
  `llm.pricing` に 0 円で登録（`{"llama3.1:8b": {"input": 0, "output": 0}}`）か `llm.daily_budget_usd: 0`。
  プロバイダ別の既定（openai_compat は無料扱い）や「不明モデルは無料」のつまみは作らなかった（有料の OpenAI 互換ゲートウェイで
  同じ穴が開くため）。wiki・設定画面・使用量画面に案内を出した。既定を緩めるかはユーザー判断。

## 既定動作の変更

- #35: 単価表に無いモデルの費用が $0 → 最も高い既知単価の見積もり（上記）。既存の DB の行は `cost_basis` が NULL のまま（遡って再計算しない）。
- #98: 実行時の base_url の検証（上記）。保存済みの行に禁止 URL があると、その項目は無視して静的設定で起動する（WARNING）。
- #96: `untrusted_block` を使う全プロンプト（triage・コパイロットのツール結果と会話文脈・intel の脆弱性 / 資産 / Web リサーチ）で、
  `untrusted_data` に正規化される文字列が置換され、不可視文字が `\u` エスケープになる。大きいデータは末尾切断の前に文字列の切り詰めが入る
  （以前より多くの要素が残り、各要素の長い文字列は短くなる）。triage のプロンプト版が @2 に上がった（評価結果の比較単位が変わる）。

## 失敗した試み

## 担当外の変更

- `backend/src/tokiwa/db/models/llm.py`（llm モジュール所有と判断）: `LLMCallRow.cost_basis`（nullable、`sync_additive` で既存 DB に追加）。
- `backend/src/tokiwa/schemas/system.py::LLMCall`: `cost_basis: str | None = None`（互換の追加）。`frontend/src/api/types.ts` も更新。

## 他レーンへの依頼

- respond-notify レーン: `llm.config.update`（特に base_url・API キー・provider の変更）を通知の高優先イベントにする（#98 推奨 (3)）。
  監査ログ（`audit_log`）には従来どおり記録されている。

- intel レーン: `intel/prompts.py::_escape`（信頼済み構造化ブロック用）は `<` `>` だけをエスケープしている。
  `tokiwa.llm.prompting.escape_json_text` に置き換えると不可視文字のエスケープも揃う（#96 の残り。担当外なので未変更）。

## 未検証事項

- #98: ホスト名が DNS でリンクローカル / メタデータに解決される場合は検査していない（`llm/endpoints.py` の `TODO(verify)`）。
  束縛により、既存のキーがそのホストへ送られることはない（攻撃者が自分で入れたキーしか送られない）が、`/llm/test` のエラー文での
  到達性確認には使える。

- **#35 単価**: 既存表の値は変えていない。claude-api リファレンス（キャッシュ 2026-11-03）では Sonnet 5.5 のキャッシュ読み取りが $0.10
  だが表は 0.20 のまま（多めに見積もる方向なので予算の安全側。`TODO(verify)`）。Haiku 5.5 は 100K トークン超の入力で $0.50 / $2.50
  になる長文単価があるが未対応（`max_input_tokens_per_call` 既定 24,000 なので通常は届かない）。追加した 3 モデルの単価も公式の料金ページでは未確認。
