# 2026-10-22 detect-web 作業ログ（Web 攻撃の署名・レート検知）

担当タスク: `docs/tasks/detect-web.md`。ブランチ: `worktree-agent-a2288520a3d078834`。
（ワークツリーが骨格コミット `c4881e1` の 1 つ前にあったため、最初に `c4881e1` へ fast-forward してから作業した。）

## やったこと

- `backend/src/tokiwa/detect/web_common.py`（新規）: 多段デコード（`%XX` 多重/入れ子、`%uXXXX`、overlong UTF-8、
  HTML エンティティ、`\uXXXX`/`\xXX`、フォーム文脈の `+`）、NFKC、SQL コメント除去、空白圧縮。検査対象抽出
  （path / query・form・JSON リーフ・multipart パート/ファイル名 / cookie / ヘッダ 2 分類）。イベント単位の
  ビューキャッシュ（`ctx.scratch`）、署名レジストリ（`rx()`/`sig()`）、ビュー単位の結合プリフィルタ、
  `WebSignatureDetector` 基底、path_key による fingerprint 正規化。
- 検知器 17 個（`detect/detectors/web_*.py`）: sqli, xss, path_traversal, lfi_rfi, cmd_injection, ssrf, log4shell,
  ssti, xxe, deserialization, rsc_action_abuse, sensitive_file_probe, scanner_ua, rare_method, error_burst,
  credential_stuffing, request_flood。詳細は `docs/detection/web.md`。
- テスト（`backend/tests/detect/test_web_*.py` + `fixtures/`）: 計 228 件（スイート全体 236 件、約 3 秒）。
  攻撃 fixture 129 ケース（全署名系検知器を網羅、エンコード変種・ヘッダ/Cookie/JSON/multipart 位置）、
  正常トラフィック fixture 50 ケース（web.* 発火ゼロ）、デコード/抽出の単体テスト、レート系、取り込み API 経由の
  重複排除統合テスト、ReDoS 全件スイープ（121 パターン、最悪 ~10 ms / 4 KiB）、性能（~0.2 ms/イベント）。
- `docs/detection/web.md`（新規）: カタログ・設定・限界・TODO(verify)。

## 共有ファイルの変更（統合担当へ）

- `backend/src/tokiwa/config.py`: `WebDetectionSettings` クラスを新設し、`DetectionSettings` 末尾に
  `web: WebDetectionSettings = Field(default_factory=WebDetectionSettings)` を 1 行追加。それ以外は未変更。
  detect-ai / sigma も `DetectionSettings` 末尾に追記していれば隣接行の衝突になるが、両方残せばよい。
- 他の共有ファイル（schemas, app.py, engine.py, conftest.py, architecture.md）は変更していない。

## 現在の状態

- 動く: 17 検知器が登録され、`uv run pytest` / `ruff check` / `ruff format --check` が緑。
  `uv run mypy src/tokiwa/detect/web_common.py src/tokiwa/detect/detectors/` もエラーなし。
- テストは `web.*` のアラートだけを数えるので、他モジュールの検知器（sigma, deception.trip 等）が
  マージされても影響しない。

## 未完・次の一手

1. `docs/architecture.md` §4.2 に「Web 署名/レート検知: docs/detection/web.md、設定 `detection.web`」への 1 行リンクを
   追加（共有ファイルのため未編集）。
2. lab-eval の評価セットで誤検知率を測り、`xss.dangerous_tag` / `xss.javascript_uri` / `rfi.include_param_url` /
   `ssrf.bare_internal_host` など medium の署名の閾値・対象を調整する。
3. 分散型（多数 IP から同一ユーザー名）のパスワードスプレー検知、ログイン成功（失敗多数の後の 2xx）検知は未実装。
4. プロトタイプ汚染一般（RSC 文脈外の `__proto__`）は対象外にしている。必要なら別検知器で。

## TODO(verify)

- CVE-2025-55182（React2Shell）: `resolved_model` / `_response` / `_formData` / `_prefix` 等の内部フィールド名は
  公開 PoC（2025-12）由来。修正版 react-server-dom-webpack のソースと照合する。Next.js の Action ID 形式
  （40 文字以上の 16 進と仮定）もバージョン差を確認する。
- スキャナのマーカーヘッダ（Acunetix-Aspect*, X-WIPP, X-Scan-Memo, X-RequestManager-Memo, X-Request-Memo）と
  Nessus のマーカー `nessus_is_probing_you` は一次資料で未確認。
- MITRE 付与（rare_method → T1595 など）は暫定。

## 他モジュールへの依頼

- **gate**: ヘッダ許可リストに `next-action`, `rsc`, `next-router-state-tree`, `x-http-method-override`,
  `x-api-version` を含めてほしい（RSC 文脈判定・メソッド偽装・Log4Shell 検知に使う）。
  `HttpInfo.response_content_type` を埋めてほしい（`sensitive_file_probe` の露出判定で SPA フォールバックを
  見分けるのに使う）。パスは**正規化前**の生の値を `path` に入れてほしい（エンコード回避の検出に必要）。
- **deception**: `/.env` 等のデコイパスでは `deception.trip` と `web.sensitive_file_probe` の両方が出る（意図どおり。
  相関側で同一インシデントに束ねられる想定）。デコイが 200 + text/plain を返すと本検知器は critical
  （露出の疑い）に昇格するので、デコイ応答には識別できるタグ/ヘッダがあると correlate で降格できる。
- **triage-correlate**: `details.signatures`（署名 ID 配列）と `tags`（`cve-2021-44228`, `cve-2025-55182`,
  `exposure_suspected`）をキルチェーン・優先度付けに使える。
- **detect-ai**: `ai.adaptive_mutation` 等で「同一 path_key・同一 param に対する署名ヒットの連鎖」を使う場合、
  fingerprint の `path_key` と `details.param` がそのままキーに使える。`web_common.get_view()` を再利用すれば
  デコード済みビューを共有できる（同じ ctx.scratch キャッシュ）。
- **lab-eval**: シミュレータのペイロードは `backend/tests/detect/fixtures/web_attacks.json` を流用可能
  （検知用文字列のみ、実害のあるエクスプロイトは含まない）。
