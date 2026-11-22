# 2026-11 監査対応: deception レーン（系統 D「デセプション」、工数 S）

担当 Issue: #133, #30, #41, #65, #68, #84。指摘の詳細は `docs/audit/2026-11/findings/*.jsonl`
（#133=L03-10, #30=L03-02, #41=L01-06, #65=L09-06, #68=L11-03, #84=L01-07）。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| #133 | 部分（推奨 (1)(2) は完全。(3)〜(5) は未着手） | 新モジュール `deception/provenance.py` でトリップごとに「出所」を判定。`induced`（`Sec-Fetch-Site: cross-site`/`same-site`、`Sec-Fetch-Dest` が `document`/`empty` 以外、`Sec-Purpose: prefetch`、別ホスト or `null` の `Origin`、別ホストの `Referer`）は全分類 low・AI 断定なし、`passive`（AI カナリア値がパス・クエリ・本文・Referer 等リンクで届く欄だけ＝経路 GET 単独）は medium・ai_score 0.5、`direct`（カナリアヘッダ等クライアント自身にしか付けられない位置）は従来どおり critical/ai_agent/0.99。降格したアラートは相関・ルール判定が AI 断定に使う印（タグ部分一致 `ai_canary`・エンティティ値 `ai_canary`）を持たない。セッション（aidetect）が Gate の `ai_canary` デコイ応答を無条件に `canary_hits`（AI 断定）にしていた経路も `provenance.decisive_canary_hit()`（既知のカナリア値をカナリアヘッダで送り、誘発兆候なし）で絞った（それ以外は `decoy_hits`）。これでカナリアページ（`/api/internal/openapi.json`、隠し HTML からリンク）を取得しただけで AI 断定される問題も止まる。設定 `deception.downgrade_browser_induced`（既定 true）。テスト `tests/deception/test_deception_framing.py`: L03-10 の再現（Gate の `EventBuilder` で HTTP + deception イベントを生成、クロスサイト `<img>`・同一オリジンの投稿内 `<img>`・リンクプレビュー bot・カナリアページ取得・`<img src=/.env>`）を **自動承認を全 ActionType で有効** にして流し、被害者 IP に対処 0 件・Gate ポリシーに載らない・インシデントは ai_agent でなく high 未満、対照としてカナリアヘッダで追従した非ブラウザは critical/ai_agent で block_ip が自動承認されること | c218d2d |
| #30 | 完全（推奨 (1)(2)。(3) 編集距離は不採用） | トークン照合を大文字小文字無視（正規表現 `IGNORECASE` + 格納値への逆引き。`find_tokens` は格納値を返すので呼び出し側は無変更）、`\` を除いた版も照合（markdownify の `dbg\_` 対策）、`/api/internal/<値>` の判定と Referer もデコード → `\` 除去 → 正規化で比較。カナリアヘッダが既知値以外で送られたら資産に紐付かない `canary_attempt`（medium・deception・AI 断定なし、送信元ごとに 1 件、誘発兆候があれば出さない、`ai_canaries=false` やカナリア値が無いときは出さない）。テスト `test_deception_variants.py`（repro の md_escaped_path / md_escaped_hdr / lowercase_hdr / %5C / 大文字パス / Referer / クエリ、切り詰め・1 文字違い・base64・でたらめ値の試み） | （このコミット） |
| #41 | 未着手 | | |
| #65 | 未着手 | | |
| #68 | 未着手 | | |
| #84 | 未着手 | | |

## 要判断

- **#133「相関で昇格」の解釈**: 検知器の中に昇格ロジックは作らなかった。`passive` は medium のまま、同じ送信元の攻撃系アラート
  （SQLi 等）があればインシデントの重大度は max でそちらに上がる（既存の相関）。カナリア自体を「攻撃と相関したら AI 断定に戻す」は、
  攻撃リクエストも `<img>` やリンクで誘発できる（`?q=' OR 1=1--`）ため採らなかった。
- **#133 誘発判定の回避（代償）**: 攻撃者が `Sec-Fetch-Site: cross-site` 等を自分で付ければ、自分のトリップを low に下げられる。
  記録・アラート（low）は残る。HTTP だけでは本物のクロスサイト要求と区別できない。`deception.downgrade_browser_induced=false` で従来の重み。
  非ブラウザ UA が `Sec-Fetch-*` を送るのは不自然なので、「ブラウザ UA のときだけ信じる」等の追加条件は将来の調整点（UA も詐称可能なので未実装）。
- **#133 経路 GET 単独を AI 断定しなくなった（検知力の低下）**: パスだけで追従するエージェントは、カナリアだけでは AI と断定されなくなる
  （他の振る舞いシグナル・攻撃アラートで判断）。推奨 (2) どおり。

- **#30 生成トークンの字母（`_`）は変えなかった**: 推奨 (1) の「字母から `_` を除く」案ではなく照合側の正規化を採った（既に配布・
  漏えいしたデコイの値を変えずに済むため）。新規生成値から `_` を外すかは任意（`tokens._FORMATS`）。
- **#30 `canary_attempt` を medium にした（推奨は high）**: ヘッダ名 `X-Debug-Auth` は本プロジェクトの公開文書・ソースにも載るので、
  「ヘッダ名だけ知っている」主体（このリポジトリを読んだ人・スキャナ）と区別できない。high にするとルール判定が rate_limit を提案する。
  `deception_trip.CANARY_ATTEMPT_SEVERITY` で調整可。`canary_header` を実クライアントが送るヘッダ名に変えた運用では雑音になる。
- **#30 経路 `/api/internal/dbg*` の値不一致は試みとして起票しない**: 実アプリの `/api/internal/` と紛れやすく、リンクで誘発もできるため。
- **#30 近似一致（編集距離 1〜2）は不採用**: 照合が正規表現の一括検索なので、近似一致は別の仕組みが要る。ヘッダでの写し間違いは
  `canary_attempt` で拾える。

## 既定動作の変更

- AI カナリアの経路 `/api/internal/<値>/` への GET（カナリアヘッダなし）: critical/ai_agent → **medium/deception**、セッションも AI 断定しない。
- カナリア値がクエリ・本文だけに現れた `ai_canary_token`: critical → **medium**。
- ブラウザのクロスサイト/サブリソース要求によるトリップ（全分類）: critical → **low**（`deception.downgrade_browser_induced=false` で従来どおり）。
- Gate の `ai_canary` デコイ応答（カナリアページ取得を含む）を AI セッション断定に数えるのは、カナリアヘッダで既知の値を送った場合だけ。
- カナリアヘッダでの追従（`direct`）は従来どおり critical/ai_agent/0.99。DB スキーマ変更なし（`deception_trips.detail` JSON に `provenance`/`induced_by` を追加）。
  bus `deception.tripped` に `provenance` を追加（後方互換）。

- （#30）トークン照合が大文字小文字を区別しなくなった（ハニートークン含む全トークン）。カナリアヘッダに既知値以外の値 → medium の
  `canary_attempt` アラート（新規）。

## 失敗した試み

- e2e テストに `<img src=/.env>` の被害者も「対処 0 件」として入れたら、detect-web の `web.sensitive_file_probe`（high）が同じ要求で立ち、
  ルール判定が rate_limit を提案・自動承認した。デセプションの責任範囲外なので、e2e では deception.trip が low になることだけを確認し、
  残りは他レーンへの依頼に回した。

## 担当外の変更

- `backend/src/tokiwa/aidetect/sessions.py`（aidetect レーン）: `_observe_other` の `ai_canary` 計数を `decisive_canary_hit(e)` で絞る
  4 行（import は関数内。モジュール先頭の import 行は触っていない）。HTTP 情報の無い deception イベントは従来どおり断定
  （既存テスト `test_non_http_events_attach_and_canary_decides` / `test_agent_session_negative_and_canary` は無変更で通る）。
- `backend/src/tokiwa/config.py`: `DeceptionSettings` に `downgrade_browser_induced` を追加（自セクションのみ）。

## 他レーンへの依頼

- **respond / triage（自動承認の最終防衛線）**: 本対応で守られるのは **ルール判定（mock / fallback）の経路だけ**。実 LLM のトリアージは
  medium の deception インシデントにも block_ip を提案し得て、自動承認なら実行される。`details.provenance in (passive, induced)` の
  deception アラートだけを根拠にした提案は自動承認しない、等のガードを respond 側に入れてほしい（テストは本レーンの e2e を流用可）。
- **aidetect**: 経路 GET 単独・カナリアページ取得を `decoy_hits`（敵対スコアのみ）に回した。AI スコアに「弱い」重み（断定ではない）
  として足すかは aidetect 側の判断（`provenance.decisive_canary_hit` と `induced_by` を使える）。
- **detect-web（#154 / #23 系）**: `<img src="https://<site>/.env">` で閲覧者の IP に `web.sensitive_file_probe`（high）→ rate_limit 提案
  （自動承認なら実行）。同じ誘発判定（`deception.provenance.induced_by`）を使えば下げられる。
- **#133 の残り**: Sec-Fetch を送らない取得（チャットのリンクプレビュー、メールのリンク検査、古いブラウザ）での **デコイパス・ハニートークン**
  トリップは critical のまま（ルール判定は block_ip を提案する）。カナリアの `passive` 相当をデコイパスにも広げるかは要検討
  （スキャナの `/.env` 取得も medium になり検知力が下がる）。推奨 (3) 訪問者ごとのカナリア値＋`Cache-Control: private`（#45 と同じ作業）、
  (4) 宣言済み AI UA の別分類、(5) 検証済みクローラへの非注入は未着手。

- #30: Gate の着地ルート（`/api/internal/<値>*`）は Gate 側の正規化のまま（大文字小文字・`\` を区別）なので、揺れた経路は上流へ
  転送され 404 になる（検知はサーバー側の HTTP イベントで行われる。Gate の `DecoyMatcher` は担当外）。

## 未検証事項

- `Sec-Purpose: prefetch` / `Purpose: prefetch` を送るブラウザの範囲（`TODO(verify)` 相当。Chromium の prefetch / prerender で送られる想定）。
- リンクプレビュー bot・メールのリンク検査が `Sec-Fetch-*` を送らないこと（一般的な理解に基づく。個別製品は未確認）。
- 実 LLM のトリアージが降格アラートにどう反応するか（`needs-live-llm`）。
- #30: 実エージェントが `dbg\_` のまま送るか・写し間違えるかは未確認（`needs-live-llm`。照合側はどちらも拾う）。
