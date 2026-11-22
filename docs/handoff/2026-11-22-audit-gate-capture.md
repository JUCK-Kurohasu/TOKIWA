# 2026-11 監査対応: gate-capture レーン（系統 A「Gate」、工数 S）

担当 Issue（この順）: #140, #141, #138 + #147 + #149, #54, #146 + #148, #99, #143。指摘の詳細は
`docs/audit/2026-11/findings/*.jsonl`（#140=L06-09, #141=L06-10, #138=L06-06, #147=L06-07, #149=L06-14, #54=L06-03,
#146=L03-07, #148=L06-12, #99=L09-05, #143=L06-13）。

ブランチ `worktree-agent-ac5a31bda64077d5d`（基点 `95343eb`）。

## 対応状況

| Issue | 状態 | 何をしたか | コミット |
|---|---|---|---|
| （未登録・high 相当）Gate の共有 httpx クッキージャー | 完全 | 上流・サーバー用の httpx クライアントに「何も保存しない」ポリシーの `CookieJar` を渡す。テスト `tests/gate/test_gate_upstream_headers.py`（A の Set-Cookie が B の要求に付かない・ジャーが空のまま・クライアント自身の Cookie はそのまま転送） | fix(gate): never store upstream cookies |

## 未登録の指摘（このレーンで発見）

- **Gate の上流クライアント（共有 `httpx.AsyncClient`）が上流の `Set-Cookie` をクッキージャーに保存し、`Cookie` を送らない
  別のクライアントの要求に付けて上流へ送っていた**（セッションの横取り）。再現: 利用者 A が `/login` で `Set-Cookie: session=...`
  を受けた後、Cookie なしの利用者 B（別 IP）の要求が上流に `Cookie: session=<A の値>` 付きで届く。httpx はレスポンスごとに
  `client.cookies.extract_cookies()` し、`build_request` で `Cookie` ヘッダが無い要求にジャーの値を足すため。
  Issue 化はしていない（GitHub には書き込まない約束）。統合担当が Issue にするか判断する。

## 要判断

## 既定動作の変更

## 失敗した試み

## 担当外の変更

## 他レーンへの依頼

## 未検証事項
