# Wave 2 / A: lab-validation — ラボを実際に動かして通しで検証する（フェーズ 2）

## 前提
フェーズ 1（B, C, D, E）が main にマージ済みであること。

## 担当範囲
`lab/**`, `docs/purple-team.md`, `lab/README.md`。見つけた結合バグは該当モジュールに **最小修正 + テスト**。

## 要件
1. `docker compose -f lab/compose.yaml up --build`（サンドボックスで dockerd が使えない場合は、devops 担当の手順
   `docs/handoff/2026-10-22-devops.md` を参照して dockerd を起動。ミラー・CA の回避策もそこにある）。
2. 全シミュレータプロファイル（benign_browser / scanner / human_attacker / ai_agent / llm_app_attacker）を Gate 経由で流す。
3. **通しシナリオの確認**: ai_agent → AI アトリビューション → インシデント → トリアージ（モック）→ block_ip 提案 →
   UI/API で承認 → Gate ポリシーに反映 → 以後の要求が 403。AI カナリアの追従で ai_agent 断定アラート。
4. ホストエージェント（ポート監視）と nginx JSON ログ取り込みも同時に動かし、新規リスナーでアラートが出ることを確認。
5. 指標を `tokiwa eval` 形式で記録し、`docs/purple-team.md` に結果と再現手順を追記。ARTEX をラボに向ける手順も実地で確認
   （ARTEX が手元にない場合は手順の検証のみ）。

## 受け入れ基準
- 上記シナリオが自動または半自動スクリプト（`lab/scripts/e2e.sh` 等）で再現できる。見つけたバグは修正済みかつテスト付き。
