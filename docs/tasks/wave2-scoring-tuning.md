# Wave 2 / B: scoring-tuning — AI エージェント判定の検証と重み調整

## 目的
第 1 波の AI アトリビューション（`aidetect/`）は「検知器と同じ仮説で合成したデータ」でしか検証されておらず、
100% は過大評価。より厳しいデータで弱点を洗い出し、説明可能性を保ったまま重みを調整する。

## 担当範囲
`backend/src/tokiwa/aidetect/**`, `enrich/sessionizer.py`, `detect/detectors/ai_*.py`, `backend/src/tokiwa/eval/**`,
`eval/**`（データセット・README）, `backend/tests/{aidetect,eval}/**`, `docs/detection/ai-attacks.md`

## 要件
1. **評価データの拡充**（`tokiwa sim generate`）: 複数シード（≥10）、プロファイル内のばらつき（速度・ページ数・誤り率）、
   正常利用のノイズ（NAT 共有 IP、ブラウザ拡張、モバイル）、**回避型 AI エージェント**（ランダム遅延で思考待ちリズムを崩す、
   UA/ヘッダ偽装、ペイロード変異を控えめにする）、遅い人間攻撃者。生成器は決定的（シード固定）に。
2. **学習 / 検証 / テストの分割**を固定し（シードで分ける）、`aidetect/scoring.py` の重み・閾値を学習用だけで調整。
   テスト分割で P / R / F1 / AUC を報告。過学習防止のため重みは少数・単調性を保つ。
3. 既知の誤り: `human_attacker` の一部が benign 判定 → 原因を特徴量レベルで分析して修正。
4. **アクター横断の指紋統合**（第 1 波の未実装）: 同一送信元で curl / python / Playwright など複数ツールを切り替える攻撃者を
   1 アクターとして束ねる（セッションは分けたまま、`actor_group_id` 的な関連付け）。誤束ね（NAT）を抑える条件付きで。
5. **オフライン評価でのデセプション**: 評価ハーネスがリプレイ用 DB にデセプション資産をシードできるようにする
   （`tokiwa.deception.service` の既存関数を呼ぶ。E 担当が `seed_defaults()` 相当を用意するので、無ければフォールバック）。
6. **回帰チェックを CI に**: 小さな固定データセットで `tokiwa eval run --llm mock` を走らせ、主要指標が閾値を下回ったら失敗する
   pytest（実行時間 < 30 秒）を追加。
7. `docs/detection/ai-attacks.md` に、評価結果・既知の限界・回避型への耐性を「事実 / 仮説」を分けて追記。

## 受け入れ基準
- テスト分割の指標（回避型を含む）を作業ログと docs に記載。正常利用の誤検知率を悪化させない。
- 回帰テストが CI で緑。
