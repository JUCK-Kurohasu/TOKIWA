# 実運用・対 AI 攻撃ツール監査（2026-11）

TOKIWA を実在の AI 攻撃ツール（ARTEX、ARES、PentAGI、Strix など）に向けたときに起きる問題を、
静的解析・動的解析（ローカルのラボのみ）・Web 調査で洗い出した監査の記録。指摘は GitHub Issue に登録している
（159 件。親は #16、サブ Issue の上限 100 件を超えた 2 巡目と追加観点の分は #152）。コードは直していない。

| パス | 内容 |
|---|---|
| `findings/*.jsonl` | レーン別の指摘の元データ（1 行 1 件。Issue 本文はここから生成） |
| `issues-filed.json` | 指摘 ID → Issue 番号の対応 |
| `repro/<レーン>/` | 監査で使った再現スクリプトと出力（作業ファイルそのまま。トークン類は伏せてある） |
| `RULES.md` | 監査エージェントに与えたルール（読み取り専用・localhost のみ・実 LLM 不使用 など） |
| `tools/` | 集計（`consolidate.py`）・Issue 本文の生成（`render2.py`）・REST での一括登録（`file_issues.py`）・親 Issue 本文の再生成（`epic.py`）・2 巡目の指示（`PASS2.md`）。LLM を使わずに再実行できる |
| `tools/taxonomy.json` + `tools/status_diagram.py` | 全 Issue の分類（系統 A〜K と原因別の束）と、#16 先頭の系統図（Mermaid）の生成。Issue の開閉状態を GitHub から読んで描き直す（`.github/workflows/audit-epic.yml` が close / reopen 時に実行） |

## レーン

L01 ARTEX の実挙動 / L02 ARES ほか AI 攻撃ツールの調査 / L03 カナリアの到達性 / L04 AI 判定の回避 /
L05 Web 検知の網羅と回避 / L06 Gate のプロトコル攻撃 / L07 API 認可・取り込みの悪用 / L08 LLM パイプライン /
L09 対処・通知の悪用 / L10 フロントエンド / L11 運用・性能 / L12 センサー・インテルの入力処理 /
L13 静的解析ツール / L14 Docker ラボの実起動 /
L15 評価（eval）の妥当性 / L16 正規トラフィックでの誤検知 / L17 個人データの扱い / L18 運用（バックアップ・移行・設定）

各レーンの 2 巡目の作業メモは `repro/<レーン>/pass2/NOTES.md`。

## 注意

- L14 のうちラボの ingest / agent プロファイルの実起動は未実施（サンドボックスで Docker イメージを取得できなかった）。
- 個人データ（L17）は事実の列挙のみで、法的な結論は書いていない（一次資料を監査環境から開けず未確認）。
- 確度は `confirmed`（再現済み）/ `likely`（コードで確認、未実行）/ `hypothesis`（推測）。実 LLM は使っていない（モックのみ）。
- 再現スクリプトは監査時の作業領域のパス（`$AUDIT_DIR`、各レーンのポート）を前提にしており、そのままでは動かないものがある。
- スクリプトはローカルのラボ（localhost）だけを対象にしている。自分が管理していない環境に向けないこと。
