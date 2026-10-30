<div align="center">

# TOKIWA

**生成AIによるサイバー攻撃を検知・防御する LLM 駆動 SIEM / XDR**

*An LLM-driven SIEM/XDR that detects and defends against generative-AI-driven cyber attacks.*

</div>

---

TOKIWA（常磐）は、AI 自律型ペネトレーションテストシステム **ARTEX** と対をなす防御側プロダクトです。
ルール検知と振る舞い分析で「AI エージェントによる攻撃」を見分け、LLM が根拠付きでトリアージし、
可逆な対処を **人間の承認のもとで** 実行します。

> ⚠️ 開発中（v0.1.0）。ラボ・自分が管理する環境での利用を前提としています。

## 特徴

| | |
|---|---|
| 🧠 **AI 攻撃アトリビューション** | 思考待ちのリズム・エラー後のペイロード変異・意味的な API 探索・LLM クライアント指紋などのセッション特徴量から、AI エージェント／スキャナ／人間を説明可能なスコアで判別 |
| 🪤 **Mirage（デセプション）** | デコイ・ハニートークン・**AI カナリア**（AI エージェントだけが従う隠し指示）で高確度に検知 |
| 🚪 **TOKIWA Gate** | リバースプロキシ型センサー。ボディまで捕捉し、block / rate-limit / tarpit / デコイ誘導を即時適用 |
| 🔎 **ルール検知** | Web 攻撃署名・レート検知・Sigma ルール・ポート逸脱・スキャン・IDS（Suricata/Zeek）取り込み |
| 🤖 **LLM トリアージ** | 構造化出力（スキーマ固定）・根拠 ID 検証・軽量→上位モデルの昇格・予算管理・監査ログ |
| 🛰️ **脆弱性インテリジェンス** | KEV / EPSS / NVD / OSV / JVN / GHSA / RSS を定期取得し資産と照合。LLM が優先度付き助言と Sigma ルール案を提示、Web 検索で 0day を定期調査 |
| 💬 **SOC コパイロット** | 参照専用ツールで TOKIWA のデータに自然言語で質問 |
| 🧪 **評価ハーネス** | ラボ用トラフィックシミュレータ（正常/スキャナ/人間/AI エージェント/LLM アプリ攻撃）と指標算出。ARTEX とのパープルチーム演習 |

## クイックスタート（開発）

```bash
# backend
cd backend
uv sync
uv run tokiwa serve --reload        # http://localhost:8788 （初回は /setup で管理者作成）

# frontend（別ターミナル）
cd frontend
npm install
npm run dev                         # http://localhost:5173

# LLM を使う場合（未設定なら mock で動作）
export ANTHROPIC_API_KEY=...        # または UI の「LLM」設定から（モデルはプルダウンで選択）
# 「LLM」設定の状態カードに「mock で動作中」と出ているときは LLM は呼ばれていません（プロバイダを auto / Anthropic に）
```

センサーの接続:

```bash
cd backend
uv run tokiwa token create gate-1                        # API トークン（一度だけ表示）
uv run tokiwa gate run --upstream http://127.0.0.1:3000 --token tkw_...   # Gate
uv run tokiwa agent run --token tkw_...                  # ホストセンサー
```

ラボ（Docker Compose）: `docker compose -f lab/compose.yaml up --build` — 詳細は `lab/README.md`。

## ドキュメント

- **使い方（Wiki・日本語 / English / 中文 / Español）**: [TOKIWA Wiki](https://github.com/JUCK-Kurohasu/TOKIWA/wiki)（ソースは [`docs/wiki/`](docs/wiki/)）
- [要件定義 v0.2](docs/requirements.md) / [アーキテクチャ](docs/architecture.md) / [API 契約](docs/api-contract.md)
- [設計判断（ADR）](docs/decisions/) / [タスク仕様](docs/tasks/)
- 開発者・AI エージェント向け: [AGENTS.md](AGENTS.md) / [CLAUDE.md](CLAUDE.md) / [HANDOFF.md](HANDOFF.md)

## 安全方針

- LLM に渡すログは常に非信頼データとして扱い、LLM の出力を実行系に直結しません。
- 対処は許可リスト型・可逆（TTL）で、既定では人間の承認が必要です。
- 能動的防御は自組織の資産上のデセプションに限定し、反撃（hack-back）は行いません。

## ライセンス

Apache License 2.0（暫定。[ADR-0005](docs/decisions/ADR-0005-license.md)）
