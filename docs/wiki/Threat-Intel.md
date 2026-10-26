> 🌐 **日本語** · [English](Threat-Intel-en) · [中文](Threat-Intel-zh) · [Español](Threat-Intel-es)

# 脆弱性インテリジェンス

脆弱性情報を定期的に取り込み、登録した資産と照合して、優先度付きの助言（アドバイザリ）を出す機能です。
さらに LLM の Web 検索で、0day や悪用の報告を定期的に調べます。

## 取り込むソース

| ソース | 内容 |
|---|---|
| CISA KEV | 実際に悪用が確認された脆弱性のカタログ |
| EPSS | 30 日以内に悪用される確率の推定値 |
| NVD | CVE の詳細・CVSS・影響を受ける製品（CPE） |
| OSV | オープンソースのパッケージ（PyPI、npm、Go、Maven など）の脆弱性 |
| JVN | 日本の脆弱性情報 |
| GitHub Security Advisories（GHSA） | GitHub のアドバイザリ |
| RSS | JPCERT/CC、IPA、CISA、The Hacker News、BleepingComputer（既定） |

- 既定で 360 分（6 時間）ごとに同期します（`intel.sync_interval_minutes`）。
- 同期には、これらのサービスへの **外向きの通信** が必要です。
- NVD は API キーなしだと取得速度の制限が厳しくなります。GitHub もトークンがある方が安定します。

```bash
export TOKIWA_INTEL__NVD_API_KEY=...       # 任意
export TOKIWA_INTEL__GITHUB_TOKEN=...      # 任意
```

> ⚠️ IPA は、2026 年 4 月から JVN iPedia / MyJVN を刷新する（JSON フィード、CVSS v4、API のレート制限）と告知しています。
> 旧フィードを前提とした取得が使えなくなっている可能性があります。告知の内容と実データでの動作はどちらも未確認です。

## 使い方

1. **資産を登録する**: **資産** 画面で、守るべきホスト・サービス・Web アプリ・LLM アプリと、そこで動くソフトウェア
   （ベンダー・製品名・バージョン・CPE・OSV のエコシステム）を登録します。
2. **同期を待つ（または手動で実行）**: **インテリジェンス → ソース状態** から同期を開始できます。CLI でも実行できます。

   ```bash
   cd backend
   uv run tokiwa intel sync              # すべての有効なソース
   uv run tokiwa intel sync -s kev       # 特定のソースだけ
   uv run tokiwa intel status            # ソースごとの同期状態
   uv run tokiwa intel show CVE-2021-44228
   ```

3. **結果を見る**: **インテリジェンス** 画面のタブで確認します。

| タブ | 内容 |
|---|---|
| 脆弱性 | 全ソースを CVE 単位で統合したもの（KEV 該当・EPSS・CVSS） |
| 資産一致 | 資産のソフトウェアと一致した脆弱性。状態（未対応 / 対応済みなど）を管理できる |
| アドバイザリ | LLM による優先度付きの助言。KEV 該当・高 EPSS・資産一致を優先して生成する |
| ニュース | RSS の記事 |
| Web リサーチ | LLM による 0day・悪用報告の調査結果。トピックを指定して手動実行もできる |
| ソース状態 | 各ソースの最終同期と件数 |

## アドバイザリと検知ルールの提案

アドバイザリには、影響の要約・優先度・推奨対応に加えて、**Sigma 形式の検知ルール案** が付くことがあります。
ルール案は検証したうえで **検知ルール → LLM 提案** に「提案」として保存され、**自動では有効化されません**。
人間がレビューして採用します。

## インシデントとの連動

アラートが CVE を参照していて、その CVE が KEV に載っている場合、インシデントの優先度が引き上げられます。
ダッシュボードの「KEV 一致」は、既知の悪用脆弱性と資産が一致している件数です。

## Web リサーチ（0day の定期調査）

- 既定で 12 時間ごと（`intel.research_interval_hours`）に、`intel.research_topics` のトピックを調べます。
- Claude の **サーバー側 Web 検索** を使うため、**Anthropic の API キーを設定しているときだけ** 実際に検索します。
  モック LLM では検索は行われず、その旨が結果に表示されます。
- 上位モデルを使うので、LLM の費用がかかります。不要なら `intel.research_enabled: false` で止められます。
- 結果の要約は LLM の出力です。重要な判断の前に、必ず出典を確認してください。

## 主な設定（`intel.*`）

| キー | 既定 | 説明 |
|---|---|---|
| `enabled` | true | インテリジェンス全体 |
| `sync_interval_minutes` | 360 | 同期間隔 |
| `sources` | すべて true | ソースごとの有効 / 無効（`kev`, `epss`, `nvd`, `osv`, `jvn`, `ghsa`, `rss`） |
| `rss_feeds` | 5 件 | 取り込む RSS の URL |
| `research_enabled` / `research_interval_hours` | true / 12 | Web リサーチ |
| `research_topics` | 0day・AI 駆動攻撃の 2 件 | 調査トピック |
| `epss_alert_threshold` | 0.1 | EPSS の急上昇とみなすしきい値 |
| `nvd_lookback_days` | 3 | NVD を遡って取る日数 |
