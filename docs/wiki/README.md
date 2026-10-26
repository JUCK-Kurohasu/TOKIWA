# docs/wiki/ — GitHub Wiki のソース

このディレクトリが [TOKIWA の Wiki](https://github.com/JUCK-Kurohasu/TOKIWA/wiki) の **正本** です。
main にマージされると `.github/workflows/wiki.yml` が `scripts/publish-wiki.sh` で Wiki に同期します
（Wiki 側を直接編集しても次の同期で上書きされます）。この README は Wiki には公開されません。

## 構成と命名

GitHub Wiki には多言語の仕組みがないため、言語ごとに別ページにして、各ページの 1 行目の **言語バー** で相互に切り替えます。

| 言語 | ファイル名 | 例 |
|---|---|---|
| 日本語（既定） | `<Page>.md` | `Quick-Start.md` |
| English | `<Page>-en.md` | `Quick-Start-en.md` |
| 中文（简体） | `<Page>-zh.md` | `Quick-Start-zh.md` |
| Español | `<Page>-es.md` | `Quick-Start-es.md` |

- Wiki はフォルダを平坦化するので、ファイル名は全体で一意にし、サブディレクトリは使わない。
- ページ内リンクは `[表示名](Page)`（拡張子なし）。各言語のページは同じ言語のページにリンクする。
- 1 行目の言語バー（例: 日本語ページ）:
  `> 🌐 **日本語** · [English](Quick-Start-en) · [中文](Quick-Start-zh) · [Español](Quick-Start-es)`
- `_Sidebar.md`（全ページ共通のサイドバー。4 言語の目次）と `_Footer.md`（共通フッター）は Wiki の特殊ページ。

## 更新の手順

1. **日本語ページを先に** 直す（事実関係はコード・`docs/` と照合する。不確かなことは「未確認」と書く）。
2. 同じ PR で英語・中国語・スペイン語のページにも反映する。訳語は既存ページに合わせる
   （UI のラベルは英語 UI の表記を使う。中国語・スペイン語では初出に訳を括弧書き）。
3. ページを追加したら `_Sidebar.md` の 4 言語すべてに追記する。
4. `python3 scripts/check_wiki.py` で整合性を確認する（全言語の存在、言語バー、リンク切れ・他言語へのリンク、
   コードブロック数の一致）。CI の infra lint ジョブでも実行される。

## 初回のみ必要な準備（リポジトリ管理者）

GitHub は Wiki の git リポジトリ（`<repo>.wiki.git`）を、Web UI で最初のページが作られるまで作りません。

1. リポジトリの **Settings → General → Features → Wikis** を有効にする。
2. **Wiki** タブで適当な内容の最初のページ（Home）を 1 つ作成する（同期で上書きされる）。
3. **Actions → Wiki → Run workflow** で手動実行するか、`docs/wiki/` を変更して main にマージする。

手元から公開する場合（リポジトリに push できる権限が必要）:

```bash
scripts/publish-wiki.sh                       # git の認証情報を使う
GH_TOKEN=<token> scripts/publish-wiki.sh      # トークンを使う（ヘッダで渡し、URL やログには出さない）
```
