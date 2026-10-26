# Wave 2 / C: frontend-consolidation — 統合後の後始末と実バックエンドでの確認

## 担当範囲
`frontend/**` のみ（バックエンドの API が足りなければ作業ログで依頼）。

## 要件
1. **SSE の一本化**: `hooks/useLiveStream.ts` と `components/common/useOpsLive.ts` を 1 つに統合（タブあたり接続 1 本、再接続、
   トピック別のクエリ無効化）。全ページを移行し、古いフックを削除。
2. **重複コンポーネントの統合**: `QueryView`/`DataState`, `OffsetPager`/`PagerBar`, `EventDetail`/`EventInspector` など、
   同じ役割の部品を 1 つにまとめる（各 handoff ログの一覧を参照）。
3. **型の集約**: `api/types-core.ts`, `types-ops.ts`, `types-intel.ts` を `api/types.ts`（または `api/types/` 配下）へ整理し、
   バックエンドの `schemas/*.py` と突き合わせて不一致を直す。
4. **バンドル削減**: ルートの遅延読み込み（`React.lazy` + `import.meta.glob` の非 eager 化）、recharts を必要ページだけに。
   **初期 JS < 500KB（gzip 前）** を目標。
5. **実バックエンドで E2E**: `uv run tokiwa serve` + `scripts/seed_demo.py` でデータを入れ、Playwright（`/opt/pw-browsers/chromium`）で
   主要画面（ログイン、ダッシュボード、アラート詳細、インシデント詳細で承認、セッション詳細、インテル、ルール、LLM、コパイロット）を巡回。
   コンソールエラー 0 を確認。テストは `frontend/e2e/` に置き、CI には入れなくてよい（手順を README に）。
6. コパイロット: 停止・エラー時にユーザーメッセージが二重表示される件を修正。インシデント詳細の「コパイロットに聞く」を
   `/copilot?incident=<id>` に接続。

## 受け入れ基準
- `npm run typecheck && npm run lint && npm run build && npx vitest run` 緑、初期バンドル < 500KB、E2E 巡回でエラー 0。
