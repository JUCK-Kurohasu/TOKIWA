/** Security news / advisories from RSS and vendor feeds, with extracted CVE ids. */
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Newspaper, Search } from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import { api } from "@/api/client";
import type { IntelItem, Page } from "@/api/types";
import { hostOf, isSafeHttpUrl } from "@/components/common/IntelBadges";
import { OffsetPager } from "@/components/common/OffsetPager";
import { QueryView } from "@/components/common/QueryView";
import { useUrlParams } from "@/components/common/urlState";
import { Badge, Card, EmptyState, Input } from "@/components/ui";
import { formatDateTime, pct, timeAgo } from "@/lib/format";
import { useLocal } from "@/lib/i18n";

const LIMIT = 30;

const strings = {
  ja: {
    search: "タイトル・本文で検索",
    source: "ソース",
    sourcePlaceholder: "すべてのソース",
    empty: "ニュースはありません",
    emptyHint: "RSS フィードの設定と同期状況をソース状態タブで確認してください。",
    relevance: "関連度",
  },
  en: {
    search: "Search title and body",
    source: "Source",
    sourcePlaceholder: "All sources",
    empty: "No news items",
    emptyHint: "Check the RSS feed configuration and sync status on the Sources tab.",
    relevance: "Relevance",
  },
};

export function NewsTab({ onOpenVuln }: { onOpenVuln: (id: string) => void }) {
  const L = useLocal(strings);
  const [params, update] = useUrlParams();
  const q = params.get("q") ?? "";
  const source = params.get("source") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const [qInput, setQInput] = useState(q);
  const [sourceInput, setSourceInput] = useState(source);
  useEffect(() => setQInput(q), [q]);
  useEffect(() => setSourceInput(source), [source]);
  const seenSources = useRef(new Set<string>());

  const query = useQuery({
    queryKey: ["intel", "news", { q, source, offset }],
    queryFn: () => api.get<Page<IntelItem>>("/intel/news", { q, source, limit: LIMIT, offset }),
    placeholderData: keepPreviousData,
  });
  for (const it of query.data?.items ?? []) seenSources.current.add(it.source);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    update({ q: qInput.trim(), source: sourceInput.trim(), offset: null });
  };

  return (
    <div className="space-y-3">
      <form onSubmit={submit} className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[16rem] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted" aria-hidden />
          <Input
            value={qInput}
            onChange={(e) => setQInput(e.target.value)}
            placeholder={L.search}
            aria-label={L.search}
            className="pl-8"
          />
        </div>
        <Input
          className="w-48"
          list="tk-news-sources"
          value={sourceInput}
          onChange={(e) => setSourceInput(e.target.value)}
          onBlur={() => sourceInput.trim() !== source && update({ source: sourceInput.trim(), offset: null })}
          placeholder={L.sourcePlaceholder}
          aria-label={L.source}
        />
        <datalist id="tk-news-sources">
          {[...seenSources.current].sort().map((s) => (
            <option key={s} value={s} />
          ))}
        </datalist>
        <button type="submit" className="sr-only">
          {L.search}
        </button>
      </form>

      <QueryView
        query={query}
        rows={6}
        isEmpty={(d) => d.items.length === 0}
        empty={
          <Card>
            <EmptyState title={L.empty} hint={L.emptyHint} icon={<Newspaper className="h-6 w-6" />} />
          </Card>
        }
      >
        {(page) => (
          <Card>
            <ul className="divide-y divide-line">
              {page.items.map((it) => (
                <li key={it.id} className="space-y-1.5 px-4 py-3">
                  <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted">
                    <Badge>{it.source}</Badge>
                    <span title={formatDateTime(it.published ?? it.fetched_at)}>
                      {timeAgo(it.published ?? it.fetched_at)}
                    </span>
                    {isSafeHttpUrl(it.url) && <span>{hostOf(it.url)}</span>}
                    {it.relevance != null && (
                      <span className="ml-auto tabular-nums">
                        {L.relevance} {pct(it.relevance)}
                      </span>
                    )}
                  </div>
                  <h3 className="text-sm font-medium leading-snug">
                    {isSafeHttpUrl(it.url) ? (
                      <a
                        href={it.url}
                        target="_blank"
                        rel="noopener noreferrer nofollow"
                        className="hover:text-accent hover:underline"
                      >
                        {it.title}
                      </a>
                    ) : (
                      it.title
                    )}
                  </h3>
                  {it.summary && (
                    <p className="line-clamp-3 text-xs leading-relaxed text-muted">{it.summary}</p>
                  )}
                  {(it.vuln_ids.length > 0 || it.tags.length > 0) && (
                    <div className="flex flex-wrap gap-1">
                      {it.vuln_ids.map((id) => (
                        <button
                          key={id}
                          type="button"
                          onClick={() => onOpenVuln(id)}
                          className="rounded border border-line bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] hover:border-accent hover:text-accent"
                        >
                          {id}
                        </button>
                      ))}
                      {it.tags.map((tag) => (
                        <span key={tag} className="px-1 text-[10px] text-muted">
                          #{tag}
                        </span>
                      ))}
                    </div>
                  )}
                </li>
              ))}
            </ul>
            <OffsetPager
              total={page.total}
              limit={LIMIT}
              offset={offset}
              onChange={(o) => update({ offset: o || null })}
            />
          </Card>
        )}
      </QueryView>
    </div>
  );
}
