/** Vulnerability list with KEV / EPSS / CVSS / asset-match filters. Default backend order: KEV → EPSS → CVSS. */
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Flame, Link2, Search } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";
import { api } from "@/api/client";
import type { Page, VulnRecord } from "@/api/types";
import { FilterChip } from "@/components/common/FilterChip";
import { CvssScore, EpssBar, KevBadge } from "@/components/common/IntelBadges";
import { OffsetPager } from "@/components/common/OffsetPager";
import { QueryView } from "@/components/common/QueryView";
import { useUrlParams } from "@/components/common/urlState";
import { Badge, Card, EmptyState, Input, Select, Table, TBody, TD, TH, THead, TR } from "@/components/ui";
import { formatNumber, timeAgo } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const LIMIT = 50;

const strings = {
  ja: {
    search: "CVE ID・製品名・説明で検索",
    kev: "KEV のみ",
    matched: "資産一致のみ",
    epss: "EPSS",
    cvss: "CVSS",
    any: "指定なし",
    id: "ID",
    title: "概要",
    published: "公開",
    sources: "情報源",
    empty: "条件に一致する脆弱性はありません",
    emptyHint: "フィルタを緩めるか、ソース状態タブで同期を確認してください。",
    total: "件",
  },
  en: {
    search: "Search CVE id, product, description",
    kev: "KEV only",
    matched: "Matched assets only",
    epss: "EPSS",
    cvss: "CVSS",
    any: "Any",
    id: "ID",
    title: "Summary",
    published: "Published",
    sources: "Sources",
    empty: "No vulnerabilities match the filters",
    emptyHint: "Loosen the filters or check feed sync on the Sources tab.",
    total: "results",
  },
};

const EPSS_OPTIONS = ["0.01", "0.1", "0.5", "0.9"];
const CVSS_OPTIONS = ["4", "7", "9"];

export function VulnsTab({ onOpen }: { onOpen: (id: string) => void }) {
  const L = useLocal(strings);
  const [params, update] = useUrlParams();
  const q = params.get("q") ?? "";
  const kev = params.get("kev") === "1";
  const matched = params.get("matched") === "1";
  const minEpss = params.get("min_epss") ?? "";
  const minCvss = params.get("min_cvss") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const [qInput, setQInput] = useState(q);
  useEffect(() => setQInput(q), [q]);

  const query = useQuery({
    queryKey: ["intel", "vulns", { q, kev, matched, minEpss, minCvss, offset }],
    queryFn: () =>
      api.get<Page<VulnRecord>>("/intel/vulns", {
        q,
        kev: kev ? true : undefined,
        matched: matched ? true : undefined,
        min_epss: minEpss,
        min_cvss: minCvss,
        limit: LIMIT,
        offset,
      }),
    placeholderData: keepPreviousData,
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    update({ q: qInput.trim(), offset: null });
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <form onSubmit={submit} className="relative min-w-[16rem] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted" aria-hidden />
          <Input
            value={qInput}
            onChange={(e) => setQInput(e.target.value)}
            placeholder={L.search}
            aria-label={L.search}
            className="pl-8"
          />
        </form>
        <FilterChip
          pressed={kev}
          tone="danger"
          onChange={(v) => update({ kev: v ? "1" : null, offset: null })}
        >
          <Flame className="h-3.5 w-3.5" aria-hidden />
          {L.kev}
        </FilterChip>
        <FilterChip pressed={matched} onChange={(v) => update({ matched: v ? "1" : null, offset: null })}>
          <Link2 className="h-3.5 w-3.5" aria-hidden />
          {L.matched}
        </FilterChip>
        <span className="flex items-center gap-1.5 text-xs text-muted">
          {L.epss} ≥
          <Select
            aria-label={`${L.epss} ≥`}
            value={minEpss}
            onChange={(e) => update({ min_epss: e.target.value, offset: null })}
          >
            <option value="">{L.any}</option>
            {EPSS_OPTIONS.map((o) => (
              <option key={o} value={o}>
                {Number(o) * 100}%
              </option>
            ))}
          </Select>
        </span>
        <span className="flex items-center gap-1.5 text-xs text-muted">
          {L.cvss} ≥
          <Select
            aria-label={`${L.cvss} ≥`}
            value={minCvss}
            onChange={(e) => update({ min_cvss: e.target.value, offset: null })}
          >
            <option value="">{L.any}</option>
            {CVSS_OPTIONS.map((o) => (
              <option key={o} value={o}>
                {Number(o).toFixed(1)}
              </option>
            ))}
          </Select>
        </span>
      </div>

      <Card className={cn(query.isFetching && !query.isLoading && "opacity-80")}>
        <QueryView
          query={query}
          className="p-4"
          rows={8}
          isEmpty={(d) => d.items.length === 0}
          empty={<EmptyState title={L.empty} hint={L.emptyHint} />}
        >
          {(page) => (
            <>
              <div className="border-b border-line px-3 py-2 text-xs text-muted">
                {formatNumber(page.total)} {L.total}
              </div>
              <Table>
                <THead>
                  <tr>
                    <TH className="w-56">{L.id}</TH>
                    <TH>{L.title}</TH>
                    <TH className="w-20">{L.cvss}</TH>
                    <TH className="w-32">{L.epss}</TH>
                    <TH className="w-24">{L.published}</TH>
                    <TH className="w-36">{L.sources}</TH>
                  </tr>
                </THead>
                <TBody>
                  {page.items.map((v) => (
                    <TR
                      key={v.id}
                      className={cn(
                        "cursor-pointer",
                        v.kev && "bg-sev-critical/[0.04] shadow-[inset_3px_0_0_0_var(--color-sev-critical)]",
                      )}
                      onClick={() => onOpen(v.id)}
                    >
                      <TD>
                        <div className="flex flex-col items-start gap-1">
                          <button
                            type="button"
                            className="font-mono text-xs font-medium text-fg hover:text-accent hover:underline"
                            onClick={(e) => {
                              e.stopPropagation();
                              onOpen(v.id);
                            }}
                          >
                            {v.id}
                          </button>
                          {v.kev && <KevBadge ransomware={v.kev_ransomware} />}
                        </div>
                      </TD>
                      <TD>
                        <div className="line-clamp-2 text-sm">{v.title || v.description || "-"}</div>
                        {v.cwe.length > 0 && (
                          <div className="mt-0.5 text-[11px] text-muted">{v.cwe.slice(0, 3).join(", ")}</div>
                        )}
                      </TD>
                      <TD>
                        <CvssScore score={v.cvss_score} vector={v.cvss_vector} />
                      </TD>
                      <TD>
                        <EpssBar epss={v.epss} percentile={v.epss_percentile} />
                      </TD>
                      <TD className="text-xs text-muted" title={v.published ?? undefined}>
                        {timeAgo(v.published)}
                      </TD>
                      <TD>
                        <div className="flex flex-wrap gap-1">
                          {v.sources.slice(0, 4).map((s) => (
                            <Badge
                              key={s}
                              tone={s === "kev" ? "danger" : s === "research" ? "ai" : "neutral"}
                            >
                              {s}
                            </Badge>
                          ))}
                        </div>
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
              <OffsetPager
                total={page.total}
                limit={LIMIT}
                offset={offset}
                onChange={(o) => update({ offset: o || null })}
              />
            </>
          )}
        </QueryView>
      </Card>
    </div>
  );
}
