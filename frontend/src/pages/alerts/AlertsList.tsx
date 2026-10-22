/**
 * Alerts list (/alerts). Filters live in the URL so a filtered view can be shared or bookmarked:
 *   ?status&severity&category&source_ip&min_ai_score&q&incident_id&offset
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell, FilterX, RefreshCw, Sparkles } from "lucide-react";
import { type ReactNode, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api } from "@/api/client";
import { type Alert, type AlertStatus, type Page, SEVERITIES } from "@/api/types";
import { ALERT_CATEGORIES, ALERT_STATUSES, type AlertUpdate } from "@/api/types-ops";
import { AiScore, Mono, PageHeader, SeverityBadge } from "@/components/common";
import {
  AlertStatusBadge,
  CategoryBadge,
  DebouncedInput,
  FilterField,
  Notice,
  Pager,
  TableSkeleton,
} from "@/components/common/OpsKit";
import { alertCategoryLabel, alertStatusLabel, fmt, useCanOperate } from "@/components/common/opsLabels";
import { useOpsLive } from "@/components/common/useOpsLive";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  Select,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/ui";
import { formatDateTime, timeAgo } from "@/lib/format";
import { useLabel, useLocal, useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const LIMIT = 50;
const FILTER_KEYS = [
  "status",
  "severity",
  "category",
  "source_ip",
  "min_ai_score",
  "q",
  "incident_id",
] as const;
type FilterKey = (typeof FILTER_KEYS)[number];

const strings = {
  ja: {
    title: "アラート",
    desc: "検知ルール・AI 振る舞い検知・デセプションが生成したアラート。LLM が一次トリアージします。",
    total: "全 {n} 件",
    search: "検索",
    searchPh: "タイトル・説明・ルール ID",
    sourceIp: "送信元 IP",
    minAi: "AI スコア下限",
    any: "指定なし",
    category: "カテゴリ",
    clear: "フィルタをクリア",
    quick: "クイック",
    qNew: "未対応",
    qAi: "AI 関与 ≥70%",
    qDeception: "デセプション",
    incidentFilter: "インシデント {id} のアラートのみ",
    colTitle: "タイトル",
    colCategory: "カテゴリ",
    colCount: "件数",
    colAi: "AI スコア",
    colLast: "最終検知",
    selectAll: "このページをすべて選択",
    selectRow: "選択",
    selected: "{n} 件選択中",
    changeTo: "状態を変更",
    apply: "一括変更",
    clearSel: "選択解除",
    bulkDone: "{ok} 件を更新しました",
    bulkFailed: "{ok} 件を更新、{failed} 件は失敗しました",
    emptyTitle: "アラートはまだありません",
    emptyHint: "センサーからイベントを取り込むと、検知結果がここに表示されます。",
    noMatch: "条件に一致するアラートはありません",
    filterBySource: "この送信元で絞り込む",
    retry: "再試行",
  },
  en: {
    title: "Alerts",
    desc: "Alerts from detection rules, AI-behaviour detectors and deception. The LLM performs first-pass triage.",
    total: "{n} total",
    search: "Search",
    searchPh: "Title, description, rule id",
    sourceIp: "Source IP",
    minAi: "Min AI score",
    any: "Any",
    category: "Category",
    clear: "Clear filters",
    quick: "Quick",
    qNew: "Unhandled",
    qAi: "AI ≥70%",
    qDeception: "Deception",
    incidentFilter: "Only alerts of incident {id}",
    colTitle: "Title",
    colCategory: "Category",
    colCount: "Count",
    colAi: "AI score",
    colLast: "Last seen",
    selectAll: "Select all on this page",
    selectRow: "Select",
    selected: "{n} selected",
    changeTo: "Change status",
    apply: "Apply",
    clearSel: "Clear selection",
    bulkDone: "Updated {ok} alert(s)",
    bulkFailed: "Updated {ok}, {failed} failed",
    emptyTitle: "No alerts yet",
    emptyHint: "Detections appear here once sensors start ingesting events.",
    noMatch: "No alerts match the filters",
    filterBySource: "Filter by this source",
    retry: "Retry",
  },
};

export function AlertsListPage() {
  const L = useLocal(strings);
  const t = useT();
  const label = useLabel();
  const canOperate = useCanOperate();
  const qc = useQueryClient();
  const [sp, setSp] = useSearchParams();

  const filters = Object.fromEntries(FILTER_KEYS.map((k) => [k, sp.get(k) ?? ""])) as Record<
    FilterKey,
    string
  >;
  const offset = Math.max(0, Number(sp.get("offset")) || 0);
  const hasFilters = FILTER_KEYS.some((k) => filters[k]);

  const update = (mutate: (n: URLSearchParams) => void) =>
    setSp(
      (prev) => {
        const n = new URLSearchParams(prev);
        mutate(n);
        return n;
      },
      { replace: true },
    );
  const setFilter = (k: FilterKey, v: string) =>
    update((n) => {
      if (v) n.set(k, v);
      else n.delete(k);
      n.delete("offset");
    });
  const toggleFilter = (k: FilterKey, v: string) => setFilter(k, filters[k] === v ? "" : v);

  const q = useQuery({
    queryKey: ["alerts", "list", filters, offset],
    queryFn: () => api.get<Page<Alert>>("/alerts", { ...filters, limit: LIMIT, offset }),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });
  useOpsLive(["alert."], [["alerts", "list"]]);

  const items = q.data?.items ?? [];
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [bulkStatus, setBulkStatus] = useState<AlertStatus>("acknowledged");
  const [bulkResult, setBulkResult] = useState<{ ok: number; failed: number } | null>(null);
  const visibleSelected = items.filter((a) => selected.has(a.id)).map((a) => a.id);
  const allSelected = items.length > 0 && visibleSelected.length === items.length;

  const toggle = (id: string) =>
    setSelected((prev) => {
      const n = new Set(prev);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  const bulk = useMutation({
    mutationFn: async ({ ids, status }: { ids: string[]; status: AlertStatus }) => {
      const res = await Promise.allSettled(
        ids.map((id) => api.patch<Alert>(`/alerts/${id}`, { status } satisfies AlertUpdate)),
      );
      return {
        ok: res.filter((r) => r.status === "fulfilled").length,
        failed: res.filter((r) => r.status === "rejected").length,
      };
    },
    onSuccess: (r) => {
      setBulkResult(r);
      setSelected(new Set());
      void qc.invalidateQueries({ queryKey: ["alerts"] });
    },
  });

  return (
    <div>
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <Bell className="h-5 w-5 text-accent" aria-hidden />
            {L.title}
          </span>
        }
        description={L.desc}
        actions={
          <Button variant="outline" size="sm" onClick={() => q.refetch()} disabled={q.isFetching}>
            <RefreshCw className={cn("h-3.5 w-3.5", q.isFetching && "animate-spin")} aria-hidden />
            {t("common.refresh")}
          </Button>
        }
      />

      {/* Filters */}
      <Card className="mb-3 p-3">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
          <div className="col-span-2">
            <FilterField label={L.search} htmlFor="af-q">
              <DebouncedInput
                id="af-q"
                type="search"
                value={filters.q}
                onCommit={(v) => setFilter("q", v)}
                placeholder={L.searchPh}
              />
            </FilterField>
          </div>
          <FilterField label={t("common.status")} htmlFor="af-status">
            <Select
              id="af-status"
              value={filters.status}
              onChange={(e) => setFilter("status", e.target.value)}
            >
              <option value="">{t("common.all")}</option>
              {ALERT_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {label(alertStatusLabel[s])}
                </option>
              ))}
            </Select>
          </FilterField>
          <FilterField label={t("common.severity")} htmlFor="af-sev">
            <Select
              id="af-sev"
              value={filters.severity}
              onChange={(e) => setFilter("severity", e.target.value)}
            >
              <option value="">{t("common.all")}</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {t(`severity.${s}`)}
                </option>
              ))}
            </Select>
          </FilterField>
          <FilterField label={L.category} htmlFor="af-cat">
            <Select
              id="af-cat"
              value={filters.category}
              onChange={(e) => setFilter("category", e.target.value)}
            >
              <option value="">{t("common.all")}</option>
              {ALERT_CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {label(alertCategoryLabel[c])}
                </option>
              ))}
            </Select>
          </FilterField>
          <FilterField label={L.sourceIp} htmlFor="af-src">
            <DebouncedInput
              id="af-src"
              className="font-mono"
              value={filters.source_ip}
              onCommit={(v) => setFilter("source_ip", v.trim())}
              placeholder="203.0.113.7"
            />
          </FilterField>
          <FilterField label={L.minAi} htmlFor="af-ai">
            <Select
              id="af-ai"
              value={filters.min_ai_score}
              onChange={(e) => setFilter("min_ai_score", e.target.value)}
            >
              <option value="">{L.any}</option>
              <option value="0.4">≥ 40%</option>
              <option value="0.7">≥ 70%</option>
              <option value="0.9">≥ 90%</option>
            </Select>
          </FilterField>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-muted">{L.quick}:</span>
          <QuickChip active={filters.status === "new"} onClick={() => toggleFilter("status", "new")}>
            {L.qNew}
          </QuickChip>
          <QuickChip
            ai
            active={filters.min_ai_score === "0.7"}
            onClick={() => toggleFilter("min_ai_score", "0.7")}
          >
            <Sparkles className="h-3 w-3" aria-hidden />
            {L.qAi}
          </QuickChip>
          <QuickChip
            active={filters.category === "deception"}
            onClick={() => toggleFilter("category", "deception")}
          >
            {L.qDeception}
          </QuickChip>
          {filters.incident_id && (
            <Badge tone="accent">{fmt(L.incidentFilter, { id: filters.incident_id.slice(0, 8) })}</Badge>
          )}
          {hasFilters && (
            <Button
              variant="ghost"
              size="sm"
              className="ml-auto"
              onClick={() => setSp({}, { replace: true })}
            >
              <FilterX className="h-3.5 w-3.5" aria-hidden />
              {L.clear}
            </Button>
          )}
        </div>
      </Card>

      {/* Bulk actions */}
      {canOperate && visibleSelected.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-accent/40 bg-accent-soft px-3 py-2 text-sm">
          <span className="font-medium">{fmt(L.selected, { n: visibleSelected.length })}</span>
          <label htmlFor="bulk-status" className="ml-2 text-xs text-muted">
            {L.changeTo}
          </label>
          <Select
            id="bulk-status"
            className="h-8"
            value={bulkStatus}
            onChange={(e) => setBulkStatus(e.target.value as AlertStatus)}
          >
            {ALERT_STATUSES.filter((s) => s !== "triaging").map((s) => (
              <option key={s} value={s}>
                {label(alertStatusLabel[s])}
              </option>
            ))}
          </Select>
          <Button
            size="sm"
            onClick={() => bulk.mutate({ ids: visibleSelected, status: bulkStatus })}
            disabled={bulk.isPending}
          >
            {L.apply}
          </Button>
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>
            {L.clearSel}
          </Button>
        </div>
      )}
      {bulkResult && (
        <Notice tone={bulkResult.failed ? "warn" : "accent"} className="mb-3">
          <span className="flex items-center justify-between gap-2">
            {bulkResult.failed ? fmt(L.bulkFailed, bulkResult) : fmt(L.bulkDone, bulkResult)}
            <button type="button" className="text-muted hover:text-fg" onClick={() => setBulkResult(null)}>
              ×
            </button>
          </span>
        </Notice>
      )}
      {bulk.error && <ErrorState error={bulk.error} />}

      <Card>
        {q.isLoading ? (
          <TableSkeleton />
        ) : q.error ? (
          <div className="space-y-2 p-4">
            <ErrorState error={q.error} />
            <Button size="sm" variant="outline" onClick={() => q.refetch()}>
              {L.retry}
            </Button>
          </div>
        ) : items.length === 0 ? (
          hasFilters ? (
            <EmptyState
              title={L.noMatch}
              hint={
                <Button size="sm" variant="ghost" onClick={() => setSp({}, { replace: true })}>
                  {L.clear}
                </Button>
              }
            />
          ) : (
            <EmptyState
              icon={<Bell className="h-8 w-8" aria-hidden />}
              title={L.emptyTitle}
              hint={L.emptyHint}
            />
          )
        ) : (
          <>
            <div className="flex items-center justify-between border-b border-line px-3 py-2 text-xs text-muted">
              <span className="tabular-nums">{fmt(L.total, { n: q.data?.total ?? 0 })}</span>
            </div>
            <Table>
              <THead>
                <tr>
                  {canOperate && (
                    <TH className="w-8">
                      <input
                        type="checkbox"
                        aria-label={L.selectAll}
                        className="accent-[var(--tk-accent)]"
                        checked={allSelected}
                        onChange={() =>
                          setSelected((prev) => {
                            const n = new Set(prev);
                            for (const a of items) {
                              if (allSelected) n.delete(a.id);
                              else n.add(a.id);
                            }
                            return n;
                          })
                        }
                      />
                    </TH>
                  )}
                  <TH>{t("common.severity")}</TH>
                  <TH>{L.colTitle}</TH>
                  <TH>{L.colCategory}</TH>
                  <TH>{t("common.source")}</TH>
                  <TH className="text-right">{L.colCount}</TH>
                  <TH>{L.colAi}</TH>
                  <TH>{t("common.status")}</TH>
                  <TH>{L.colLast}</TH>
                </tr>
              </THead>
              <TBody>
                {items.map((a) => {
                  const ai = (a.ai_score ?? 0) >= 0.7;
                  return (
                    <TR key={a.id} className={cn(selected.has(a.id) && "bg-accent-soft/40")}>
                      {canOperate && (
                        <TD className={cn(ai && "shadow-[inset_3px_0_0_0_var(--color-ai)]")}>
                          <input
                            type="checkbox"
                            aria-label={`${L.selectRow}: ${a.title}`}
                            className="accent-[var(--tk-accent)]"
                            checked={selected.has(a.id)}
                            onChange={() => toggle(a.id)}
                          />
                        </TD>
                      )}
                      <TD className={cn(!canOperate && ai && "shadow-[inset_3px_0_0_0_var(--color-ai)]")}>
                        <SeverityBadge severity={a.severity} />
                      </TD>
                      <TD className="max-w-[420px]">
                        <Link to={`/alerts/${a.id}`} className="line-clamp-2 font-medium hover:text-accent">
                          {a.title}
                        </Link>
                        <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
                          <Mono className="text-[11px] text-muted">{a.rule_id}</Mono>
                          {a.incident_id && (
                            <Link
                              to={`/incidents/${a.incident_id}`}
                              className="text-[11px] text-accent hover:underline"
                            >
                              INC-{a.incident_id.slice(0, 6)}
                            </Link>
                          )}
                        </div>
                      </TD>
                      <TD>
                        <CategoryBadge category={a.category} />
                      </TD>
                      <TD>
                        {a.source_ip ? (
                          <button
                            type="button"
                            className="font-mono text-xs hover:text-accent"
                            title={L.filterBySource}
                            onClick={() => a.source_ip && setFilter("source_ip", a.source_ip)}
                          >
                            {a.source_ip}
                          </button>
                        ) : (
                          <span className="text-muted">-</span>
                        )}
                      </TD>
                      <TD className="text-right tabular-nums">{a.count}</TD>
                      <TD>
                        <AiScore score={a.ai_score} className={cn(ai && "font-semibold text-ai")} />
                      </TD>
                      <TD>
                        <AlertStatusBadge status={a.status} />
                      </TD>
                      <TD
                        className="whitespace-nowrap text-xs text-muted"
                        title={formatDateTime(a.last_seen)}
                      >
                        {timeAgo(a.last_seen)}
                      </TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
            <Pager
              total={q.data?.total ?? 0}
              limit={LIMIT}
              offset={offset}
              onChange={(o) =>
                update((n) => {
                  if (o) n.set("offset", String(o));
                  else n.delete("offset");
                })
              }
            />
          </>
        )}
      </Card>
    </div>
  );
}

function QuickChip({
  active,
  ai,
  onClick,
  children,
}: {
  active: boolean;
  ai?: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2.5 py-1 transition-colors",
        active
          ? ai
            ? "border-ai/60 bg-ai/15 text-ai"
            : "border-accent/60 bg-accent-soft text-accent"
          : "border-line text-muted hover:text-fg",
      )}
    >
      {children}
    </button>
  );
}
