/**
 * Incidents list (/incidents). Correlated alerts grouped by actor; AI-agent actors are emphasised in purple.
 * Filters live in the URL: ?status&severity&actor_type&offset
 */
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Bot, FilterX, Flame, RefreshCw } from "lucide-react";
import { Link, useSearchParams } from "react-router";
import { api } from "@/api/client";
import { type ActorType, type Incident, type Page, SEVERITIES } from "@/api/types";
import { ACTOR_TYPES, INCIDENT_STATUSES } from "@/api/types-ops";
import { ActorBadge, AiScore, PageHeader, SeverityBadge } from "@/components/common";
import { KillChainMini } from "@/components/common/KillChain";
import {
  FilterChip,
  FilterField,
  IncidentStatusBadge,
  Pager,
  TableSkeleton,
} from "@/components/common/OpsKit";
import { fmt, incidentStatusLabel } from "@/components/common/opsLabels";
import { useOpsLive } from "@/components/common/useOpsLive";
import {
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
const FILTER_KEYS = ["status", "severity", "actor_type"] as const;
type FilterKey = (typeof FILTER_KEYS)[number];

const actorOptionLabel: Record<ActorType, { ja: string; en: string }> = {
  ai_agent: { ja: "AI エージェント", en: "AI agent" },
  automated_scanner: { ja: "スキャナ", en: "Scanner" },
  human: { ja: "人間", en: "Human" },
  benign: { ja: "正常", en: "Benign" },
  unknown: { ja: "不明", en: "Unknown" },
};

const strings = {
  ja: {
    title: "インシデント",
    desc: "関連するアラートを送信元・セッション・エンティティで束ねたもの。kill chain の進行と AI 関与を一目で確認できます。",
    actor: "アクター",
    clear: "フィルタをクリア",
    aiOnly: "AI エージェントのみ",
    openOnly: "オープンのみ",
    colTitle: "タイトル",
    colKill: "キルチェーン",
    colAlerts: "アラート",
    colSources: "送信元",
    colAssignee: "担当",
    colLast: "最終",
    total: "全 {n} 件",
    more: "他 {n}",
    emptyTitle: "インシデントはありません",
    emptyHint: "相関エンジンが関連アラートを束ねると、ここにインシデントが作成されます。",
    noMatch: "条件に一致するインシデントはありません",
    retry: "再試行",
  },
  en: {
    title: "Incidents",
    desc: "Related alerts grouped by source, session and entity. See kill-chain progress and AI involvement at a glance.",
    actor: "Actor",
    clear: "Clear filters",
    aiOnly: "AI agents only",
    openOnly: "Open only",
    colTitle: "Title",
    colKill: "Kill chain",
    colAlerts: "Alerts",
    colSources: "Sources",
    colAssignee: "Assignee",
    colLast: "Last",
    total: "{n} total",
    more: "+{n}",
    emptyTitle: "No incidents",
    emptyHint: "Incidents are created when the correlation engine groups related alerts.",
    noMatch: "No incidents match the filters",
    retry: "Retry",
  },
};

export function IncidentsListPage() {
  const L = useLocal(strings);
  const t = useT();
  const label = useLabel();
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

  const q = useQuery({
    queryKey: ["incidents", "list", filters, offset],
    queryFn: () => api.get<Page<Incident>>("/incidents", { ...filters, limit: LIMIT, offset }),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });
  useOpsLive(["incident."], [["incidents", "list"]]);
  const items = q.data?.items ?? [];

  return (
    <div>
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <Flame className="h-5 w-5 text-accent" aria-hidden />
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

      <Card className="mb-3 p-3">
        <div className="flex flex-wrap items-end gap-3">
          <FilterField label={t("common.status")} htmlFor="if-status">
            <Select
              id="if-status"
              value={filters.status}
              onChange={(e) => setFilter("status", e.target.value)}
            >
              <option value="">{t("common.all")}</option>
              {INCIDENT_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {label(incidentStatusLabel[s])}
                </option>
              ))}
            </Select>
          </FilterField>
          <FilterField label={t("common.severity")} htmlFor="if-sev">
            <Select
              id="if-sev"
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
          <FilterField label={L.actor} htmlFor="if-actor">
            <Select
              id="if-actor"
              value={filters.actor_type}
              onChange={(e) => setFilter("actor_type", e.target.value)}
            >
              <option value="">{t("common.all")}</option>
              {ACTOR_TYPES.map((a) => (
                <option key={a} value={a}>
                  {label(actorOptionLabel[a])}
                </option>
              ))}
            </Select>
          </FilterField>
          <div className="flex flex-wrap items-center gap-2 pb-1 text-xs">
            <FilterChip
              ai
              active={filters.actor_type === "ai_agent"}
              onClick={() => setFilter("actor_type", filters.actor_type === "ai_agent" ? "" : "ai_agent")}
            >
              <Bot className="h-3 w-3" aria-hidden />
              {L.aiOnly}
            </FilterChip>
            <FilterChip
              active={filters.status === "open"}
              onClick={() => setFilter("status", filters.status === "open" ? "" : "open")}
            >
              {L.openOnly}
            </FilterChip>
          </div>
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
          <EmptyState
            icon={hasFilters ? undefined : <Flame className="h-8 w-8" aria-hidden />}
            title={hasFilters ? L.noMatch : L.emptyTitle}
            hint={hasFilters ? undefined : L.emptyHint}
          />
        ) : (
          <>
            <div className="border-b border-line px-3 py-2 text-xs text-muted tabular-nums">
              {fmt(L.total, { n: q.data?.total ?? 0 })}
            </div>
            <Table>
              <THead>
                <tr>
                  <TH>{t("common.severity")}</TH>
                  <TH>{L.colTitle}</TH>
                  <TH>{L.actor}</TH>
                  <TH>{L.colKill}</TH>
                  <TH className="text-right">{L.colAlerts}</TH>
                  <TH>{L.colSources}</TH>
                  <TH>{t("common.status")}</TH>
                  <TH>{L.colAssignee}</TH>
                  <TH>{L.colLast}</TH>
                </tr>
              </THead>
              <TBody>
                {items.map((inc) => {
                  const ai = inc.actor_type === "ai_agent";
                  return (
                    <TR key={inc.id} className={cn(ai && "bg-ai/5")}>
                      <TD className={cn(ai && "shadow-[inset_3px_0_0_0_var(--color-ai)]")}>
                        <SeverityBadge severity={inc.severity} />
                      </TD>
                      <TD className="max-w-[380px]">
                        <Link
                          to={`/incidents/${inc.id}`}
                          className="line-clamp-1 font-medium hover:text-accent"
                        >
                          {inc.title}
                        </Link>
                        {inc.summary && <p className="line-clamp-1 text-xs text-muted">{inc.summary}</p>}
                      </TD>
                      <TD>
                        <div className="flex flex-col gap-1">
                          <ActorBadge actor={inc.actor_type} />
                          <AiScore score={inc.ai_score} className={cn(ai && "font-semibold text-ai")} />
                        </div>
                      </TD>
                      <TD>
                        <KillChainMini stages={inc.kill_chain ?? []} />
                      </TD>
                      <TD className="text-right tabular-nums">{inc.alert_count}</TD>
                      <TD className="font-mono text-xs">
                        {inc.source_ips[0] ?? "-"}
                        {inc.source_ips.length > 1 && (
                          <span className="ml-1 text-muted" title={inc.source_ips.join("\n")}>
                            {fmt(L.more, { n: inc.source_ips.length - 1 })}
                          </span>
                        )}
                      </TD>
                      <TD>
                        <IncidentStatusBadge status={inc.status} />
                      </TD>
                      <TD className="text-xs">{inc.assignee ?? <span className="text-muted">-</span>}</TD>
                      <TD
                        className="whitespace-nowrap text-xs text-muted"
                        title={formatDateTime(inc.last_seen)}
                      >
                        {timeAgo(inc.last_seen)}
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
