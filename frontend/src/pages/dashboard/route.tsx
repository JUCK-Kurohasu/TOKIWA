/**
 * Dashboard (`/`): 24h KPIs, activity timeline, live feed, top sources / rules, recent incidents.
 * Data: GET /dashboard/summary, GET /dashboard/timeline, SSE /stream.
 */
import { useQueryClient } from "@tanstack/react-query";
import {
  Bot,
  Coins,
  Flag,
  Gavel,
  LayoutDashboard,
  RefreshCw,
  ShieldAlert,
  Siren,
  Waypoints,
} from "lucide-react";
import { Link } from "react-router";
import type { DashboardSummary } from "@/api/types-core";
import { ActorBadge, AiScore, Mono, PageHeader, SeverityBadge } from "@/components/common";
import { ApiErrorNotice, DataState } from "@/components/common/DataState";
import { LiveDot } from "@/components/common/LiveDot";
import { Badge, Button, Card, CardHeader } from "@/components/ui";
import { useApiQuery } from "@/hooks/useApi";
import { useLiveStream } from "@/hooks/useLiveStream";
import { formatNumber, formatUsd, timeAgo } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import type { AppRoute } from "@/routes";
import { LiveFeed } from "./LiveFeed";
import { TimelineCard } from "./TimelineCard";
import { BudgetMeter, InlineBar, SeverityBreakdown, StatTile } from "./widgets";

const strings = {
  ja: {
    title: "ダッシュボード",
    desc: "過去 24 時間の脅威状況。AI エージェント由来のシグナルは紫で表示します。",
    refresh: "更新",
    alerts: "アラート (24h)",
    incidents: "オープンインシデント",
    aiSessions: "AI エージェントセッション (24h)",
    aiSessionsHint: "振る舞い特徴量による推定",
    llmCost: "LLM 費用 (今日)",
    budget: "予算",
    pending: "承認待ち対処",
    pendingHint: "承認なしでは実行されません",
    kev: "KEV 一致",
    kevHint: "既知の悪用脆弱性 × 資産",
    events: "イベント (24h)",
    topSources: "上位送信元",
    topSourcesDesc: "アラート件数と AI スコア",
    topRules: "上位ルール",
    topRulesDesc: "24 時間の検知件数",
    recent: "最近のインシデント",
    recentDesc: "新しい順",
    noSources: "送信元はまだありません",
    noRules: "検知はまだありません",
    noIncidents: "インシデントはありません",
    count: "件",
    sessions: "セッション",
    allIncidents: "すべて表示",
    alertsUnit: "アラート",
  },
  en: {
    title: "Dashboard",
    desc: "Threat picture for the last 24 hours. Signals attributed to AI agents are shown in purple.",
    refresh: "Refresh",
    alerts: "Alerts (24h)",
    incidents: "Open incidents",
    aiSessions: "AI agent sessions (24h)",
    aiSessionsHint: "Estimated from behaviour",
    llmCost: "LLM cost (today)",
    budget: "budget",
    pending: "Pending actions",
    pendingHint: "Nothing runs without approval",
    kev: "KEV matches",
    kevHint: "Known-exploited vulns × assets",
    events: "Events (24h)",
    topSources: "Top sources",
    topSourcesDesc: "Alert count and AI score",
    topRules: "Top rules",
    topRulesDesc: "Detections in 24h",
    recent: "Recent incidents",
    recentDesc: "Newest first",
    noSources: "No sources yet",
    noRules: "No detections yet",
    noIncidents: "No incidents",
    count: "",
    sessions: "Sessions",
    allIncidents: "View all",
    alertsUnit: "alerts",
  },
};

function KpiRow({ data, loading }: { data?: DashboardSummary; loading: boolean }) {
  const L = useLocal(strings);
  const s = data;
  const v = (n: number | undefined) => (n == null ? "-" : formatNumber(n));
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
      <StatTile
        label={L.alerts}
        value={v(s?.alerts_24h?.total)}
        icon={<Siren className="h-3.5 w-3.5" />}
        to="/alerts"
        loading={loading}
        tone={(s?.alerts_24h?.by_severity?.critical ?? 0) > 0 ? "danger" : "neutral"}
      >
        {s && <SeverityBreakdown bySeverity={s.alerts_24h?.by_severity ?? {}} />}
      </StatTile>
      <StatTile
        label={L.incidents}
        value={v(s?.open_incidents)}
        icon={<Flag className="h-3.5 w-3.5" />}
        to="/incidents"
        loading={loading}
        tone={(s?.open_incidents ?? 0) > 0 ? "warn" : "neutral"}
        hint={s ? `${L.events} ${formatNumber(s.events_24h)}` : undefined}
      />
      <StatTile
        label={L.aiSessions}
        value={v(s?.ai_sessions_24h)}
        icon={<Bot className="h-3.5 w-3.5 text-ai" />}
        to="/sessions?classification=ai_agent"
        loading={loading}
        tone={(s?.ai_sessions_24h ?? 0) > 0 ? "ai" : "neutral"}
        highlight={(s?.ai_sessions_24h ?? 0) > 0 ? "ai" : undefined}
        hint={L.aiSessionsHint}
      />
      <StatTile
        label={L.llmCost}
        value={s ? formatUsd(s.llm_cost_today_usd) : "-"}
        icon={<Coins className="h-3.5 w-3.5" />}
        to="/llm"
        loading={loading}
        hint={s ? `${L.budget} ${formatUsd(s.llm_budget_usd)}` : undefined}
      >
        {s && <BudgetMeter spent={s.llm_cost_today_usd} budget={s.llm_budget_usd} />}
      </StatTile>
      <StatTile
        label={L.pending}
        value={v(s?.pending_actions)}
        icon={<Gavel className="h-3.5 w-3.5" />}
        to="/response"
        loading={loading}
        tone={(s?.pending_actions ?? 0) > 0 ? "warn" : "neutral"}
        hint={L.pendingHint}
      />
      <StatTile
        label={L.kev}
        value={v(s?.kev_matches)}
        icon={<ShieldAlert className="h-3.5 w-3.5" />}
        to="/intel"
        loading={loading}
        tone={(s?.kev_matches ?? 0) > 0 ? "danger" : "neutral"}
        hint={L.kevHint}
      />
    </div>
  );
}

function TopSources({ data, loading, error }: { data?: DashboardSummary; loading: boolean; error: unknown }) {
  const L = useLocal(strings);
  const rows = data?.top_sources ?? [];
  const max = Math.max(1, ...rows.map((r) => r.count));
  return (
    <Card>
      <CardHeader title={L.topSources} description={L.topSourcesDesc} />
      <DataState
        loading={loading}
        empty={(!!data && rows.length === 0) || !!error}
        emptyTitle={error ? "—" : L.noSources}
        className="p-4"
      >
        <ul className="divide-y divide-line">
          {rows.slice(0, 8).map((r) => {
            const ai = (r.ai_score ?? 0) >= 0.7;
            return (
              <li
                key={r.ip}
                className={cn(
                  "grid grid-cols-[minmax(0,1fr)_72px_auto] items-center gap-3 border-l-2 px-4 py-2",
                  ai ? "border-l-ai bg-ai/[0.04]" : "border-l-transparent",
                )}
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5">
                    <Link
                      to={`/events?source_ip=${encodeURIComponent(r.ip)}`}
                      className="truncate font-mono text-xs hover:text-accent hover:underline"
                    >
                      {r.ip}
                    </Link>
                    {ai && <Badge tone="ai">AI</Badge>}
                    <Link
                      to={`/sessions?source_ip=${encodeURIComponent(r.ip)}`}
                      className="text-muted hover:text-ai"
                      title={L.sessions}
                      aria-label={`${L.sessions}: ${r.ip}`}
                    >
                      <Waypoints className="h-3 w-3" />
                    </Link>
                  </div>
                  <InlineBar value={r.count} max={max} className="mt-1" />
                </div>
                <span className="text-right text-xs tabular-nums">
                  {formatNumber(r.count)}
                  <span className="ml-0.5 text-muted">{L.count}</span>
                </span>
                <AiScore score={r.ai_score} />
              </li>
            );
          })}
        </ul>
      </DataState>
    </Card>
  );
}

function TopRules({ data, loading, error }: { data?: DashboardSummary; loading: boolean; error: unknown }) {
  const L = useLocal(strings);
  const rows = data?.top_rules ?? [];
  const max = Math.max(1, ...rows.map((r) => r.count));
  return (
    <Card>
      <CardHeader title={L.topRules} description={L.topRulesDesc} />
      <DataState
        loading={loading}
        empty={(!!data && rows.length === 0) || !!error}
        emptyTitle={error ? "—" : L.noRules}
        className="p-4"
      >
        <ul className="divide-y divide-line">
          {rows.slice(0, 8).map((r) => {
            const ai = r.rule_id.startsWith("ai.") || r.rule_id.startsWith("llm_app.");
            return (
              <li
                key={r.rule_id}
                className="grid grid-cols-[minmax(0,1fr)_56px] items-center gap-3 px-4 py-2"
              >
                <div className="min-w-0">
                  <Link
                    to={`/alerts?q=${encodeURIComponent(r.rule_id)}`}
                    className="block truncate text-sm hover:text-accent hover:underline"
                    title={r.title}
                  >
                    {r.title || r.rule_id}
                  </Link>
                  <div className="flex items-center gap-1.5">
                    <Mono className={cn("truncate", ai ? "text-ai" : "text-muted")}>{r.rule_id}</Mono>
                  </div>
                  <InlineBar value={r.count} max={max} className="mt-1" />
                </div>
                <span className="text-right text-xs tabular-nums">{formatNumber(r.count)}</span>
              </li>
            );
          })}
        </ul>
      </DataState>
    </Card>
  );
}

function RecentIncidents({
  data,
  loading,
  error,
}: {
  data?: DashboardSummary;
  loading: boolean;
  error: unknown;
}) {
  const L = useLocal(strings);
  const rows = data?.recent_incidents ?? [];
  return (
    <Card>
      <CardHeader
        title={L.recent}
        description={L.recentDesc}
        actions={
          <Link to="/incidents" className="text-xs text-accent hover:underline">
            {L.allIncidents}
          </Link>
        }
      />
      <DataState
        loading={loading}
        empty={(!!data && rows.length === 0) || !!error}
        emptyTitle={error ? "—" : L.noIncidents}
        className="p-4"
      >
        <ul className="divide-y divide-line">
          {rows.slice(0, 8).map((inc) => {
            const ai = inc.actor_type === "ai_agent";
            return (
              <li key={inc.id}>
                <Link
                  to={`/incidents/${inc.id}`}
                  className={cn(
                    "block border-l-2 px-4 py-2 hover:bg-surface-2/60 focus-visible:outline-2 focus-visible:outline-accent",
                    ai ? "border-l-ai bg-ai/[0.04]" : "border-l-transparent",
                  )}
                >
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={inc.severity} />
                    <span className="min-w-0 flex-1 truncate text-sm">{inc.title}</span>
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted">
                    <ActorBadge actor={inc.actor_type} />
                    {inc.ai_score != null && <AiScore score={inc.ai_score} />}
                    <span className="tabular-nums">
                      {formatNumber(inc.alert_count)} {L.alertsUnit}
                    </span>
                    <span className="ml-auto">{timeAgo(inc.last_seen)}</span>
                  </div>
                </Link>
              </li>
            );
          })}
        </ul>
      </DataState>
    </Card>
  );
}

function DashboardPage() {
  const L = useLocal(strings);
  const qc = useQueryClient();
  const { status } = useLiveStream();
  const summary = useApiQuery<DashboardSummary>(["dashboard", "summary"], "/dashboard/summary", undefined, {
    refetchInterval: 30_000,
    keepPrevious: true,
  });

  return (
    <div className="space-y-4">
      <PageHeader
        title={L.title}
        description={L.desc}
        actions={
          <>
            <LiveDot status={status} />
            <Button
              variant="outline"
              size="sm"
              onClick={() => qc.invalidateQueries({ queryKey: ["dashboard"] })}
              disabled={summary.isFetching}
            >
              <RefreshCw className={cn("h-3.5 w-3.5", summary.isFetching && "animate-spin")} />
              {L.refresh}
            </Button>
          </>
        }
      />
      {summary.error ? (
        <ApiErrorNotice error={summary.error} onRetry={() => summary.refetch()} compact />
      ) : null}
      <KpiRow data={summary.data} loading={summary.isLoading} />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <TimelineCard />
        </div>
        <LiveFeed className="h-[420px] xl:h-auto xl:max-h-[452px]" />
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3">
        <TopSources data={summary.data} loading={summary.isLoading} error={summary.error} />
        <TopRules data={summary.data} loading={summary.isLoading} error={summary.error} />
        <RecentIncidents data={summary.data} loading={summary.isLoading} error={summary.error} />
      </div>
    </div>
  );
}

export const route: AppRoute = {
  path: "/",
  component: DashboardPage,
  nav: {
    label: { ja: "ダッシュボード", en: "Dashboard" },
    icon: LayoutDashboard,
    section: "monitor",
    order: 0,
  },
};
