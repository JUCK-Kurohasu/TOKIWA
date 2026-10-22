/**
 * Activity over time as two aligned charts (no dual axis): event volume (area) above, alerts below as
 * stacked columns split into "other" (grey) and "AI-related" (purple). Hover is synced across both.
 */
import { BarChart3, Table2 } from "lucide-react";
import { useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { DashboardTimeline } from "@/api/types-core";
import {
  axisProps,
  ChartTooltipBox,
  LegendSwatch,
  TooltipRow,
  useChartPalette,
} from "@/components/common/ChartKit";
import { DataState } from "@/components/common/DataState";
import { formatCompact, formatTick } from "@/components/common/numfmt";
import { Button, Card, CardHeader, Table, TBody, TD, TH, THead, TR } from "@/components/ui";
import { useApiQuery } from "@/hooks/useApi";
import { formatDateTime, formatNumber } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const RANGES = [6, 24, 72, 168] as const;

interface Datum {
  t: number;
  events: number;
  alerts: number;
  other: number;
  ai: number;
}

export function TimelineCard() {
  const L = useLocal({
    ja: {
      title: "アクティビティ",
      events: "イベント",
      alerts: "アラート",
      other: "その他のアラート",
      ai: "AI 関連アラート",
      chart: "グラフ",
      table: "表",
      time: "時刻",
      empty: "この期間のデータはありません",
      range: "期間",
      total: "合計",
    },
    en: {
      title: "Activity",
      events: "Events",
      alerts: "Alerts",
      other: "Other alerts",
      ai: "AI-related alerts",
      chart: "Chart",
      table: "Table",
      time: "Time",
      empty: "No data for this period",
      range: "Range",
      total: "Total",
    },
  });
  const [hours, setHours] = useState<number>(24);
  const [view, setView] = useState<"chart" | "table">("chart");
  const p = useChartPalette();
  const q = useApiQuery<DashboardTimeline>(
    ["dashboard", "timeline", hours],
    "/dashboard/timeline",
    { hours },
    {
      keepPrevious: true,
      refetchInterval: 60_000,
    },
  );

  const data: Datum[] = useMemo(
    () =>
      (q.data?.buckets ?? []).map((b) => {
        const ai = Math.max(0, b.ai_alerts ?? 0);
        const alerts = Math.max(0, b.alerts ?? 0);
        return { t: Date.parse(b.ts), events: b.events ?? 0, alerts, ai, other: Math.max(0, alerts - ai) };
      }),
    [q.data],
  );
  const span = data.length > 1 ? data[data.length - 1].t - data[0].t : hours * 3600_000;
  const totals = data.reduce(
    (acc, d) => ({ events: acc.events + d.events, alerts: acc.alerts + d.alerts, ai: acc.ai + d.ai }),
    { events: 0, alerts: 0, ai: 0 },
  );
  const tick = (v: number) => formatTick(v, span);

  const tooltip = ({ active, payload }: { active?: boolean; payload?: readonly { payload?: Datum }[] }) => {
    const d = payload?.[0]?.payload;
    if (!active || !d) return null;
    return (
      <ChartTooltipBox title={formatDateTime(new Date(d.t).toISOString())}>
        <TooltipRow color={p.accent} label={L.events} value={formatNumber(d.events)} />
        <TooltipRow color={p.neutral} label={L.other} value={formatNumber(d.other)} />
        <TooltipRow color={p.ai} label={L.ai} value={formatNumber(d.ai)} />
      </ChartTooltipBox>
    );
  };

  return (
    <Card className="flex flex-col">
      <CardHeader
        title={L.title}
        description={
          q.data ? (
            <span className="tabular-nums">
              {L.events} {formatNumber(totals.events)} · {L.alerts} {formatNumber(totals.alerts)} ·{" "}
              <span className="text-ai">AI {formatNumber(totals.ai)}</span>
            </span>
          ) : undefined
        }
        actions={
          <>
            <div className="flex rounded-md border border-line p-0.5" title={L.range}>
              {RANGES.map((h) => (
                <button
                  key={h}
                  type="button"
                  aria-pressed={hours === h}
                  onClick={() => setHours(h)}
                  className={cn(
                    "rounded px-2 py-0.5 text-xs tabular-nums transition-colors",
                    hours === h ? "bg-accent-soft text-accent" : "text-muted hover:text-fg",
                  )}
                >
                  {h < 48 ? `${h}h` : `${h / 24}d`}
                </button>
              ))}
            </div>
            <Button
              size="icon"
              variant="ghost"
              onClick={() => setView(view === "chart" ? "table" : "chart")}
              title={view === "chart" ? L.table : L.chart}
              aria-label={view === "chart" ? L.table : L.chart}
            >
              {view === "chart" ? <Table2 className="h-4 w-4" /> : <BarChart3 className="h-4 w-4" />}
            </Button>
          </>
        }
      />
      <div className={cn("flex-1 px-4 pb-3 pt-3 transition-opacity", q.isFetching && q.data && "opacity-70")}>
        <DataState
          loading={q.isLoading}
          error={q.error}
          empty={!!q.data && data.length === 0}
          emptyTitle={L.empty}
          onRetry={() => q.refetch()}
        >
          {view === "chart" ? (
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <LegendSwatch color={p.accent} label={L.events} shape="line" />
              </div>
              <div className="h-[84px]">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={data}
                    syncId="dash-timeline"
                    margin={{ top: 4, right: 4, bottom: 0, left: 0 }}
                  >
                    <CartesianGrid stroke={p.grid} vertical={false} />
                    <XAxis dataKey="t" hide />
                    <YAxis {...axisProps(p)} width={40} tickFormatter={formatCompact} allowDecimals={false} />
                    <Tooltip content={tooltip} cursor={{ stroke: p.muted, strokeWidth: 1 }} />
                    <Area
                      type="monotone"
                      dataKey="events"
                      stroke={p.accent}
                      strokeWidth={2}
                      fill={p.accent}
                      fillOpacity={0.1}
                      isAnimationActive={false}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
              <div className="flex flex-wrap items-center gap-3 pt-2">
                <LegendSwatch color={p.neutral} label={L.other} />
                <LegendSwatch color={p.ai} label={L.ai} />
              </div>
              <div className="h-[170px]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={data}
                    syncId="dash-timeline"
                    margin={{ top: 4, right: 4, bottom: 0, left: 0 }}
                  >
                    <CartesianGrid stroke={p.grid} vertical={false} />
                    <XAxis dataKey="t" {...axisProps(p)} tickFormatter={tick} minTickGap={28} />
                    <YAxis {...axisProps(p)} width={40} tickFormatter={formatCompact} allowDecimals={false} />
                    <Tooltip content={tooltip} cursor={{ fill: p.grid, fillOpacity: 0.4 }} />
                    <Bar
                      dataKey="other"
                      stackId="a"
                      fill={p.neutral}
                      maxBarSize={24}
                      stroke={p.surface}
                      strokeWidth={1}
                      isAnimationActive={false}
                    />
                    <Bar
                      dataKey="ai"
                      stackId="a"
                      fill={p.ai}
                      maxBarSize={24}
                      radius={[4, 4, 0, 0]}
                      stroke={p.surface}
                      strokeWidth={1}
                      isAnimationActive={false}
                    />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          ) : (
            <div className="max-h-[300px] overflow-y-auto">
              <Table>
                <THead>
                  <tr>
                    <TH>{L.time}</TH>
                    <TH className="text-right">{L.events}</TH>
                    <TH className="text-right">{L.alerts}</TH>
                    <TH className="text-right">{L.ai}</TH>
                  </tr>
                </THead>
                <TBody>
                  {[...data].reverse().map((d) => (
                    <TR key={d.t}>
                      <TD className="text-xs">{formatDateTime(new Date(d.t).toISOString())}</TD>
                      <TD className="text-right tabular-nums">{formatNumber(d.events)}</TD>
                      <TD className="text-right tabular-nums">{formatNumber(d.alerts)}</TD>
                      <TD className={cn("text-right tabular-nums", d.ai > 0 && "text-ai")}>
                        {formatNumber(d.ai)}
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            </div>
          )}
        </DataState>
      </div>
    </Card>
  );
}
