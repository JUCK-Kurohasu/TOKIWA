/**
 * Compact event-volume histogram (GET /events/stats/timeline). Unfiltered by design — it gives context
 * for the selected period; clicking a bucket narrows the explorer to that bucket.
 */
import { useMemo } from "react";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { EventTimeline } from "@/api/types-core";
import { axisProps, ChartTooltipBox, TooltipRow, useChartPalette } from "@/components/common/ChartKit";
import { classifyError } from "@/components/common/DataState";
import { formatCompact, formatTick } from "@/components/common/numfmt";
import { Skeleton } from "@/components/ui";
import { useApiQuery } from "@/hooks/useApi";
import { formatDateTime, formatNumber } from "@/lib/format";
import { useLocal } from "@/lib/i18n";

interface Datum {
  t: number;
  total: number;
  byKind: Record<string, number>;
}

export function VolumeStrip({
  hours,
  bucketMinutes,
  onPick,
}: {
  hours: number;
  bucketMinutes: number;
  onPick: (from: number, to: number) => void;
}) {
  const L = useLocal({
    ja: {
      title: "取り込み量（全イベント・フィルタ非適用）",
      hint: "クリックでその時間帯に絞り込み",
      total: "合計",
    },
    en: {
      title: "Ingest volume (all events, unfiltered)",
      hint: "Click a bar to zoom into it",
      total: "Total",
    },
  });
  const p = useChartPalette();
  const q = useApiQuery<EventTimeline>(
    ["events", "timeline", hours, bucketMinutes],
    "/events/stats/timeline",
    { hours, bucket_minutes: bucketMinutes },
    { keepPrevious: true, refetchInterval: 60_000 },
  );
  const data: Datum[] = useMemo(
    () =>
      (q.data?.buckets ?? []).map((b) => ({
        t: Date.parse(b.ts),
        total: b.total ?? 0,
        byKind: b.by_kind ?? {},
      })),
    [q.data],
  );
  // The strip is auxiliary: hide it quietly when the endpoint is missing.
  if (q.error && classifyError(q.error) === "unavailable") return null;
  if (q.error) return null;
  const span = hours * 3600_000;

  return (
    <div className="rounded-lg border border-line bg-surface px-3 pb-1 pt-2">
      <div className="flex items-center justify-between text-[11px] text-muted">
        <span>{L.title}</span>
        <span className="hidden sm:inline">{L.hint}</span>
      </div>
      {q.isLoading ? (
        <Skeleton className="my-2 h-12 w-full" />
      ) : (
        <div className="h-[72px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={data}
              margin={{ top: 6, right: 0, bottom: 0, left: 0 }}
              onClick={(state) => {
                const idx = state?.activeTooltipIndex;
                const i = typeof idx === "number" ? idx : Number(idx);
                if (Number.isFinite(i) && data[i]) onPick(data[i].t, data[i].t + bucketMinutes * 60_000);
              }}
            >
              <XAxis
                dataKey="t"
                {...axisProps(p)}
                tickFormatter={(v: number) => formatTick(v, span)}
                minTickGap={40}
                height={18}
              />
              <YAxis
                {...axisProps(p)}
                width={36}
                tickFormatter={formatCompact}
                allowDecimals={false}
                tickCount={3}
              />
              <Tooltip
                cursor={{ fill: p.grid, fillOpacity: 0.5 }}
                content={({ active, payload }) => {
                  const d = payload?.[0]?.payload as Datum | undefined;
                  if (!active || !d) return null;
                  const kinds = Object.entries(d.byKind)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 6);
                  return (
                    <ChartTooltipBox title={formatDateTime(new Date(d.t).toISOString())}>
                      <TooltipRow color={p.accent} label={L.total} value={formatNumber(d.total)} />
                      {kinds.map(([k, n]) => (
                        <TooltipRow
                          key={k}
                          label={<span className="font-mono">{k}</span>}
                          value={formatNumber(n)}
                        />
                      ))}
                    </ChartTooltipBox>
                  );
                }}
              />
              <Bar
                dataKey="total"
                fill={p.accent}
                fillOpacity={0.75}
                maxBarSize={24}
                radius={[3, 3, 0, 0]}
                isAnimationActive={false}
                cursor="pointer"
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
