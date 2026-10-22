/**
 * "Thinking rhythm" of a session:
 *  - scatter of inter-arrival gap (y, log scale by default) over time (x), marker colour + shape by HTTP
 *    status class, with shaded reference bands for bursts and model-inference pauses;
 *  - log-binned histogram of gaps, where the burst/think bimodality of LLM agents shows up as two humps.
 */
import { useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ReferenceArea,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from "recharts";
import {
  axisProps,
  ChartTooltipBox,
  LegendSwatch,
  TooltipRow,
  useChartPalette,
} from "@/components/common/ChartKit";
import { formatClock, formatMs, formatTick } from "@/components/common/numfmt";
import { Card, CardHeader, EmptyState } from "@/components/ui";
import { formatNumber, pct } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { BURST_MAX_MS, gapHistogram, type RhythmPoint, THINK_MAX_MS, THINK_MIN_MS } from "./rhythm";

const strings = {
  ja: {
    title: "到着間隔のリズム",
    desc: "x = 時刻、y = 直前リクエストからの間隔。AI エージェントは「短いバースト → 推論待ちの沈黙」を繰り返す傾向があります（仮説）。",
    log: "対数",
    linear: "線形",
    scale: "縦軸",
    ok: "2xx / 3xx",
    client: "4xx",
    server: "5xx",
    none: "ステータスなし",
    think: `推論待ち帯（目安 ${THINK_MIN_MS / 1000}–${THINK_MAX_MS / 1000}s）`,
    burst: `バースト帯（≤${BURST_MAX_MS}ms）`,
    gap: "間隔",
    status: "ステータス",
    path: "パス",
    histTitle: "間隔の分布",
    histDesc: "対数ビン。2 つの山（バーストと推論待ち）があれば AI エージェント的なリズムです。",
    requests: "件数",
    share: "割合",
    empty: "リズムを描くには 2 件以上のリクエストが必要です",
    thinkZone: "推論待ち帯",
    otherZone: "その他",
  },
  en: {
    title: "Inter-arrival rhythm",
    desc: "x = time, y = gap since the previous request. LLM agents tend to alternate short bursts with silent model-inference pauses (hypothesis).",
    log: "Log",
    linear: "Linear",
    scale: "Y scale",
    ok: "2xx / 3xx",
    client: "4xx",
    server: "5xx",
    none: "No status",
    think: `Inference pause band (≈${THINK_MIN_MS / 1000}–${THINK_MAX_MS / 1000}s)`,
    burst: `Burst band (≤${BURST_MAX_MS}ms)`,
    gap: "Gap",
    status: "Status",
    path: "Path",
    histTitle: "Gap distribution",
    histDesc: "Log-spaced bins. Two humps (bursts + inference pauses) indicate an agent-like rhythm.",
    requests: "Requests",
    share: "Share",
    empty: "At least two requests are needed to draw the rhythm",
    thinkZone: "Inference pause band",
    otherZone: "Other",
  },
};

interface ScatterDatum extends RhythmPoint {
  y: number;
}

export function RhythmScatter({ points }: { points: RhythmPoint[] }) {
  const L = useLocal(strings);
  const p = useChartPalette();
  const [log, setLog] = useState(true);

  const data: ScatterDatum[] = useMemo(
    () => points.filter((pt) => pt.gap != null).map((pt) => ({ ...pt, y: Math.max(1, pt.gap ?? 1) })),
    [points],
  );
  const groups = useMemo(
    () => ({
      ok: data.filter((d) => d.cls === "ok" || d.cls === "redirect"),
      client: data.filter((d) => d.cls === "client"),
      server: data.filter((d) => d.cls === "server"),
      none: data.filter((d) => d.cls === "none"),
    }),
    [data],
  );
  const maxGap = Math.max(1000, ...data.map((d) => d.y));
  const span = data.length > 1 ? data[data.length - 1].t - data[0].t : 0;
  const logTicks = [1, 10, 100, 1_000, 10_000, 60_000, 600_000].filter((t) => t <= maxGap * 1.5);

  const tooltip = ({
    active,
    payload,
  }: {
    active?: boolean;
    payload?: readonly { payload?: ScatterDatum }[];
  }) => {
    const d = payload?.[0]?.payload;
    if (!active || !d) return null;
    return (
      <ChartTooltipBox title={`#${d.idx + 1} · ${formatClock(d.t)}`}>
        <TooltipRow label={L.gap} value={formatMs(d.gap)} />
        <TooltipRow label={L.status} value={d.status ?? "-"} />
        {d.path && <div className="mt-1 max-w-[280px] truncate font-mono text-[11px] text-fg">{d.path}</div>}
      </ChartTooltipBox>
    );
  };

  return (
    <Card>
      <CardHeader
        title={L.title}
        description={L.desc}
        actions={
          <div className="flex rounded-md border border-line p-0.5" title={L.scale}>
            {[true, false].map((v) => (
              <button
                key={String(v)}
                type="button"
                aria-pressed={log === v}
                onClick={() => setLog(v)}
                className={cn(
                  "rounded px-2 py-0.5 text-xs transition-colors",
                  log === v ? "bg-accent-soft text-accent" : "text-muted hover:text-fg",
                )}
              >
                {v ? L.log : L.linear}
              </button>
            ))}
          </div>
        }
      />
      <div className="px-4 pb-3 pt-3">
        {data.length < 1 ? (
          <EmptyState title={L.empty} />
        ) : (
          <>
            <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1">
              <LegendSwatch color={p.ok} label={L.ok} shape="circle" />
              <LegendSwatch color={p.warn} label={L.client} shape="triangle" />
              <LegendSwatch color={p.danger} label={L.server} shape="diamond" />
              {groups.none.length > 0 && <LegendSwatch color={p.muted} label={L.none} shape="circle" />}
              <span className="mx-1 hidden h-3 w-px bg-line sm:inline-block" />
              <LegendSwatch color={p.ai} label={L.think} shape="band" />
              <LegendSwatch color={p.muted} label={L.burst} shape="band" />
            </div>
            <div className="h-[280px]">
              <ResponsiveContainer width="100%" height="100%">
                <ScatterChart margin={{ top: 8, right: 12, bottom: 0, left: 4 }}>
                  <CartesianGrid stroke={p.grid} />
                  <XAxis
                    type="number"
                    dataKey="t"
                    domain={["dataMin", "dataMax"]}
                    {...axisProps(p)}
                    tickFormatter={(v: number) => (span < 3600_000 ? formatClock(v) : formatTick(v, span))}
                    minTickGap={40}
                    name="time"
                  />
                  <YAxis
                    type="number"
                    dataKey="y"
                    {...axisProps(p)}
                    width={56}
                    scale={log ? "log" : "linear"}
                    domain={log ? [1, maxGap * 1.5] : [0, "auto"]}
                    ticks={log ? logTicks : undefined}
                    allowDataOverflow
                    tickFormatter={(v: number) => formatMs(v)}
                    name="gap"
                  />
                  <ZAxis range={[56, 56]} />
                  <ReferenceArea
                    y1={log ? 1 : 0}
                    y2={BURST_MAX_MS}
                    fill={p.muted}
                    fillOpacity={0.08}
                    stroke="none"
                    ifOverflow="hidden"
                  />
                  <ReferenceArea
                    y1={THINK_MIN_MS}
                    y2={THINK_MAX_MS}
                    fill={p.ai}
                    fillOpacity={0.09}
                    stroke="none"
                    ifOverflow="hidden"
                  />
                  <Tooltip content={tooltip} cursor={{ stroke: p.muted, strokeWidth: 1 }} />
                  <Scatter data={groups.ok} fill={p.ok} shape="circle" isAnimationActive={false} />
                  <Scatter data={groups.client} fill={p.warn} shape="triangle" isAnimationActive={false} />
                  <Scatter data={groups.server} fill={p.danger} shape="diamond" isAnimationActive={false} />
                  <Scatter data={groups.none} fill={p.muted} shape="circle" isAnimationActive={false} />
                </ScatterChart>
              </ResponsiveContainer>
            </div>
          </>
        )}
      </div>
    </Card>
  );
}

export function GapHistogram({ points }: { points: RhythmPoint[] }) {
  const L = useLocal(strings);
  const p = useChartPalette();
  const bins = useMemo(() => gapHistogram(points), [points]);
  const total = bins.reduce((s, b) => s + b.count, 0);

  return (
    <Card>
      <CardHeader title={L.histTitle} description={L.histDesc} />
      <div className="px-4 pb-3 pt-3">
        {total === 0 ? (
          <EmptyState title={L.empty} />
        ) : (
          <>
            <div className="mb-2 flex flex-wrap gap-x-4 gap-y-1">
              <LegendSwatch color={p.ai} label={L.thinkZone} />
              <LegendSwatch color={p.neutral} label={L.otherZone} />
            </div>
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={bins} margin={{ top: 8, right: 4, bottom: 0, left: 0 }}>
                  <CartesianGrid stroke={p.grid} vertical={false} />
                  <XAxis
                    dataKey="label"
                    {...axisProps(p)}
                    interval={0}
                    angle={-35}
                    textAnchor="end"
                    height={48}
                  />
                  <YAxis {...axisProps(p)} width={36} allowDecimals={false} />
                  <Tooltip
                    cursor={{ fill: p.grid, fillOpacity: 0.4 }}
                    content={({ active, payload }) => {
                      const b = payload?.[0]?.payload as (typeof bins)[number] | undefined;
                      if (!active || !b) return null;
                      return (
                        <ChartTooltipBox title={b.label}>
                          <TooltipRow label={L.requests} value={formatNumber(b.count)} />
                          <TooltipRow label={L.share} value={pct(total ? b.count / total : 0)} />
                        </ChartTooltipBox>
                      );
                    }}
                  />
                  <Bar dataKey="count" maxBarSize={24} radius={[4, 4, 0, 0]} isAnimationActive={false}>
                    {bins.map((b) => (
                      <Cell key={b.label} fill={b.zone === "think" ? p.ai : p.neutral} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </>
        )}
      </div>
    </Card>
  );
}
