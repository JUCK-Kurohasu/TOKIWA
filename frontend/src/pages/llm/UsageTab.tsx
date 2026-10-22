/**
 * LLM usage: daily cost (with the daily budget as a reference line), daily tokens (input/output stacked),
 * and cost by purpose. Each chart has one y-scale; a table view gives the exact numbers.
 *
 * Token series colours were checked with the dataviz palette validator (light #2a78d6/#007b43,
 * dark #3987e5/#199e70: lightness band, chroma, CVD and contrast all pass). Identity is also given by the legend.
 */
import { useQuery } from "@tanstack/react-query";
import { BarChart3, Table2 } from "lucide-react";
import { type ReactNode, useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  LabelList,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "@/api/client";
import type { LLMConfig, LLMUsageResponse, PurposeUsage } from "@/api/types-intel";
import { KpiCard } from "@/components/common";
import { ApiErrorState, LoadingRows } from "@/components/common/QueryView";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  Select,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/ui";
import { formatNumber, formatUsd } from "@/lib/format";
import { useLang, useLocal } from "@/lib/i18n";
import { LLM_CONFIG_KEY } from "./ConfigTab";

const strings = {
  ja: {
    period: "期間",
    days: "日間",
    totalCost: "期間の費用",
    calls: "呼び出し回数",
    tokens: "トークン（入力 / 出力）",
    avg: "1 日平均",
    dailyCost: "日別費用",
    dailyCostDesc: "破線は日次予算",
    budget: "予算",
    dailyTokens: "日別トークン",
    input: "入力",
    output: "出力",
    byPurpose: "目的別の費用",
    byPurposeDesc: "期間合計（トリアージ・コパイロット・アドバイザリなど）",
    table: "表で表示",
    chart: "グラフで表示",
    date: "日付",
    cost: "費用",
    empty: "この期間の LLM 利用はありません",
    purpose: "目的",
    noPurpose: "目的別の内訳はありません",
  },
  en: {
    period: "Period",
    days: "days",
    totalCost: "Cost (period)",
    calls: "Calls",
    tokens: "Tokens (in / out)",
    avg: "Daily average",
    dailyCost: "Daily cost",
    dailyCostDesc: "Dashed line = daily budget",
    budget: "Budget",
    dailyTokens: "Daily tokens",
    input: "Input",
    output: "Output",
    byPurpose: "Cost by purpose",
    byPurposeDesc: "Period total (triage, copilot, advisory …)",
    table: "Show table",
    chart: "Show charts",
    date: "Date",
    cost: "Cost",
    empty: "No LLM usage in this period",
    purpose: "Purpose",
    noPurpose: "No per-purpose breakdown",
  },
};

const purposeLabels: Record<string, { ja: string; en: string }> = {
  triage: { ja: "トリアージ", en: "Triage" },
  incident: { ja: "インシデント", en: "Incident" },
  copilot: { ja: "コパイロット", en: "Copilot" },
  advisory: { ja: "アドバイザリ", en: "Advisory" },
  research: { ja: "Web リサーチ", en: "Research" },
  rule: { ja: "ルール", en: "Rule" },
  classify: { ja: "分類", en: "Classify" },
  eval: { ja: "評価", en: "Eval" },
  test: { ja: "テスト", en: "Test" },
};

function compactTokens(v: number): string {
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`;
  if (v >= 1_000) return `${(v / 1_000).toFixed(v >= 10_000 ? 0 : 1)}k`;
  return String(v);
}

function shortDate(d: string): string {
  const m = /^\d{4}-(\d{2})-(\d{2})/.exec(d);
  return m ? `${Number(m[1])}/${Number(m[2])}` : d;
}

/** Normalise a by_purpose value: number = USD cost (TODO(verify) against routes/llm.py). */
function purposeCost(v: PurposeUsage): { cost: number; calls: number | null } {
  if (typeof v === "number") return { cost: v, calls: null };
  return { cost: v.cost_usd ?? 0, calls: v.calls ?? null };
}

const axisTick = { fill: "var(--color-muted)", fontSize: 11 };

interface TipEntry {
  dataKey?: unknown;
  name?: unknown;
  value?: unknown;
  color?: string;
}

function ChartTooltip({
  active,
  payload,
  label,
  format,
  title,
}: {
  active?: boolean;
  payload?: readonly TipEntry[];
  label?: string | number;
  format: (v: number) => string;
  title?: (l: string) => ReactNode;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-md border border-line bg-surface px-3 py-2 text-xs shadow-lg">
      <div className="mb-1 font-medium text-fg">{title ? title(String(label ?? "")) : label}</div>
      {payload.map((p) => (
        <div key={String(p.dataKey)} className="flex items-center justify-between gap-4">
          <span className="flex items-center gap-1.5 text-muted">
            <span className="inline-block h-2 w-2 rounded-sm" style={{ background: p.color }} aria-hidden />
            {String(p.name ?? "")}
          </span>
          <span className="tabular-nums text-fg">{format(Number(p.value ?? 0))}</span>
        </div>
      ))}
    </div>
  );
}

function LegendItem({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted">
      <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: color }} aria-hidden />
      {label}
    </span>
  );
}

export function UsageTab() {
  const L = useLocal(strings);
  const { lang } = useLang();
  const [days, setDays] = useState(14);
  const [showTable, setShowTable] = useState(false);

  const usage = useQuery({
    queryKey: ["llm", "usage", days],
    queryFn: () => api.get<LLMUsageResponse>("/llm/usage", { days }),
  });
  const config = useQuery({
    queryKey: LLM_CONFIG_KEY,
    queryFn: () => api.get<LLMConfig>("/llm/config"),
    retry: false,
  });
  const budget = config.data?.daily_budget_usd ?? null;

  const rows = useMemo(
    () =>
      [...(usage.data?.days ?? [])]
        .sort((a, b) => a.date.localeCompare(b.date))
        .map((d) => ({ ...d, label: shortDate(d.date) })),
    [usage.data],
  );
  const totals = useMemo(
    () =>
      rows.reduce(
        (acc, d) => ({
          cost: acc.cost + (d.cost_usd ?? 0),
          calls: acc.calls + (d.calls ?? 0),
          input: acc.input + (d.input_tokens ?? 0),
          output: acc.output + (d.output_tokens ?? 0),
        }),
        { cost: 0, calls: 0, input: 0, output: 0 },
      ),
    [rows],
  );
  const purposes = useMemo(() => {
    const agg = new Map<string, { cost: number; calls: number | null }>();
    for (const d of rows) {
      for (const [k, v] of Object.entries(d.by_purpose ?? {})) {
        const { cost, calls } = purposeCost(v);
        const prev = agg.get(k) ?? { cost: 0, calls: null };
        agg.set(k, { cost: prev.cost + cost, calls: calls == null ? prev.calls : (prev.calls ?? 0) + calls });
      }
    }
    return [...agg.entries()]
      .map(([purpose, v]) => ({ purpose, name: purposeLabels[purpose]?.[lang] ?? purpose, ...v }))
      .sort((a, b) => b.cost - a.cost);
  }, [rows, lang]);

  const header = (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <Select aria-label={L.period} value={String(days)} onChange={(e) => setDays(Number(e.target.value))}>
        {[7, 14, 30, 90].map((d) => (
          <option key={d} value={d}>
            {d} {L.days}
          </option>
        ))}
      </Select>
      <Button variant="outline" size="sm" onClick={() => setShowTable((v) => !v)} aria-pressed={showTable}>
        {showTable ? (
          <BarChart3 className="h-3.5 w-3.5" aria-hidden />
        ) : (
          <Table2 className="h-3.5 w-3.5" aria-hidden />
        )}
        {showTable ? L.chart : L.table}
      </Button>
    </div>
  );

  if (usage.isLoading) return <LoadingRows rows={6} />;
  if (usage.error) return <ApiErrorState error={usage.error} />;

  const hasUsage = rows.some((d) => d.calls > 0 || d.cost_usd > 0);

  return (
    <div className="space-y-4">
      {header}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard label={L.totalCost} value={formatUsd(totals.cost)} tone="ai" />
        <KpiCard label={L.calls} value={formatNumber(totals.calls)} />
        <KpiCard
          label={L.tokens}
          value={
            <span className="text-xl">
              {compactTokens(totals.input)} <span className="text-muted">/</span>{" "}
              {compactTokens(totals.output)}
            </span>
          }
        />
        <KpiCard
          label={L.avg}
          value={formatUsd(rows.length ? totals.cost / rows.length : 0)}
          hint={budget != null ? `${L.budget} ${formatUsd(budget)}` : undefined}
        />
      </div>

      {!hasUsage ? (
        <Card>
          <EmptyState title={L.empty} icon={<BarChart3 className="h-6 w-6" />} />
        </Card>
      ) : showTable ? (
        <Card>
          <Table>
            <THead>
              <tr>
                <TH>{L.date}</TH>
                <TH className="text-right">{L.calls}</TH>
                <TH className="text-right">{L.input}</TH>
                <TH className="text-right">{L.output}</TH>
                <TH className="text-right">{L.cost}</TH>
              </tr>
            </THead>
            <TBody>
              {rows.map((d) => (
                <TR key={d.date}>
                  <TD className="font-mono text-xs">{d.date}</TD>
                  <TD className="text-right tabular-nums">{formatNumber(d.calls)}</TD>
                  <TD className="text-right tabular-nums">{formatNumber(d.input_tokens)}</TD>
                  <TD className="text-right tabular-nums">{formatNumber(d.output_tokens)}</TD>
                  <TD className="text-right tabular-nums">{formatUsd(d.cost_usd)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
          {purposes.length > 0 && (
            <Table className="border-t border-line">
              <THead>
                <tr>
                  <TH>{L.purpose}</TH>
                  <TH className="text-right">{L.calls}</TH>
                  <TH className="text-right">{L.cost}</TH>
                </tr>
              </THead>
              <TBody>
                {purposes.map((p) => (
                  <TR key={p.purpose}>
                    <TD>{p.name}</TD>
                    <TD className="text-right tabular-nums">
                      {p.calls == null ? "-" : formatNumber(p.calls)}
                    </TD>
                    <TD className="text-right tabular-nums">{formatUsd(p.cost)}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </Card>
      ) : (
        <div className="grid gap-4 xl:grid-cols-2 [--viz-in:#2a78d6] [--viz-out:#007b43] dark:[--viz-in:#3987e5] dark:[--viz-out:#199e70]">
          <Card>
            <CardHeader title={L.dailyCost} description={budget != null ? L.dailyCostDesc : undefined} />
            <CardBody className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
                  <CartesianGrid vertical={false} stroke="var(--color-line)" strokeDasharray="3 3" />
                  <XAxis
                    dataKey="label"
                    tick={axisTick}
                    tickLine={false}
                    axisLine={{ stroke: "var(--color-line)" }}
                  />
                  <YAxis
                    tick={axisTick}
                    tickLine={false}
                    axisLine={false}
                    width={52}
                    tickFormatter={(v: number) => `$${v < 1 ? v.toFixed(2) : v.toFixed(0)}`}
                    domain={[0, (max: number) => Math.max(max, budget ?? 0) * 1.1 || 1]}
                  />
                  <Tooltip
                    cursor={{ fill: "var(--color-surface-2)" }}
                    content={(p) => (
                      <ChartTooltip
                        active={p.active}
                        payload={p.payload}
                        label={p.label}
                        format={formatUsd}
                      />
                    )}
                  />
                  {budget != null && budget > 0 && (
                    <ReferenceLine
                      y={budget}
                      stroke="var(--color-sev-high)"
                      strokeDasharray="4 4"
                      label={{
                        value: L.budget,
                        position: "insideTopRight",
                        fill: "var(--color-muted)",
                        fontSize: 11,
                      }}
                    />
                  )}
                  <Bar
                    dataKey="cost_usd"
                    name={L.cost}
                    fill="var(--color-accent)"
                    radius={[4, 4, 0, 0]}
                    maxBarSize={28}
                  />
                </BarChart>
              </ResponsiveContainer>
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              title={L.dailyTokens}
              actions={
                <span className="flex gap-3">
                  <LegendItem color="var(--viz-in)" label={L.input} />
                  <LegendItem color="var(--viz-out)" label={L.output} />
                </span>
              }
            />
            <CardBody className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
                  <CartesianGrid vertical={false} stroke="var(--color-line)" strokeDasharray="3 3" />
                  <XAxis
                    dataKey="label"
                    tick={axisTick}
                    tickLine={false}
                    axisLine={{ stroke: "var(--color-line)" }}
                  />
                  <YAxis
                    tick={axisTick}
                    tickLine={false}
                    axisLine={false}
                    width={52}
                    tickFormatter={compactTokens}
                  />
                  <Tooltip
                    cursor={{ fill: "var(--color-surface-2)" }}
                    content={(p) => (
                      <ChartTooltip
                        active={p.active}
                        payload={p.payload}
                        label={p.label}
                        format={(v) => formatNumber(v)}
                      />
                    )}
                  />
                  <Bar
                    dataKey="input_tokens"
                    name={L.input}
                    stackId="t"
                    fill="var(--viz-in)"
                    stroke="var(--color-surface)"
                    strokeWidth={1}
                    maxBarSize={28}
                  />
                  <Bar
                    dataKey="output_tokens"
                    name={L.output}
                    stackId="t"
                    fill="var(--viz-out)"
                    stroke="var(--color-surface)"
                    strokeWidth={1}
                    radius={[4, 4, 0, 0]}
                    maxBarSize={28}
                  />
                </BarChart>
              </ResponsiveContainer>
            </CardBody>
          </Card>

          <Card className="xl:col-span-2">
            <CardHeader title={L.byPurpose} description={L.byPurposeDesc} />
            <CardBody style={{ height: Math.max(120, purposes.length * 36 + 24) }}>
              {purposes.length === 0 ? (
                <EmptyState title={L.noPurpose} />
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={purposes}
                    layout="vertical"
                    margin={{ top: 0, right: 72, bottom: 0, left: 8 }}
                  >
                    <XAxis type="number" hide />
                    <YAxis
                      type="category"
                      dataKey="name"
                      tick={{ ...axisTick, fill: "var(--color-fg)" }}
                      tickLine={false}
                      axisLine={false}
                      width={110}
                    />
                    <Tooltip
                      cursor={{ fill: "var(--color-surface-2)" }}
                      content={(p) => (
                        <ChartTooltip
                          active={p.active}
                          payload={p.payload}
                          label={p.label}
                          format={formatUsd}
                        />
                      )}
                    />
                    <Bar
                      dataKey="cost"
                      name={L.cost}
                      fill="var(--color-ai)"
                      radius={[0, 4, 4, 0]}
                      maxBarSize={20}
                    >
                      <LabelList
                        dataKey="cost"
                        position="right"
                        fill="var(--color-muted)"
                        fontSize={11}
                        formatter={(v: unknown) => formatUsd(Number(v))}
                      />
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </CardBody>
          </Card>
        </div>
      )}
    </div>
  );
}
