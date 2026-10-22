/** Dashboard stat tiles and small inline meters. */
import { ArrowUpRight } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router";
import { SEVERITIES, type Severity } from "@/api/types";
import { SeverityDot } from "@/components/common";
import { Skeleton } from "@/components/ui";
import { formatNumber } from "@/lib/format";
import { useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export type TileTone = "neutral" | "accent" | "danger" | "warn" | "ai";

const toneText: Record<TileTone, string> = {
  neutral: "text-fg",
  accent: "text-accent",
  danger: "text-sev-critical",
  warn: "text-sev-medium",
  ai: "text-ai",
};

export function StatTile({
  label,
  value,
  hint,
  icon,
  tone = "neutral",
  to,
  loading,
  children,
  highlight,
}: {
  label: ReactNode;
  value: ReactNode;
  hint?: ReactNode;
  icon?: ReactNode;
  tone?: TileTone;
  to?: string;
  loading?: boolean;
  children?: ReactNode;
  /** Purple ring for AI-related tiles */
  highlight?: "ai";
}) {
  const body = (
    <>
      <div className="flex items-center justify-between gap-2 text-xs text-muted">
        <span className="truncate">{label}</span>
        <span className="flex items-center gap-1">
          {icon}
          {to && (
            <ArrowUpRight className="h-3.5 w-3.5 opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100" />
          )}
        </span>
      </div>
      {loading ? (
        <Skeleton className="mt-2 h-7 w-20" />
      ) : (
        <div className={cn("mt-1.5 text-2xl font-semibold leading-tight", toneText[tone])}>{value}</div>
      )}
      {hint && <div className="mt-1 truncate text-xs text-muted">{hint}</div>}
      {children && <div className="mt-2">{children}</div>}
    </>
  );
  const cls = cn(
    "group block rounded-lg border bg-surface p-3.5 transition-colors",
    highlight === "ai" ? "border-ai/35 bg-ai/[0.04]" : "border-line",
    to && "hover:border-accent/50 focus-visible:outline-2 focus-visible:outline-accent",
  );
  return to ? (
    <Link to={to} className={cls}>
      {body}
    </Link>
  ) : (
    <div className={cls}>{body}</div>
  );
}

const sevBg: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

/** Part-to-whole bar of alerts by severity with a labelled legend (never colour alone). */
export function SeverityBreakdown({ bySeverity }: { bySeverity: Partial<Record<Severity, number>> }) {
  const t = useT();
  const total = SEVERITIES.reduce((s, k) => s + (bySeverity[k] ?? 0), 0);
  return (
    <div className="space-y-1.5">
      <div className="flex h-1.5 w-full gap-[2px] overflow-hidden rounded-full bg-surface-2">
        {total > 0 &&
          SEVERITIES.map((s) => {
            const n = bySeverity[s] ?? 0;
            if (!n) return null;
            return (
              <span
                key={s}
                className={cn("h-full first:rounded-l-full last:rounded-r-full", sevBg[s])}
                style={{ width: `${(n / total) * 100}%` }}
                title={`${t(`severity.${s}`)}: ${n}`}
              />
            );
          })}
      </div>
      <div className="flex flex-wrap gap-x-2.5 gap-y-0.5 text-[11px] text-muted">
        {SEVERITIES.filter((s) => s !== "info").map((s) => (
          <span key={s} className="inline-flex items-center gap-1">
            <SeverityDot severity={s} />
            {t(`severity.${s}`)}
            <span className="tabular-nums text-fg">{formatNumber(bySeverity[s] ?? 0)}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/** Budget meter: accent -> warning -> danger as spend approaches the budget. */
export function BudgetMeter({ spent, budget }: { spent: number; budget: number }) {
  const ratio = budget > 0 ? spent / budget : 0;
  const fill = ratio >= 0.9 ? "bg-sev-critical" : ratio >= 0.7 ? "bg-sev-medium" : "bg-accent";
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
      <div className={cn("h-full rounded-full", fill)} style={{ width: `${Math.min(100, ratio * 100)}%` }} />
    </div>
  );
}

/** Thin proportional bar used inside table rows (single series => single colour). */
export function InlineBar({ value, max, className }: { value: number; max: number; className?: string }) {
  const pct = max > 0 ? Math.max(2, (value / max) * 100) : 0;
  return (
    <span className={cn("block h-1 w-full overflow-hidden rounded-full bg-surface-2", className)}>
      <span className="block h-full rounded-full bg-accent/70" style={{ width: `${pct}%` }} />
    </span>
  );
}
