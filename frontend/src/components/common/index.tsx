/** Domain-specific shared components (severity, status, AI score, JSON viewer, KPI tile, page header). */
import type { ReactNode } from "react";
import type { ActorType, Severity } from "@/api/types";
import { useLang, useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const sevClasses: Record<Severity, string> = {
  info: "bg-sev-info/15 text-sev-info border-sev-info/30",
  low: "bg-sev-low/15 text-sev-low border-sev-low/30",
  medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
  high: "bg-sev-high/15 text-sev-high border-sev-high/30",
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/40",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const t = useT();
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 text-[11px] font-semibold uppercase leading-none",
        sevClasses[severity],
        className,
      )}
    >
      {t(`severity.${severity}`)}
    </span>
  );
}

export function SeverityDot({ severity }: { severity: Severity }) {
  const color: Record<Severity, string> = {
    info: "bg-sev-info",
    low: "bg-sev-low",
    medium: "bg-sev-medium",
    high: "bg-sev-high",
    critical: "bg-sev-critical",
  };
  return <span className={cn("inline-block h-2 w-2 rounded-full", color[severity])} />;
}

const actorLabels: Record<ActorType, { ja: string; en: string }> = {
  human: { ja: "人間", en: "Human" },
  automated_scanner: { ja: "スキャナ", en: "Scanner" },
  ai_agent: { ja: "AIエージェント", en: "AI agent" },
  benign: { ja: "正常", en: "Benign" },
  unknown: { ja: "不明", en: "Unknown" },
};

export function ActorBadge({ actor }: { actor: ActorType }) {
  const { lang } = useLang();
  const tone =
    actor === "ai_agent"
      ? "bg-ai/15 text-ai border-ai/40"
      : actor === "automated_scanner"
        ? "bg-sev-high/10 text-sev-high border-sev-high/30"
        : actor === "benign"
          ? "bg-accent-soft text-accent border-accent/30"
          : "bg-surface-2 text-muted border-line";
  return (
    <span
      className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-[11px] font-medium", tone)}
    >
      {actorLabels[actor][lang]}
    </span>
  );
}

/** 0..1 likelihood that the actor is an autonomous AI agent, rendered as a small meter. */
export function AiScore({ score, className }: { score: number | null | undefined; className?: string }) {
  if (score == null) return <span className="text-muted">-</span>;
  const pct = Math.round(score * 100);
  const color = score >= 0.7 ? "bg-ai" : score >= 0.4 ? "bg-sev-medium" : "bg-sev-info";
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs tabular-nums", className)} title="AI score">
      <span className="relative h-1.5 w-12 overflow-hidden rounded-full bg-surface-2">
        <span className={cn("absolute inset-y-0 left-0", color)} style={{ width: `${pct}%` }} />
      </span>
      {pct}%
    </span>
  );
}

export function JsonView({ value, className }: { value: unknown; className?: string }) {
  return (
    <pre
      className={cn(
        "max-h-[480px] overflow-auto rounded-md border border-line bg-bg p-3 font-mono text-xs leading-relaxed",
        className,
      )}
    >
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function KpiCard({
  label,
  value,
  hint,
  icon,
  tone = "neutral",
}: {
  label: ReactNode;
  value: ReactNode;
  hint?: ReactNode;
  icon?: ReactNode;
  tone?: "neutral" | "accent" | "danger" | "ai";
}) {
  const toneClass = {
    neutral: "text-fg",
    accent: "text-accent",
    danger: "text-sev-critical",
    ai: "text-ai",
  }[tone];
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <div className="flex items-center justify-between text-xs text-muted">
        <span>{label}</span>
        {icon}
      </div>
      <div className={cn("mt-2 text-2xl font-semibold tabular-nums", toneClass)}>{value}</div>
      {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1 text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("font-mono text-xs", className)}>{children}</span>;
}
