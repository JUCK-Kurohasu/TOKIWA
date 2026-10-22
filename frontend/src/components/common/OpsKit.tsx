/**
 * Small building blocks shared by the ops pages: status/category badges, pager, debounced filter input,
 * meters, metadata tiles, MITRE chips. Built on @/components/ui primitives and semantic color tokens.
 */
import { ArrowLeft, ChevronLeft, ChevronRight, ExternalLink, Loader2 } from "lucide-react";
import { type InputHTMLAttributes, type ReactNode, useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import type { AlertCategory, AlertStatus, IncidentStatus } from "@/api/types";
import { Badge, Button, Input, Skeleton } from "@/components/ui";
import { useLabel, useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import {
  AI_CATEGORIES,
  alertCategoryLabel,
  alertStatusLabel,
  fmt,
  incidentStatusLabel,
  labelOf,
  mitreUrl,
} from "./opsLabels";

type Tone = "neutral" | "accent" | "ai" | "warn" | "danger";

const alertStatusTone: Record<AlertStatus, Tone> = {
  new: "warn",
  triaging: "ai",
  triaged: "neutral",
  acknowledged: "neutral",
  resolved: "accent",
  false_positive: "neutral",
};

export function AlertStatusBadge({ status }: { status: AlertStatus }) {
  const label = useLabel();
  return (
    <Badge tone={alertStatusTone[status] ?? "neutral"}>
      {status === "triaging" && <Loader2 className="h-3 w-3 animate-spin" aria-hidden />}
      {label(labelOf(alertStatusLabel, status))}
    </Badge>
  );
}

const incidentStatusTone: Record<IncidentStatus, Tone> = {
  open: "danger",
  investigating: "warn",
  contained: "accent",
  resolved: "accent",
  false_positive: "neutral",
};

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  const label = useLabel();
  return (
    <Badge tone={incidentStatusTone[status] ?? "neutral"}>
      {label(labelOf(incidentStatusLabel, status))}
    </Badge>
  );
}

export function CategoryBadge({ category }: { category: AlertCategory | string }) {
  const label = useLabel();
  const ai = AI_CATEGORIES.has(category);
  return (
    <span className={cn("text-xs", ai ? "font-medium text-ai" : "text-muted")}>
      {label(labelOf(alertCategoryLabel, category))}
    </span>
  );
}

/** Horizontal 0..1 meter with a percentage label. */
export function Meter({
  value,
  tone = "accent",
  label,
  className,
}: {
  value: number | null | undefined;
  tone?: "accent" | "ai" | "warn";
  label?: ReactNode;
  className?: string;
}) {
  const pct = value == null ? null : Math.round(Math.min(1, Math.max(0, value)) * 100);
  const bar = { accent: "bg-accent", ai: "bg-ai", warn: "bg-sev-medium" }[tone];
  const text = { accent: "text-fg", ai: "text-ai", warn: "text-sev-medium" }[tone];
  return (
    <div className={cn("space-y-1", className)}>
      {label && (
        <div className="flex items-center justify-between text-xs">
          <span className="text-muted">{label}</span>
          <span className={cn("font-semibold tabular-nums", text)}>{pct == null ? "-" : `${pct}%`}</span>
        </div>
      )}
      {/* Decorative bar; the value is announced through the text label above (or the sr-only span). */}
      <div className="h-1.5 overflow-hidden rounded-full bg-surface-2" aria-hidden>
        <div className={cn("h-full rounded-full", bar)} style={{ width: `${pct ?? 0}%` }} />
      </div>
      {!label && <span className="sr-only">{pct == null ? "-" : `${pct}%`}</span>}
    </div>
  );
}

/** Compact label/value tile used in detail-page metadata strips. */
export function MetaItem({
  label,
  children,
  className,
}: {
  label: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("min-w-0 rounded-md border border-line bg-surface px-3 py-2", className)}>
      <div className="text-[11px] text-muted">{label}</div>
      <div className="mt-0.5 truncate text-sm">{children}</div>
    </div>
  );
}

export function MitreChips({ ids, empty = "-" }: { ids: string[]; empty?: ReactNode }) {
  if (!ids.length) return <span className="text-xs text-muted">{empty}</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {ids.map((id) => {
        const url = mitreUrl(id);
        return url ? (
          <a
            key={id}
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 rounded border border-line bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-fg hover:border-accent"
          >
            {id}
            <ExternalLink className="h-3 w-3 text-muted" aria-hidden />
          </a>
        ) : (
          <span
            key={id}
            className="rounded border border-line bg-surface-2 px-1.5 py-0.5 font-mono text-[11px]"
          >
            {id}
          </span>
        );
      })}
    </div>
  );
}

export function BackLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link to={to} className="mb-3 inline-flex items-center gap-1 text-xs text-muted hover:text-fg">
      <ArrowLeft className="h-3.5 w-3.5" aria-hidden />
      {children}
    </Link>
  );
}

export function SectionTitle({
  children,
  icon,
  extra,
}: {
  children: ReactNode;
  icon?: ReactNode;
  extra?: ReactNode;
}) {
  return (
    <div className="mb-2 flex items-center justify-between gap-2">
      <h4 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
        {icon}
        {children}
      </h4>
      {extra}
    </div>
  );
}

/** Input that commits its value after the user stops typing (filters synced to the URL). */
export function DebouncedInput({
  value,
  onCommit,
  delay = 350,
  ...props
}: Omit<InputHTMLAttributes<HTMLInputElement>, "value" | "onChange"> & {
  value: string;
  onCommit: (v: string) => void;
  delay?: number;
}) {
  const [local, setLocal] = useState(value);
  const commit = useRef(onCommit);
  commit.current = onCommit;
  const committed = useRef(value);

  // External changes (e.g. "clear filters") flow back into the field.
  useEffect(() => {
    committed.current = value;
    setLocal(value);
  }, [value]);

  useEffect(() => {
    if (local === committed.current) return;
    const t = setTimeout(() => {
      committed.current = local;
      commit.current(local);
    }, delay);
    return () => clearTimeout(t);
  }, [local, delay]);

  return <Input value={local} onChange={(e) => setLocal(e.target.value)} {...props} />;
}

export function Pager({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
}) {
  const L = useLocal({
    ja: { range: "{from}–{to} / 全 {total} 件", prev: "前へ", next: "次へ" },
    en: { range: "{from}–{to} of {total}", prev: "Previous", next: "Next" },
  });
  if (total <= 0) return null;
  const from = offset + 1;
  const to = Math.min(offset + limit, total);
  return (
    <div className="flex items-center justify-between gap-2 border-t border-line px-3 py-2 text-xs text-muted">
      <span className="tabular-nums">{fmt(L.range, { from, to, total })}</span>
      <div className="flex gap-1">
        <Button
          variant="ghost"
          size="sm"
          disabled={offset <= 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
          aria-label={L.prev}
        >
          <ChevronLeft className="h-4 w-4" aria-hidden />
          {L.prev}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={offset + limit >= total}
          onClick={() => onChange(offset + limit)}
          aria-label={L.next}
        >
          {L.next}
          <ChevronRight className="h-4 w-4" aria-hidden />
        </Button>
      </div>
    </div>
  );
}

export function TableSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div className="space-y-2 p-4">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-7 w-full" />
      ))}
    </div>
  );
}

/** Inline notice block (info / warning / ai). */
export function Notice({
  tone = "neutral",
  icon,
  title,
  children,
  className,
}: {
  tone?: "neutral" | "accent" | "ai" | "warn" | "danger";
  icon?: ReactNode;
  title?: ReactNode;
  children?: ReactNode;
  className?: string;
}) {
  const tones = {
    neutral: "border-line bg-surface-2 text-fg",
    accent: "border-accent/40 bg-accent-soft text-fg",
    ai: "border-ai/40 bg-ai/10 text-fg",
    warn: "border-sev-medium/40 bg-sev-medium/10 text-fg",
    danger: "border-sev-critical/40 bg-sev-critical/10 text-fg",
  };
  return (
    <div className={cn("flex gap-2.5 rounded-md border px-3 py-2.5 text-sm", tones[tone], className)}>
      {icon && <div className="mt-0.5 shrink-0">{icon}</div>}
      <div className="min-w-0 space-y-0.5">
        {title && <div className="font-medium">{title}</div>}
        {children && <div className="text-xs leading-relaxed text-muted">{children}</div>}
      </div>
    </div>
  );
}

/** Small "filter label + control" wrapper used in filter bars. */
export function FilterField({
  label,
  htmlFor,
  children,
}: {
  label: ReactNode;
  htmlFor: string;
  children: ReactNode;
}) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <label htmlFor={htmlFor} className="text-[11px] font-medium text-muted">
        {label}
      </label>
      {children}
    </div>
  );
}
