/**
 * Vulnerability-intel visual vocabulary: KEV (known exploited) is always red with a text label, EPSS is a bar plus
 * the numeric value, CVSS is a score with its severity band, advisory priority P1..P4. Colour never carries the
 * meaning alone.
 */
import { ExternalLink, Flame, Skull, Sparkles } from "lucide-react";
import type { ReactNode } from "react";
import type { Priority, Severity } from "@/api/types";
import { useLang } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export function KevBadge({ ransomware, className }: { ransomware?: boolean | null; className?: string }) {
  const { lang } = useLang();
  return (
    <span className={cn("inline-flex items-center gap-1", className)}>
      <span
        className="inline-flex items-center gap-1 rounded border border-sev-critical/50 bg-sev-critical/15 px-1.5 py-0.5 text-[11px] font-bold leading-none text-sev-critical"
        title={
          lang === "ja" ? "CISA KEV: 実際に悪用が確認された脆弱性" : "CISA KEV: known exploited vulnerability"
        }
      >
        <Flame className="h-3 w-3" aria-hidden />
        KEV
      </span>
      {ransomware ? (
        <span
          className="inline-flex items-center gap-1 rounded border border-sev-critical/40 px-1.5 py-0.5 text-[10px] font-medium leading-none text-sev-critical"
          title={lang === "ja" ? "ランサムウェアでの悪用が報告" : "Known ransomware campaign use"}
        >
          <Skull className="h-3 w-3" aria-hidden />
          {lang === "ja" ? "ランサム" : "Ransomware"}
        </span>
      ) : null}
    </span>
  );
}

function epssColor(v: number): string {
  if (v >= 0.5) return "bg-sev-critical";
  if (v >= 0.1) return "bg-sev-high";
  if (v >= 0.01) return "bg-sev-medium";
  return "bg-sev-info";
}

/** EPSS probability (0..1) as a bar with the percentage; percentile in the tooltip. */
export function EpssBar({
  epss,
  percentile,
  className,
}: {
  epss: number | null | undefined;
  percentile?: number | null;
  className?: string;
}) {
  const { lang } = useLang();
  if (epss == null) return <span className="text-xs text-muted">-</span>;
  const pctValue = Math.max(0, Math.min(1, epss)) * 100;
  const label =
    pctValue >= 10 ? pctValue.toFixed(0) : pctValue >= 1 ? pctValue.toFixed(1) : pctValue.toFixed(2);
  const title =
    percentile != null
      ? lang === "ja"
        ? `EPSS ${label}%（上位 ${(100 - percentile * 100).toFixed(1)}%）`
        : `EPSS ${label}% (top ${(100 - percentile * 100).toFixed(1)}%)`
      : `EPSS ${label}%`;
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs tabular-nums", className)} title={title}>
      <span className="relative h-1.5 w-14 overflow-hidden rounded-full bg-surface-2" aria-hidden>
        <span
          className={cn("absolute inset-y-0 left-0 rounded-full", epssColor(epss))}
          style={{ width: `${Math.max(2, pctValue)}%` }}
        />
      </span>
      {label}%
    </span>
  );
}

export function cvssSeverity(score: number | null | undefined): Severity {
  if (score == null) return "info";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

const sevText: Record<Severity, string> = {
  info: "text-sev-info border-sev-info/30 bg-sev-info/10",
  low: "text-sev-low border-sev-low/30 bg-sev-low/10",
  medium: "text-sev-medium border-sev-medium/30 bg-sev-medium/10",
  high: "text-sev-high border-sev-high/30 bg-sev-high/10",
  critical: "text-sev-critical border-sev-critical/40 bg-sev-critical/10",
};

export function CvssScore({ score, vector }: { score: number | null | undefined; vector?: string | null }) {
  if (score == null) return <span className="text-xs text-muted">-</span>;
  const sev = cvssSeverity(score);
  return (
    <span
      className={cn(
        "inline-flex min-w-[2.5rem] justify-center rounded border px-1.5 py-0.5 font-mono text-[11px] font-semibold tabular-nums",
        sevText[sev],
      )}
      title={vector ?? `CVSS ${score.toFixed(1)}`}
    >
      {score.toFixed(1)}
    </span>
  );
}

const priorityStyle: Record<Priority, string> = {
  P1: "bg-sev-critical/20 text-sev-critical border-sev-critical/50",
  P2: "bg-sev-high/15 text-sev-high border-sev-high/40",
  P3: "bg-sev-medium/15 text-sev-medium border-sev-medium/40",
  P4: "bg-surface-2 text-muted border-line",
};
const priorityHint = {
  ja: { P1: "即時対応", P2: "今週中", P3: "次回メンテ", P4: "情報" },
  en: { P1: "Act now", P2: "This week", P3: "Next window", P4: "Info" },
};

export function PriorityBadge({ priority, showHint }: { priority: Priority; showHint?: boolean }) {
  const { lang } = useLang();
  const hint = priorityHint[lang][priority] ?? "";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-bold leading-none",
        priorityStyle[priority] ?? priorityStyle.P4,
      )}
      title={hint}
    >
      {priority}
      {showHint && <span className="font-medium">{hint}</span>}
    </span>
  );
}

/** Only http(s) URLs are rendered as links; anything else (javascript:, data:) is shown as inert text. */
export function isSafeHttpUrl(url: string | null | undefined): url is string {
  return !!url && /^https?:\/\/[^\s]+$/i.test(url.trim());
}

export function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

export function SafeLink({
  href,
  children,
  className,
}: {
  href: string | null | undefined;
  children?: ReactNode;
  className?: string;
}) {
  if (!isSafeHttpUrl(href)) {
    return <span className={cn("break-all text-muted", className)}>{children ?? href ?? "-"}</span>;
  }
  return (
    <a
      href={href.trim()}
      target="_blank"
      rel="noopener noreferrer nofollow"
      className={cn("inline-flex items-center gap-1 break-all text-accent hover:underline", className)}
      onClick={(e) => e.stopPropagation()}
    >
      {children ?? href}
      <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
    </a>
  );
}

/** MITRE ATT&CK technique ids (T1190, T1059.001) linked to attack.mitre.org. */
export function MitreLinks({ ids, className }: { ids: string[]; className?: string }) {
  if (!ids.length) return <span className="text-xs text-muted">-</span>;
  return (
    <span className={cn("flex flex-wrap gap-1", className)}>
      {ids.map((raw) => {
        const id = raw.trim().toUpperCase();
        const m = /^(T\d{4})(?:\.(\d{3}))?$/.exec(id);
        const cls =
          "rounded border border-line bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] leading-none text-muted";
        if (!m) {
          return (
            <span key={raw} className={cls}>
              {raw}
            </span>
          );
        }
        const href = `https://attack.mitre.org/techniques/${m[1]}/${m[2] ? `${m[2]}/` : ""}`;
        return (
          <a
            key={raw}
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className={cn(cls, "hover:border-accent hover:text-accent")}
            onClick={(e) => e.stopPropagation()}
          >
            {id}
          </a>
        );
      })}
    </span>
  );
}

/** Small "AI generated" marker (purple = LLM output). */
export function AiGeneratedBadge({ className }: { className?: string }) {
  const { lang } = useLang();
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded border border-ai/30 bg-ai/10 px-1.5 py-0.5 text-[10px] font-medium leading-none text-ai",
        className,
      )}
    >
      <Sparkles className="h-3 w-3" aria-hidden />
      {lang === "ja" ? "AI生成" : "AI-generated"}
    </span>
  );
}
