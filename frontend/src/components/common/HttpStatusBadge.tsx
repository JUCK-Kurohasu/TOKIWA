/** HTTP status code chip coloured by class (2xx/3xx/4xx/5xx); the number is always visible. */
import { cn } from "@/lib/utils";
import { statusClass } from "./numfmt";

const tones = {
  ok: "text-accent border-accent/30 bg-accent-soft",
  redirect: "text-sev-low border-sev-low/30 bg-sev-low/10",
  client: "text-sev-medium border-sev-medium/30 bg-sev-medium/10",
  server: "text-sev-critical border-sev-critical/30 bg-sev-critical/10",
  none: "text-muted border-line bg-surface-2",
} as const;

export function HttpStatusBadge({
  status,
  className,
}: {
  status: number | null | undefined;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex min-w-[2.5rem] justify-center rounded border px-1 py-0.5 font-mono text-[11px] leading-none tabular-nums",
        tones[statusClass(status)],
        className,
      )}
    >
      {status ?? "—"}
    </span>
  );
}
