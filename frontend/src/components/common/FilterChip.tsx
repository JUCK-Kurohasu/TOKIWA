/** Toggle chip for boolean list filters (aria-pressed). */
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function FilterChip({
  pressed,
  onChange,
  children,
  tone = "accent",
}: {
  pressed: boolean;
  onChange: (next: boolean) => void;
  children: ReactNode;
  tone?: "accent" | "danger" | "ai";
}) {
  const on = {
    accent: "border-accent/50 bg-accent-soft text-accent",
    danger: "border-sev-critical/50 bg-sev-critical/15 text-sev-critical",
    ai: "border-ai/50 bg-ai/15 text-ai",
  }[tone];
  return (
    <button
      type="button"
      aria-pressed={pressed}
      onClick={() => onChange(!pressed)}
      className={cn(
        "inline-flex h-9 items-center gap-1.5 rounded-md border px-3 text-sm transition-colors",
        "focus-visible:outline-2 focus-visible:outline-accent",
        pressed ? on : "border-line text-muted hover:bg-surface-2 hover:text-fg",
      )}
    >
      {children}
    </button>
  );
}
