/** Inline feedback line after an action (success / info / error), announced via role=status. */
import { CheckCircle2, Info, XCircle } from "lucide-react";
import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";

export type NoticeTone = "success" | "info" | "error";

export function InlineNotice({
  tone = "success",
  children,
  className,
}: {
  tone?: NoticeTone;
  children: ReactNode;
  className?: string;
}) {
  const Icon = tone === "success" ? CheckCircle2 : tone === "error" ? XCircle : Info;
  return (
    <span
      role="status"
      className={cn(
        "inline-flex items-center gap-1.5 text-xs",
        tone === "success" && "text-accent",
        tone === "info" && "text-muted",
        tone === "error" && "text-sev-critical",
        className,
      )}
    >
      <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden />
      {children}
    </span>
  );
}

/** Short-lived notice state: `flash("saved")` shows for `ms` then clears. */
export function useFlash(
  ms = 4000,
): [{ tone: NoticeTone; text: string } | null, (text: string, tone?: NoticeTone) => void] {
  const [state, setState] = useState<{ tone: NoticeTone; text: string } | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  const flash = useCallback(
    (text: string, tone: NoticeTone = "success") => {
      clearTimeout(timer.current);
      setState({ text, tone });
      timer.current = setTimeout(() => setState(null), ms);
    },
    [ms],
  );
  return [state, flash];
}
