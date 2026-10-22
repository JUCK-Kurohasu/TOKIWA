/**
 * Minimal transient notice (toast) for mutation results, scoped to the component that renders `node`.
 *
 *   const { flash, node } = useFlash();
 *   flash("Saved");  flash(err.message, "danger");
 *   return <>{...}{node}</>;
 */
import { CircleAlert, CircleCheck, X } from "lucide-react";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import { cn } from "@/lib/utils";

type Tone = "success" | "danger";

export function useFlash(timeoutMs = 4500): {
  flash: (msg: ReactNode, tone?: Tone) => void;
  node: ReactNode;
} {
  const [msg, setMsg] = useState<{ id: number; text: ReactNode; tone: Tone } | null>(null);
  const flash = useCallback((text: ReactNode, tone: Tone = "success") => {
    setMsg({ id: Date.now(), text, tone });
  }, []);
  useEffect(() => {
    if (!msg) return;
    const t = setTimeout(() => setMsg(null), msg.tone === "danger" ? timeoutMs * 2 : timeoutMs);
    return () => clearTimeout(t);
  }, [msg, timeoutMs]);

  const node = msg ? (
    <div
      key={msg.id}
      role={msg.tone === "danger" ? "alert" : "status"}
      className={cn(
        "fixed bottom-4 right-4 z-[60] flex max-w-sm items-start gap-2 rounded-md border px-3 py-2 text-sm shadow-xl",
        msg.tone === "danger"
          ? "border-sev-critical/40 bg-surface text-sev-critical"
          : "border-accent/40 bg-surface text-fg",
      )}
    >
      {msg.tone === "danger" ? (
        <CircleAlert className="mt-0.5 h-4 w-4 shrink-0" />
      ) : (
        <CircleCheck className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
      )}
      <div className="min-w-0 flex-1 break-words">{msg.text}</div>
      <button
        type="button"
        onClick={() => setMsg(null)}
        className="rounded p-0.5 text-muted hover:text-fg"
        aria-label="dismiss"
      >
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  ) : null;

  return { flash, node };
}
