/** Live-stream connection indicator (dot + label; never colour alone). */
import type { LiveStatus } from "@/hooks/useLiveStream";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export function LiveDot({ status, className }: { status: LiveStatus; className?: string }) {
  const L = useLocal({
    ja: { open: "ライブ", connecting: "接続中", reconnecting: "再接続中", idle: "停止" },
    en: { open: "Live", connecting: "Connecting", reconnecting: "Reconnecting", idle: "Paused" },
  });
  const dot = {
    open: "bg-accent",
    connecting: "bg-sev-medium",
    reconnecting: "bg-sev-medium",
    idle: "bg-sev-info",
  }[status];
  return (
    <span
      className={cn("inline-flex items-center gap-1.5 text-xs text-muted", className)}
      role="status"
      aria-live="polite"
    >
      <span className="relative inline-flex h-2 w-2">
        {status === "open" && (
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent opacity-50 motion-reduce:hidden" />
        )}
        <span className={cn("relative inline-flex h-2 w-2 rounded-full", dot)} />
      </span>
      {L[status]}
    </span>
  );
}
