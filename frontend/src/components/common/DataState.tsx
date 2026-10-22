/**
 * Loading / error / empty handling for API-backed panels.
 *
 * A 404 from the API is shown as a calm "not available yet" notice rather than a red error: modules are
 * built in parallel and an endpoint may simply not exist on this server build yet.
 */
import { Lock, PlugZap, RotateCw, ServerOff, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { ApiError } from "@/api/client";
import { Button, EmptyState, Skeleton } from "@/components/ui";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const strings = {
  ja: {
    unavailable: "この機能の API はまだ利用できません",
    unavailableHint: "サーバー側で該当モジュールが未実装か無効です (404)",
    forbidden: "権限がありません",
    forbiddenHint: "この操作には上位のロールが必要です (403)",
    offline: "サーバーに接続できません",
    offlineHint: "バックエンドが起動しているか確認してください",
    error: "読み込みに失敗しました",
    retry: "再試行",
    empty: "データがありません",
  },
  en: {
    unavailable: "This API is not available yet",
    unavailableHint: "The backend module is not implemented or disabled (404)",
    forbidden: "Permission denied",
    forbiddenHint: "A higher role is required (403)",
    offline: "Cannot reach the server",
    offlineHint: "Check that the backend is running",
    error: "Failed to load",
    retry: "Retry",
    empty: "No data",
  },
};

type ErrorKind = "unavailable" | "forbidden" | "offline" | "error";

export function classifyError(error: unknown): ErrorKind {
  if (error instanceof ApiError) {
    if (error.status === 404 || error.status === 405 || error.status === 501) return "unavailable";
    if (error.status === 403) return "forbidden";
    if (error.status === 502 || error.status === 503 || error.status === 504) return "offline";
    return "error";
  }
  if (error instanceof TypeError) return "offline"; // fetch network failure
  return "error";
}

export function ApiErrorNotice({
  error,
  onRetry,
  compact,
  className,
}: {
  error: unknown;
  onRetry?: () => void;
  compact?: boolean;
  className?: string;
}) {
  const L = useLocal(strings);
  const kind = classifyError(error);
  const detail = error instanceof Error ? error.message : String(error);
  const icon = {
    unavailable: <PlugZap className="h-5 w-5" />,
    forbidden: <Lock className="h-5 w-5" />,
    offline: <ServerOff className="h-5 w-5" />,
    error: <TriangleAlert className="h-5 w-5" />,
  }[kind];
  const title = { unavailable: L.unavailable, forbidden: L.forbidden, offline: L.offline, error: L.error }[
    kind
  ];
  const hint = {
    unavailable: L.unavailableHint,
    forbidden: L.forbiddenHint,
    offline: L.offlineHint,
    error: detail,
  }[kind];
  const tone =
    kind === "error"
      ? "border-sev-critical/30 bg-sev-critical/10 text-sev-critical"
      : "border-line bg-surface-2/50 text-muted";
  return (
    <div
      role={kind === "error" ? "alert" : "status"}
      className={cn(
        "flex items-start gap-3 rounded-md border",
        compact ? "p-2.5 text-xs" : "p-4 text-sm",
        tone,
        className,
      )}
    >
      <span className="mt-0.5 shrink-0">{icon}</span>
      <div className="min-w-0 flex-1">
        <div className="font-medium">{title}</div>
        <div className={cn("mt-0.5 break-words text-xs", kind === "error" ? "" : "text-muted")}>{hint}</div>
      </div>
      {onRetry && kind !== "forbidden" && kind !== "unavailable" && (
        <Button size="sm" variant="outline" onClick={onRetry}>
          <RotateCw className="h-3.5 w-3.5" />
          {L.retry}
        </Button>
      )}
    </div>
  );
}

/** Default skeleton: a few table-ish rows. */
export function RowsSkeleton({ rows = 5, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn("space-y-2", className)} aria-busy="true">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-7 w-full" />
      ))}
    </div>
  );
}

export function DataState({
  loading,
  error,
  empty,
  emptyTitle,
  emptyHint,
  emptyIcon,
  skeleton,
  onRetry,
  className,
  children,
}: {
  loading?: boolean;
  error?: unknown;
  empty?: boolean;
  emptyTitle?: ReactNode;
  emptyHint?: ReactNode;
  emptyIcon?: ReactNode;
  skeleton?: ReactNode;
  onRetry?: () => void;
  className?: string;
  children?: ReactNode;
}) {
  const L = useLocal(strings);
  if (loading) return <div className={className}>{skeleton ?? <RowsSkeleton />}</div>;
  if (error) return <ApiErrorNotice error={error} onRetry={onRetry} className={className} />;
  if (empty)
    return (
      <div className={className}>
        <EmptyState title={emptyTitle ?? L.empty} hint={emptyHint} icon={emptyIcon} />
      </div>
    );
  return <>{children}</>;
}
