/**
 * Loading / error / empty handling for a TanStack query, so every list renders all three states the same way.
 * A 404 is shown as "API not available yet" instead of a raw error, because the backend modules are built in
 * parallel and a page must not break when its endpoint is missing.
 */
import { AlertTriangle } from "lucide-react";
import type { ReactNode } from "react";
import { ApiError } from "@/api/client";
import { EmptyState, Skeleton } from "@/components/ui";
import { useLang } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const msgs = {
  ja: {
    notFound: "この API はまだ利用できません（404）。バックエンドの実装・起動を確認してください。",
    forbidden: "この操作を行う権限がありません（403）。",
    unauthorized: "セッションの有効期限が切れました。再ログインしてください。",
    network: "サーバーに接続できません。",
    validation: "入力内容に誤りがあります",
    empty: "データがありません",
  },
  en: {
    notFound:
      "This API is not available yet (404). Check that the backend module is implemented and running.",
    forbidden: "You do not have permission for this action (403).",
    unauthorized: "Your session expired. Please sign in again.",
    network: "Cannot reach the server.",
    validation: "Invalid input",
    empty: "No data",
  },
};

type FastApiValidationItem = { loc?: (string | number)[]; msg?: string };

/** Human-readable message for an API error (FastAPI `{detail}` incl. 422 validation arrays). */
export function describeError(err: unknown, lang: "ja" | "en"): string {
  const m = msgs[lang];
  if (err instanceof ApiError) {
    if (err.status === 404) return m.notFound;
    if (err.status === 403) return m.forbidden;
    if (err.status === 401) return m.unauthorized;
    const body = err.body as { detail?: unknown } | undefined;
    if (body && Array.isArray(body.detail)) {
      const items = (body.detail as FastApiValidationItem[])
        .map((d) => {
          const loc = (d.loc ?? []).filter((x) => x !== "body").join(".");
          return loc ? `${loc}: ${d.msg ?? ""}` : (d.msg ?? "");
        })
        .filter(Boolean);
      if (items.length) return `${m.validation}: ${items.join(" / ")}`;
    }
    return err.message || `HTTP ${err.status}`;
  }
  if (err instanceof TypeError) return m.network;
  return err instanceof Error ? err.message : String(err);
}

export function ApiErrorState({ error, className }: { error: unknown; className?: string }) {
  const { lang } = useLang();
  const notFound = error instanceof ApiError && error.status === 404;
  return (
    <div
      role="alert"
      className={cn(
        "flex items-start gap-2 rounded-md border p-3 text-sm",
        notFound
          ? "border-line bg-surface-2 text-muted"
          : "border-sev-critical/30 bg-sev-critical/10 text-sev-critical",
        className,
      )}
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
      <span className="min-w-0 break-words">{describeError(error, lang)}</span>
    </div>
  );
}

export function LoadingRows({ rows = 4, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn("space-y-2", className)} aria-busy="true">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-9 w-full" />
      ))}
    </div>
  );
}

interface QueryLike<T> {
  data: T | undefined;
  isLoading: boolean;
  error: unknown;
}

export function QueryView<T>({
  query,
  isEmpty,
  empty,
  rows,
  className,
  children,
}: {
  query: QueryLike<T>;
  isEmpty?: (data: T) => boolean;
  empty?: ReactNode;
  rows?: number;
  className?: string;
  children: (data: T) => ReactNode;
}) {
  const { lang } = useLang();
  if (query.isLoading) return <LoadingRows rows={rows} className={className} />;
  if (query.error) return <ApiErrorState error={query.error} className={className} />;
  if (query.data === undefined) return null;
  if (isEmpty?.(query.data)) {
    return <div className={className}>{empty ?? <EmptyState title={msgs[lang].empty} />}</div>;
  }
  return <>{children(query.data)}</>;
}
