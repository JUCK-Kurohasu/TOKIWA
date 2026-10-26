/**
 * Thin TanStack Query helpers around the `api` client.
 *
 * - 4xx responses are not retried (a 404 from a not-yet-implemented endpoint should render an
 *   "unavailable" state immediately instead of spinning through retries).
 * - `keepPrevious` holds the previous page while a new filter/page loads (no skeleton flash).
 */
import {
  keepPreviousData,
  type QueryKey,
  type UseQueryOptions,
  type UseQueryResult,
  useQuery,
} from "@tanstack/react-query";
import { ApiError, api } from "@/api/client";

export type QueryParams = Parameters<typeof api.get>[1];

export function retryUnlessClientError(failureCount: number, error: unknown): boolean {
  if (error instanceof ApiError && error.status >= 400 && error.status < 500) return false;
  return failureCount < 1;
}

export function isApiStatus(error: unknown, ...statuses: number[]): boolean {
  return error instanceof ApiError && statuses.includes(error.status);
}

export function useApiQuery<T>(
  key: QueryKey,
  path: string,
  params?: QueryParams,
  options?: Omit<UseQueryOptions<T, Error>, "queryKey" | "queryFn"> & { keepPrevious?: boolean },
): UseQueryResult<T, Error> {
  const { keepPrevious, ...rest } = options ?? {};
  return useQuery<T, Error>({
    queryKey: key,
    queryFn: () => api.get<T>(path, params),
    retry: retryUnlessClientError,
    ...(keepPrevious ? { placeholderData: keepPreviousData } : {}),
    ...rest,
  });
}

/**
 * Best-effort human readable message for an unknown error. FastAPI 422 bodies
 * (`{detail: [{loc, msg}, ...]}`) are flattened to "field: message; ...".
 */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    const detail = (error.body as { detail?: unknown } | undefined)?.detail;
    if (Array.isArray(detail)) {
      return detail
        .map((d) => {
          const item = d as { loc?: unknown[]; msg?: unknown };
          const loc = Array.isArray(item.loc) ? item.loc.filter((x) => x !== "body").join(".") : "";
          return `${loc ? `${loc}: ` : ""}${String(item.msg ?? JSON.stringify(d))}`;
        })
        .join("; ");
    }
    return error.message;
  }
  if (error instanceof Error) return error.message;
  return String(error);
}
