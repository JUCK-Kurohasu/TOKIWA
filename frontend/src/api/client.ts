/**
 * API client. All calls go to /api/v1 (proxied to the backend in dev).
 *
 *   const data = await api.get<Page<Alert>>("/alerts", { severity: "high" });
 *   await api.post("/response/actions/123/approve");
 *
 * Use TanStack Query hooks in pages:  useQuery({ queryKey: ["alerts", params], queryFn: () => api.get(...) })
 */
import { authStore } from "@/stores/auth";
import type { StreamTicket } from "./types-core";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public body?: unknown,
  ) {
    super(message);
  }
}

type Params = Record<string, string | number | boolean | null | undefined | string[]>;

const BASE = "/api/v1";

function buildUrl(path: string, params?: Params): string {
  const url = new URL(BASE + path, window.location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined || v === null || v === "") continue;
      if (Array.isArray(v)) for (const item of v) url.searchParams.append(k, item);
      else url.searchParams.set(k, String(v));
    }
  }
  return url.pathname + url.search;
}

async function request<T>(method: string, path: string, body?: unknown, params?: Params): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const token = authStore.getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(buildUrl(path, params), {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401 && token) {
    authStore.logout();
  }
  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!res.ok) {
    const detail =
      data && typeof data === "object" && "detail" in data
        ? (data as { detail: unknown }).detail
        : res.statusText;
    throw new ApiError(res.status, typeof detail === "string" ? detail : JSON.stringify(detail), data);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string, params?: Params) => request<T>("GET", path, undefined, params),
  post: <T>(path: string, body?: unknown, params?: Params) => request<T>("POST", path, body ?? {}, params),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body ?? {}),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body ?? {}),
  delete: <T>(path: string) => request<T>("DELETE", path),
};

/**
 * URL for the live stream (`EventSource`): `/api/v1/stream?ticket=<single-use ticket>` (audit #100).
 *
 * EventSource cannot send the Authorization header, and a JWT in the URL would end up in reverse-proxy access
 * logs, so a ticket (valid 60 s, one connection) is fetched with the JWT first. A used ticket is refused (401),
 * so after any disconnect the caller must fetch a new URL instead of letting EventSource retry the old one.
 * Open the stream through `useLiveStream` (one shared connection per tab), not directly.
 */
export async function streamUrl(): Promise<string> {
  const { ticket } = await api.post<StreamTicket>("/stream/ticket");
  return buildUrl("/stream", { ticket });
}

/**
 * POST that returns an SSE stream (copilot). Calls onEvent for each `data:` JSON payload.
 */
export async function postStream(
  path: string,
  body: unknown,
  onEvent: (data: Record<string, unknown>) => void,
  signal?: AbortSignal,
): Promise<void> {
  const token = authStore.getToken();
  const res = await fetch(BASE + path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "text/event-stream",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
    signal,
  });
  if (!res.ok || !res.body) throw new ApiError(res.status, res.statusText);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let idx = buf.indexOf("\n\n");
    while (idx >= 0) {
      const chunk = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      for (const line of chunk.split("\n")) {
        if (line.startsWith("data:")) {
          try {
            onEvent(JSON.parse(line.slice(5).trim()));
          } catch {
            /* ignore */
          }
        }
      }
      idx = buf.indexOf("\n\n");
    }
  }
}
