/**
 * Live refresh for ops pages: subscribe to GET /stream (SSE) and invalidate TanStack Query keys when a
 * topic with one of the given prefixes arrives (alert.* / incident.* / action.* / deception.*).
 *
 * Invalidations are debounced so a burst of events triggers one refetch. If /stream is not available
 * (non-200 response), EventSource gives up permanently per spec; pages still work through their own
 * polling / manual refresh. The payload is never rendered — it only triggers a refetch.
 */
import { type QueryKey, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { openEventStream } from "@/api/client";

export function useOpsLive(topicPrefixes: string[], keys: QueryKey[], debounceMs = 800): void {
  const qc = useQueryClient();
  const latest = useRef({ topicPrefixes, keys });
  latest.current = { topicPrefixes, keys };

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const close = openEventStream("/stream", (topic) => {
      if (!latest.current.topicPrefixes.some((p) => topic.startsWith(p))) return;
      if (timer) return;
      timer = setTimeout(() => {
        timer = undefined;
        for (const k of latest.current.keys) void qc.invalidateQueries({ queryKey: k });
      }, debounceMs);
    });
    return () => {
      close();
      if (timer) clearTimeout(timer);
    };
  }, [qc, debounceMs]);
}
