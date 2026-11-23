/**
 * Live refresh for ops pages: invalidate TanStack Query keys when a stream topic with one of the given prefixes
 * arrives (alert.* / incident.* / action.* / deception.*).
 *
 * Uses the tab's shared SSE connection (`useLiveStream`), which handles the ticket auth (audit #100) and
 * reconnects with backoff; pages still work through their own polling / manual refresh while it is down.
 * Invalidations are debounced so a burst of events triggers one refetch. The payload is never rendered — it only
 * triggers a refetch.
 */
import { type QueryKey, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef } from "react";
import { useLiveStream } from "@/hooks/useLiveStream";

export function useOpsLive(topicPrefixes: string[], keys: QueryKey[], debounceMs = 800): void {
  const qc = useQueryClient();
  const latestKeys = useRef(keys);
  latestKeys.current = keys;
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const onMessage = useCallback(() => {
    if (timer.current) return;
    timer.current = setTimeout(() => {
      timer.current = undefined;
      for (const k of latestKeys.current) void qc.invalidateQueries({ queryKey: k });
    }, debounceMs);
  }, [qc, debounceMs]);

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
      timer.current = undefined;
    },
    [],
  );

  // An empty prefix list matched nothing before; useLiveStream treats "no topics" as "all topics".
  useLiveStream({ topics: topicPrefixes, onMessage, invalidate: false, enabled: topicPrefixes.length > 0 });
}
