/**
 * Live updates over SSE (`GET /api/v1/stream`, payload `{"topic": "...", "data": {...}}`).
 *
 * - One shared EventSource per tab, reference-counted across every component that calls the hook
 *   (browsers cap HTTP/1.1 connections per origin, so we must not open one stream per widget).
 * - Every message invalidates the matching TanStack Query caches (throttled per key), so pages that
 *   follow the `[<resource>, ...params]` query-key convention refresh automatically.
 * - The last {@link BUFFER_SIZE} messages are kept so a live feed survives page navigation.
 *
 * Why not `openEventStream()` from api/client.ts: it hides open/error state, which we need for the
 * connection indicator and for reconnecting after the server closes the stream (EventSource gives up
 * permanently on HTTP errors such as 401/404/502). The URL and auth scheme are identical
 * (`/api/v1/stream?access_token=<JWT>`).
 *
 * Usage:
 *   const { status } = useLiveStream();                       // just keep caches fresh
 *   useLiveStream({ topics: ["alert."], onMessage: (m) => ... });
 *   const feed = useLiveFeed(["alert.", "incident."]);        // recent messages, newest first
 */
import { type QueryClient, type QueryKey, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useSyncExternalStore } from "react";
import { authStore } from "@/stores/auth";

export type LiveStatus = "idle" | "connecting" | "open" | "reconnecting";

export interface LiveMessage {
  /** Monotonic id (per tab) usable as a React key */
  id: number;
  topic: string;
  data: unknown;
  receivedAt: number;
}

type Listener = (msg: LiveMessage) => void;

const STREAM_URL = "/api/v1/stream";
const BUFFER_SIZE = 100;
const CLOSE_GRACE_MS = 1500;
const MAX_BACKOFF_MS = 60_000;

/**
 * Topic prefix -> query-key prefixes to invalidate, and the minimum delay between invalidations.
 * Keys follow the convention `[resource, ...params]` (e.g. ["alerts", {...}], ["dashboard", "summary"]).
 */
export const TOPIC_INVALIDATIONS: { prefix: string; keys: QueryKey[]; delayMs: number }[] = [
  { prefix: "alert.", keys: [["alerts"], ["dashboard"]], delayMs: 1_000 },
  { prefix: "incident.", keys: [["incidents"], ["dashboard"]], delayMs: 1_000 },
  { prefix: "action.", keys: [["response"], ["actions"], ["incidents"], ["dashboard"]], delayMs: 1_000 },
  { prefix: "deception.", keys: [["deception"], ["dashboard"]], delayMs: 2_000 },
  { prefix: "intel.", keys: [["intel"], ["dashboard"]], delayMs: 5_000 },
  { prefix: "llm.call", keys: [["llm"], ["dashboard"]], delayMs: 5_000 },
  // Raw event volume can be high: refresh aggregate views slowly. The events explorer itself is NOT
  // invalidated (rows must not jump under the cursor); it shows a "new events" banner instead.
  { prefix: "event.ingested", keys: [["dashboard"], ["sessions"], ["hosts"]], delayMs: 15_000 },
];

class LiveStreamManager {
  private es: EventSource | null = null;
  private token: string | null = null;
  private listeners = new Set<Listener>();
  private clients = new Map<QueryClient, number>();
  private statusListeners = new Set<() => void>();
  private bufferListeners = new Set<() => void>();
  private status: LiveStatus = "idle";
  private buffer: LiveMessage[] = [];
  private seq = 0;
  private attempt = 0;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private closeTimer: ReturnType<typeof setTimeout> | null = null;
  private pendingInvalidations = new Map<string, ReturnType<typeof setTimeout>>();
  private unsubscribeAuth: (() => void) | null = null;

  // ----- subscriptions -----
  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    this.ensureOpen();
    return () => {
      this.listeners.delete(listener);
      this.maybeClose();
    };
  }

  attachClient(qc: QueryClient): () => void {
    this.clients.set(qc, (this.clients.get(qc) ?? 0) + 1);
    return () => {
      const n = (this.clients.get(qc) ?? 1) - 1;
      if (n <= 0) this.clients.delete(qc);
      else this.clients.set(qc, n);
    };
  }

  // ----- external stores -----
  getStatus = (): LiveStatus => this.status;
  subscribeStatus = (l: () => void): (() => void) => {
    this.statusListeners.add(l);
    return () => this.statusListeners.delete(l);
  };
  getBuffer = (): LiveMessage[] => this.buffer;
  subscribeBuffer = (l: () => void): (() => void) => {
    this.bufferListeners.add(l);
    return () => this.bufferListeners.delete(l);
  };

  // ----- connection lifecycle -----
  private setStatus(s: LiveStatus) {
    if (this.status === s) return;
    this.status = s;
    for (const l of this.statusListeners) l();
  }

  private ensureOpen() {
    if (this.closeTimer) {
      clearTimeout(this.closeTimer);
      this.closeTimer = null;
    }
    if (!this.unsubscribeAuth) {
      // Reconnect with the new JWT after login / drop the stream on logout.
      this.unsubscribeAuth = authStore.subscribe(() => {
        if (authStore.getToken() !== this.token && this.listeners.size > 0) {
          this.teardown();
          this.connect();
        }
      });
    }
    if (!this.es && !this.retryTimer) this.connect();
  }

  private maybeClose() {
    if (this.listeners.size > 0 || this.closeTimer) return;
    // Grace period: survives StrictMode double-mount and route changes without reconnecting.
    this.closeTimer = setTimeout(() => {
      this.closeTimer = null;
      if (this.listeners.size === 0) {
        this.teardown();
        this.unsubscribeAuth?.();
        this.unsubscribeAuth = null;
        this.setStatus("idle");
      }
    }, CLOSE_GRACE_MS);
  }

  private teardown() {
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    if (this.es) {
      this.es.onopen = null;
      this.es.onmessage = null;
      this.es.onerror = null;
      this.es.close();
      this.es = null;
    }
  }

  private connect() {
    this.token = authStore.getToken();
    if (!this.token || typeof EventSource === "undefined") {
      this.setStatus("idle");
      return;
    }
    this.setStatus(this.attempt === 0 ? "connecting" : "reconnecting");
    const es = new EventSource(`${STREAM_URL}?access_token=${encodeURIComponent(this.token)}`);
    this.es = es;
    es.onopen = () => {
      this.attempt = 0;
      this.setStatus("open");
    };
    es.onmessage = (ev) => this.handleRaw(ev.data);
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) {
        // The browser gave up (HTTP error / wrong content type): retry ourselves with backoff.
        this.teardown();
        this.scheduleReconnect();
      } else {
        // Browser is auto-reconnecting after a network drop.
        this.setStatus("reconnecting");
      }
    };
  }

  private scheduleReconnect() {
    if (this.listeners.size === 0) return;
    this.attempt += 1;
    this.setStatus("reconnecting");
    const delay = Math.min(MAX_BACKOFF_MS, 1000 * 2 ** Math.min(this.attempt, 6));
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.connect();
    }, delay);
  }

  // ----- messages -----
  private handleRaw(raw: string) {
    let parsed: { topic?: unknown; data?: unknown };
    try {
      parsed = JSON.parse(raw) as { topic?: unknown; data?: unknown };
    } catch {
      return; // ignore malformed frames
    }
    if (!parsed || typeof parsed.topic !== "string") return;
    this.seq += 1;
    const msg: LiveMessage = { id: this.seq, topic: parsed.topic, data: parsed.data, receivedAt: Date.now() };
    this.buffer = [msg, ...this.buffer].slice(0, BUFFER_SIZE);
    for (const l of this.bufferListeners) l();
    this.invalidateFor(msg.topic);
    for (const l of this.listeners) {
      try {
        l(msg);
      } catch (err) {
        console.error("live stream listener failed", err);
      }
    }
  }

  private invalidateFor(topic: string) {
    if (this.clients.size === 0) return;
    for (const rule of TOPIC_INVALIDATIONS) {
      if (!topic.startsWith(rule.prefix)) continue;
      for (const key of rule.keys) {
        const id = JSON.stringify(key);
        if (this.pendingInvalidations.has(id)) continue; // already scheduled: throttle
        this.pendingInvalidations.set(
          id,
          setTimeout(() => {
            this.pendingInvalidations.delete(id);
            for (const qc of this.clients.keys()) void qc.invalidateQueries({ queryKey: key });
          }, rule.delayMs),
        );
      }
    }
  }
}

const manager = new LiveStreamManager();

function matches(topic: string, topics?: readonly string[]): boolean {
  return !topics || topics.length === 0 || topics.some((t) => topic === t || topic.startsWith(t));
}

export interface UseLiveStreamOptions {
  /** Topic names or prefixes (e.g. "alert."). Omit for all topics. */
  topics?: readonly string[];
  onMessage?: (msg: LiveMessage) => void;
  /** Invalidate TanStack Query caches per {@link TOPIC_INVALIDATIONS}. Default true. */
  invalidate?: boolean;
  /** Default true. */
  enabled?: boolean;
}

/** Subscribe to the shared SSE stream. Returns the connection status. */
export function useLiveStream(options: UseLiveStreamOptions = {}): { status: LiveStatus } {
  const { topics, onMessage, invalidate = true, enabled = true } = options;
  const qc = useQueryClient();
  const handlerRef = useRef(onMessage);
  const topicsRef = useRef(topics);
  handlerRef.current = onMessage;
  topicsRef.current = topics;

  useEffect(() => {
    if (!enabled) return;
    const detachClient = invalidate ? manager.attachClient(qc) : undefined;
    const unsubscribe = manager.subscribe((msg) => {
      if (handlerRef.current && matches(msg.topic, topicsRef.current)) handlerRef.current(msg);
    });
    return () => {
      unsubscribe();
      detachClient?.();
    };
  }, [enabled, invalidate, qc]);

  return { status: useLiveStatus() };
}

/** Connection status without subscribing (does not open the stream by itself). */
export function useLiveStatus(): LiveStatus {
  return useSyncExternalStore(manager.subscribeStatus, manager.getStatus, manager.getStatus);
}

/**
 * Recent stream messages (newest first) filtered by topic, kept across navigation.
 * Opens the stream (and cache invalidation) while mounted.
 */
export function useLiveFeed(topics?: readonly string[], max = 50): LiveMessage[] {
  useLiveStream();
  const buffer = useSyncExternalStore(manager.subscribeBuffer, manager.getBuffer, manager.getBuffer);
  const key = topics?.join("|") ?? "";
  // biome-ignore lint/correctness/useExhaustiveDependencies: `key` is the stable identity of `topics`
  return useMemo(() => buffer.filter((m) => matches(m.topic, topics)).slice(0, max), [buffer, key, max]);
}
