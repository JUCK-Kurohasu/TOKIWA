/**
 * Sends a copilot message and consumes the SSE response (POST, via postStream):
 *   text → answer text (appended; the backend may send it in chunks or all at once)
 *   tool_call / tool_result → read-only tool progress ("search_events を実行中…" → done)
 *   done / error → end of turn
 * Field names beyond `type` are not pinned down by the contract, so several spellings are accepted.
 */
import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, postStream } from "@/api/client";
import type { CopilotConversation } from "@/api/types-intel";

export interface ToolStep {
  key: string;
  id?: string;
  name: string;
  input?: unknown;
  status: "running" | "done" | "error";
  summary?: string;
}

export interface StreamState {
  convId: string;
  userText: string;
  text: string;
  steps: ToolStep[];
  phase: "streaming" | "finishing" | "stopped" | "error";
  error?: unknown;
}

function asText(v: unknown): string {
  if (typeof v === "string") return v;
  if (v == null) return "";
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

function pickString(ev: Record<string, unknown>, ...keys: string[]): string | undefined {
  for (const k of keys) {
    const v = ev[k];
    if (typeof v === "string" && v) return v;
  }
  return undefined;
}

export class StreamError extends Error {}

export function useCopilotStream(onConversationCreated: (id: string) => void) {
  const qc = useQueryClient();
  const [stream, setStream] = useState<StreamState | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const seq = useRef(0);

  useEffect(() => () => abortRef.current?.abort(), []);

  const stop = useCallback(() => abortRef.current?.abort(), []);
  const clear = useCallback(() => setStream(null), []);

  const send = useCallback(
    async (conversationId: string | null, content: string, title?: string) => {
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;
      let convId = conversationId;
      try {
        if (!convId) {
          const conv = await api.post<CopilotConversation>("/copilot/conversations", {
            title: title ?? content.slice(0, 60),
          });
          convId = conv.id;
          qc.invalidateQueries({ queryKey: ["copilot", "conversations"] });
        }
        const id = convId;
        setStream({ convId: id, userText: content, text: "", steps: [], phase: "streaming" });
        if (!conversationId) onConversationCreated(id);

        let sawError: string | null = null;
        await postStream(
          `/copilot/conversations/${encodeURIComponent(id)}/messages`,
          { content },
          (ev) => {
            const type = ev.type;
            if (type === "text") {
              const chunk = pickString(ev, "text", "delta", "content") ?? "";
              if (chunk) setStream((s) => (s ? { ...s, text: s.text + chunk } : s));
            } else if (type === "tool_call") {
              seq.current += 1;
              const step: ToolStep = {
                key: `t${seq.current}`,
                id: pickString(ev, "id", "tool_use_id"),
                name: pickString(ev, "name", "tool") ?? "tool",
                input: ev.input ?? ev.arguments,
                status: "running",
              };
              setStream((s) => (s ? { ...s, steps: [...s.steps, step] } : s));
            } else if (type === "tool_result") {
              const rid = pickString(ev, "id", "tool_use_id");
              const rname = pickString(ev, "name", "tool");
              const isError = ev.is_error === true;
              const summary =
                pickString(ev, "summary") ?? (ev.content != null ? asText(ev.content) : undefined);
              setStream((s) => {
                if (!s) return s;
                const steps = [...s.steps];
                let idx = rid ? steps.findIndex((t) => t.id === rid) : -1;
                if (idx < 0)
                  idx = steps.findIndex((t) => t.status === "running" && (!rname || t.name === rname));
                if (idx < 0) idx = steps.findIndex((t) => t.status === "running");
                if (idx >= 0) {
                  steps[idx] = { ...steps[idx], status: isError ? "error" : "done", summary };
                } else {
                  seq.current += 1;
                  steps.push({
                    key: `t${seq.current}`,
                    name: rname ?? "tool",
                    status: isError ? "error" : "done",
                    summary,
                  });
                }
                return { ...s, steps };
              });
            } else if (type === "error") {
              sawError = pickString(ev, "error", "message", "detail") ?? "error";
            }
          },
          controller.signal,
        );
        if (sawError) throw new StreamError(sawError);
        setStream((s) => (s ? { ...s, phase: "finishing" } : s));
        await Promise.all([
          qc.invalidateQueries({ queryKey: ["copilot", "conversation", id] }),
          qc.invalidateQueries({ queryKey: ["copilot", "conversations"] }),
        ]);
        // The persisted messages now include this turn; drop the live bubble.
        setStream((s) => (s && s.convId === id && s.phase === "finishing" ? null : s));
      } catch (err) {
        const aborted =
          controller.signal.aborted || (err instanceof DOMException && err.name === "AbortError");
        setStream((s) =>
          s
            ? {
                ...s,
                phase: aborted ? "stopped" : "error",
                error: aborted ? undefined : err,
                steps: s.steps.map((t) =>
                  t.status === "running" ? { ...t, status: aborted ? "done" : "error" } : t,
                ),
              }
            : convId
              ? { convId, userText: content, text: "", steps: [], phase: "error", error: err }
              : null,
        );
        if (!convId && !aborted) throw err;
        if (convId) {
          qc.invalidateQueries({ queryKey: ["copilot", "conversation", convId] });
        }
      } finally {
        if (abortRef.current === controller) abortRef.current = null;
      }
    },
    [qc, onConversationCreated],
  );

  return { stream, send, stop, clear, busy: stream?.phase === "streaming" || stream?.phase === "finishing" };
}
