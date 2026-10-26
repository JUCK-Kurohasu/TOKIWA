/**
 * Copilot (/copilot): conversation list + chat with read-only tools, streamed over SSE.
 *   ?c=<id>            open a conversation
 *   ?incident=<id>     create a conversation with context.incident_id (used by "Ask copilot" on incidents)
 * OWNER: frontend-intel.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, MessageSquarePlus, Trash2 } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/api/client";
import type { Page } from "@/api/types";
import { asList, type CopilotConversation } from "@/api/types-intel";
import { PageHeader } from "@/components/common";
import { ConfirmDialog } from "@/components/common/DangerConfirm";
import { ApiErrorState, LoadingRows } from "@/components/common/QueryView";
import { useUrlParams } from "@/components/common/urlState";
import { Button, Card, EmptyState } from "@/components/ui";
import { timeAgo } from "@/lib/format";
import { useLocal, useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import type { AppRoute } from "@/routes";
import { ChatView } from "./ChatView";
import { useCopilotStream } from "./useCopilotStream";

const strings = {
  ja: {
    title: "コパイロット",
    desc: "自然言語で調査する SOC アシスタント（参照専用ツールのみ）",
    newChat: "新しい会話",
    conversations: "会話",
    empty: "会話はまだありません",
    deleteTitle: "会話を削除",
    deleteBody: "「{name}」を削除します。この操作は取り消せません。",
    incidentTitle: "インシデント {id}",
    creating: "インシデントの文脈で会話を作成しています…",
    untitled: "無題の会話",
  },
  en: {
    title: "Copilot",
    desc: "SOC assistant for natural-language investigation (read-only tools only)",
    newChat: "New conversation",
    conversations: "Conversations",
    empty: "No conversations yet",
    deleteTitle: "Delete conversation",
    deleteBody: 'Delete "{name}". This cannot be undone.',
    incidentTitle: "Incident {id}",
    creating: "Creating a conversation with the incident context…",
    untitled: "Untitled conversation",
  },
};

function CopilotPage() {
  const L = useLocal(strings);
  const t = useT();
  const qc = useQueryClient();
  const [params, update] = useUrlParams();
  const convId = params.get("c");
  const incidentParam = params.get("incident");
  const [toDelete, setToDelete] = useState<CopilotConversation | null>(null);
  const [sendError, setSendError] = useState<unknown>(null);

  const list = useQuery({
    queryKey: ["copilot", "conversations"],
    queryFn: () => api.get<CopilotConversation[] | Page<CopilotConversation>>("/copilot/conversations"),
    select: (d) => [...asList(d)].sort((a, b) => b.updated_at.localeCompare(a.updated_at)),
  });

  const onCreated = useCallback((id: string) => update({ c: id, incident: null }), [update]);
  const { stream, send, stop, clear, busy } = useCopilotStream(onCreated);

  // ?incident=<id>: create a context-bound conversation once (ref guards StrictMode double effects).
  const handledIncident = useRef<string | null>(null);
  const createForIncident = useMutation({
    mutationFn: (incidentId: string) =>
      api.post<CopilotConversation>("/copilot/conversations", {
        title: L.incidentTitle.replace("{id}", incidentId.slice(0, 12)),
        context: { incident_id: incidentId },
      }),
    onSuccess: (conv) => {
      qc.invalidateQueries({ queryKey: ["copilot", "conversations"] });
      update({ c: conv.id, incident: null });
    },
  });
  const { mutate: createIncidentConv } = createForIncident;
  useEffect(() => {
    if (!incidentParam || handledIncident.current === incidentParam) return;
    handledIncident.current = incidentParam;
    createIncidentConv(incidentParam);
  }, [incidentParam, createIncidentConv]);

  // Navigating away from a conversation that is still streaming stops that stream. Compare against the
  // previous ?c= so a freshly created conversation (stream id set just before the URL updates) is not stopped.
  const prevConv = useRef(convId);
  useEffect(() => {
    const prev = prevConv.current;
    prevConv.current = convId;
    if (stream?.phase === "streaming" && prev === stream.convId && convId !== stream.convId) stop();
  }, [convId, stream, stop]);

  const del = useMutation({
    mutationFn: (c: CopilotConversation) => api.delete(`/copilot/conversations/${encodeURIComponent(c.id)}`),
    onSuccess: (_d, c) => {
      setToDelete(null);
      if (c.id === convId) update({ c: null });
      qc.removeQueries({ queryKey: ["copilot", "conversation", c.id] });
      qc.invalidateQueries({ queryKey: ["copilot", "conversations"] });
    },
  });

  const handleSend = async (content: string) => {
    setSendError(null);
    try {
      await send(convId, content);
    } catch (err) {
      setSendError(err);
    }
  };

  return (
    <div className="flex h-[calc(100vh-7.5rem)] min-h-[32rem] flex-col">
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <Bot className="h-5 w-5 text-ai" aria-hidden />
            {L.title}
          </span>
        }
        description={L.desc}
      />
      <div className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[17rem_minmax(0,1fr)]">
        <Card className="flex min-h-0 flex-col">
          <div className="flex items-center justify-between gap-2 border-b border-line px-3 py-2">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-muted">{L.conversations}</h2>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                clear();
                setSendError(null);
                update({ c: null });
              }}
            >
              <MessageSquarePlus className="h-3.5 w-3.5" aria-hidden />
              {L.newChat}
            </Button>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">
            {list.isLoading && <LoadingRows rows={4} className="p-3" />}
            {list.error ? <ApiErrorState error={list.error} className="m-3" /> : null}
            {list.data && list.data.length === 0 && <EmptyState title={L.empty} />}
            <ul className="divide-y divide-line">
              {(list.data ?? []).map((c) => (
                <li key={c.id} className="group relative">
                  <button
                    type="button"
                    aria-current={c.id === convId ? "true" : undefined}
                    onClick={() => {
                      setSendError(null);
                      update({ c: c.id });
                    }}
                    className={cn(
                      "flex w-full flex-col gap-0.5 py-2 pr-10 pl-3 text-left transition-colors hover:bg-surface-2",
                      c.id === convId && "bg-ai/10 shadow-[inset_3px_0_0_0_var(--color-ai)]",
                    )}
                  >
                    <span className="truncate text-sm">{c.title || L.untitled}</span>
                    <span className="text-[11px] text-muted">{timeAgo(c.updated_at)}</span>
                  </button>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="absolute top-1.5 right-1 h-7 w-7 opacity-60 group-hover:opacity-100 hover:text-sev-critical focus-visible:opacity-100"
                    aria-label={`${t("common.delete")}: ${c.title}`}
                    title={t("common.delete")}
                    onClick={() => {
                      del.reset();
                      setToDelete(c);
                    }}
                  >
                    <Trash2 className="h-3.5 w-3.5" aria-hidden />
                  </Button>
                </li>
              ))}
            </ul>
          </div>
        </Card>

        <Card className="flex min-h-0 flex-col overflow-hidden">
          {createForIncident.isPending ? (
            <div className="p-4 text-sm text-muted">{L.creating}</div>
          ) : (
            <>
              {createForIncident.error ? (
                <ApiErrorState error={createForIncident.error} className="m-3" />
              ) : null}
              {sendError ? <ApiErrorState error={sendError} className="m-3" /> : null}
              <div className="min-h-0 flex-1">
                <ChatView
                  conversationId={convId}
                  stream={stream}
                  busy={busy}
                  onSend={handleSend}
                  onStop={stop}
                />
              </div>
            </>
          )}
        </Card>
      </div>

      <ConfirmDialog
        open={!!toDelete}
        title={L.deleteTitle}
        body={L.deleteBody.replace("{name}", toDelete?.title ?? "")}
        confirmLabel={t("common.delete")}
        busy={del.isPending}
        error={del.error}
        onConfirm={() => toDelete && del.mutate(toDelete)}
        onClose={() => setToDelete(null)}
      />
    </div>
  );
}

export const route: AppRoute = {
  path: "/copilot",
  component: CopilotPage,
  nav: {
    label: { ja: "コパイロット", en: "Copilot" },
    icon: Bot,
    section: "investigate",
    order: 25,
  },
};
