/**
 * Copilot chat pane. Assistant answers are rendered with SafeMarkdown (React elements only, no innerHTML);
 * user messages are plain text. While a turn streams, tool calls are shown as live steps.
 */
import { useQuery } from "@tanstack/react-query";
import {
  Bot,
  CheckCircle2,
  CircleStop,
  Loader2,
  Send,
  ShieldAlert,
  User,
  Wrench,
  XCircle,
} from "lucide-react";
import { type KeyboardEvent, useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { api } from "@/api/client";
import type { CopilotConversationDetail, CopilotMessage, CopilotToolCall } from "@/api/types-intel";
import { ApiErrorState, LoadingRows } from "@/components/common/QueryView";
import { SafeMarkdown } from "@/components/common/SafeMarkdown";
import { Button, Textarea } from "@/components/ui";
import { formatDateTime } from "@/lib/format";
import { useLang, useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import type { StreamState, ToolStep } from "./useCopilotStream";

const strings = {
  ja: {
    placeholder: "質問を入力（例: 直近 24 時間で AI エージェントらしいセッションは？）",
    hint: "Enter で送信 / Shift+Enter で改行",
    send: "送信",
    stop: "停止",
    thinking: "考え中…",
    running: "を実行中…",
    done: "完了",
    failed: "失敗",
    stopped: "停止しました",
    toolsUsed: "使用したツール",
    safety:
      "コパイロットは参照専用のツールだけを使い、対処を実行することはありません。回答の根拠は必ず確認してください。",
    context: "インシデントの文脈",
    welcome: "SOC コパイロット",
    welcomeHint: "イベント・アラート・インシデント・セッション・脆弱性を自然言語で調べられます。",
    suggestions: "質問の例",
  },
  en: {
    placeholder: "Ask a question (e.g. which sessions in the last 24h look like AI agents?)",
    hint: "Enter to send / Shift+Enter for a new line",
    send: "Send",
    stop: "Stop",
    thinking: "Thinking…",
    running: "running…",
    done: "done",
    failed: "failed",
    stopped: "Stopped",
    toolsUsed: "Tools used",
    safety:
      "The copilot only uses read-only tools and never executes response actions. Always verify the evidence.",
    context: "Incident context",
    welcome: "SOC Copilot",
    welcomeHint: "Investigate events, alerts, incidents, sessions and vulnerabilities in natural language.",
    suggestions: "Try asking",
  },
};

const suggestionSets = {
  ja: {
    general: [
      "直近 24 時間で AI エージェントらしいセッションを要約して",
      "KEV に該当する脆弱性を持つ資産は？",
      "アラートが最も多い送信元 IP と、その行動を教えて",
      "未対応の重大インシデントを一覧にして",
    ],
    incident: [
      "このインシデントを要約して、攻撃の段階と根拠を示して",
      "このインシデントの送信元は他に何をしている？",
      "次に取るべき調査手順を提案して",
    ],
  },
  en: {
    general: [
      "Summarize sessions from the last 24h that look like AI agents",
      "Which assets have KEV-listed vulnerabilities?",
      "Which source IP raised the most alerts, and what did it do?",
      "List open critical incidents",
    ],
    incident: [
      "Summarize this incident with its attack stage and evidence",
      "What else did this incident's source do?",
      "Suggest the next investigation steps",
    ],
  },
};

const toolLabels: Record<string, { ja: string; en: string }> = {
  search_events: { ja: "イベント検索", en: "Search events" },
  get_alert: { ja: "アラート取得", en: "Get alert" },
  list_alerts: { ja: "アラート一覧", en: "List alerts" },
  get_incident: { ja: "インシデント取得", en: "Get incident" },
  list_incidents: { ja: "インシデント一覧", en: "List incidents" },
  get_session: { ja: "セッション取得", en: "Get session" },
  top_sources: { ja: "送信元ランキング", en: "Top sources" },
  lookup_vuln: { ja: "脆弱性照会", en: "Look up vulnerability" },
  list_vuln_matches: { ja: "資産一致の取得", en: "List vulnerability matches" },
  get_asset: { ja: "資産取得", en: "Get asset" },
  list_actions: { ja: "対処一覧", en: "List actions" },
};

function compactInput(input: unknown): string {
  if (input == null) return "";
  let s: string;
  try {
    s = typeof input === "string" ? input : JSON.stringify(input);
  } catch {
    s = String(input);
  }
  return s.length > 140 ? `${s.slice(0, 140)}…` : s;
}

function ToolName({ name }: { name: string }) {
  const { lang } = useLang();
  const label = toolLabels[name]?.[lang];
  return (
    <span>
      <span className="font-mono">{name}</span>
      {label && <span className="ml-1 text-muted">({label})</span>}
    </span>
  );
}

function StepRow({ step }: { step: ToolStep }) {
  const L = useLocal(strings);
  const Icon = step.status === "running" ? Loader2 : step.status === "error" ? XCircle : CheckCircle2;
  return (
    <li className="space-y-0.5">
      <div
        className={cn(
          "flex items-center gap-1.5 text-xs",
          step.status === "running" && "text-ai",
          step.status === "done" && "text-muted",
          step.status === "error" && "text-sev-critical",
        )}
      >
        <Icon
          className={cn("h-3.5 w-3.5 shrink-0", step.status === "running" && "animate-spin")}
          aria-hidden
        />
        <ToolName name={step.name} />
        <span>{step.status === "running" ? L.running : step.status === "error" ? L.failed : L.done}</span>
      </div>
      {step.input != null && (
        <div className="ml-5 truncate font-mono text-[10px] text-muted" title={compactInput(step.input)}>
          {compactInput(step.input)}
        </div>
      )}
      {step.summary && step.status !== "running" && (
        <div className="ml-5 line-clamp-2 text-[11px] text-muted">{step.summary}</div>
      )}
    </li>
  );
}

function ToolCallsUsed({ calls }: { calls: CopilotToolCall[] }) {
  const L = useLocal(strings);
  return (
    <details className="mt-2 text-xs">
      <summary className="inline-flex cursor-pointer items-center gap-1 text-muted hover:text-fg">
        <Wrench className="h-3 w-3" aria-hidden />
        {L.toolsUsed} ({calls.length})
      </summary>
      <ul className="mt-1.5 space-y-1 border-l border-line pl-3">
        {calls.map((c, i) => (
          <li key={c.id ?? i}>
            <ToolName name={c.name} />
            {c.input != null && (
              <div className="truncate font-mono text-[10px] text-muted">{compactInput(c.input)}</div>
            )}
            {c.summary && <div className="text-[11px] text-muted">{c.summary}</div>}
          </li>
        ))}
      </ul>
    </details>
  );
}

function Avatar({ who }: { who: "user" | "assistant" }) {
  return (
    <span
      aria-hidden
      className={cn(
        "flex h-7 w-7 shrink-0 items-center justify-center rounded-full border",
        who === "assistant" ? "border-ai/40 bg-ai/15 text-ai" : "border-line bg-surface-2 text-muted",
      )}
    >
      {who === "assistant" ? <Bot className="h-4 w-4" /> : <User className="h-4 w-4" />}
    </span>
  );
}

function MessageBubble({ m }: { m: CopilotMessage }) {
  if (m.role === "user") {
    return (
      <div className="flex justify-end gap-2">
        <div className="max-w-[80%] rounded-lg rounded-tr-sm border border-line bg-surface-2 px-3 py-2">
          <p className="whitespace-pre-wrap break-words text-sm">{m.content}</p>
          <div className="mt-1 text-right text-[10px] text-muted">{formatDateTime(m.created_at)}</div>
        </div>
        <Avatar who="user" />
      </div>
    );
  }
  return (
    <div className="flex gap-2">
      <Avatar who="assistant" />
      <div className="min-w-0 max-w-[85%] rounded-lg rounded-tl-sm border border-ai/20 bg-surface px-3 py-2">
        {m.content ? <SafeMarkdown text={m.content} /> : null}
        {m.tool_calls && m.tool_calls.length > 0 && <ToolCallsUsed calls={m.tool_calls} />}
        <div className="mt-1 text-[10px] text-muted">{formatDateTime(m.created_at)}</div>
      </div>
    </div>
  );
}

function LiveBubble({ stream }: { stream: StreamState }) {
  const L = useLocal(strings);
  return (
    <>
      <div className="flex justify-end gap-2">
        <div className="max-w-[80%] rounded-lg rounded-tr-sm border border-line bg-surface-2 px-3 py-2">
          <p className="whitespace-pre-wrap break-words text-sm">{stream.userText}</p>
        </div>
        <Avatar who="user" />
      </div>
      <div className="flex gap-2" aria-live="polite" aria-busy={stream.phase === "streaming"}>
        <Avatar who="assistant" />
        <div className="min-w-0 max-w-[85%] space-y-2 rounded-lg rounded-tl-sm border border-ai/30 bg-surface px-3 py-2">
          {stream.steps.length > 0 && (
            <ul className="space-y-1.5 rounded-md border border-line bg-bg/60 p-2">
              {stream.steps.map((s) => (
                <StepRow key={s.key} step={s} />
              ))}
            </ul>
          )}
          {stream.text ? (
            <SafeMarkdown text={stream.text} />
          ) : stream.phase === "streaming" && !stream.steps.some((s) => s.status === "running") ? (
            <div className="flex items-center gap-1.5 text-xs text-ai">
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
              {L.thinking}
            </div>
          ) : null}
          {stream.phase === "stopped" && <div className="text-xs text-muted">{L.stopped}</div>}
          {stream.phase === "error" && stream.error ? <ApiErrorState error={stream.error} /> : null}
        </div>
      </div>
    </>
  );
}

export function ChatView({
  conversationId,
  stream,
  busy,
  onSend,
  onStop,
}: {
  conversationId: string | null;
  stream: StreamState | null;
  busy: boolean;
  onSend: (content: string) => void;
  onStop: () => void;
}) {
  const L = useLocal(strings);
  const { lang } = useLang();
  const [draft, setDraft] = useState("");
  const scroller = useRef<HTMLDivElement>(null);

  const detail = useQuery({
    queryKey: ["copilot", "conversation", conversationId],
    queryFn: () =>
      api.get<CopilotConversationDetail>(
        `/copilot/conversations/${encodeURIComponent(conversationId ?? "")}`,
      ),
    enabled: !!conversationId,
  });

  const live = stream && stream.convId === conversationId ? stream : null;
  const messages = (detail.data?.messages ?? []).filter((m) => m.role === "user" || m.role === "assistant");
  const incidentId =
    typeof detail.data?.conversation.context?.incident_id === "string"
      ? (detail.data.conversation.context.incident_id as string)
      : null;

  // Keep the newest content in view as messages load and the live answer grows.
  const scrollKey = `${messages.length}:${live?.text.length ?? 0}:${live?.steps.length ?? 0}:${live?.phase ?? ""}`;
  useEffect(() => {
    const el = scroller.current;
    if (el && scrollKey) el.scrollTop = el.scrollHeight;
  }, [scrollKey]);

  const submit = () => {
    const text = draft.trim();
    if (!text || busy) return;
    setDraft("");
    onSend(text);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    // Ignore Enter while an IME (Japanese input) is composing.
    if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing && e.keyCode !== 229) {
      e.preventDefault();
      submit();
    }
  };

  const suggestions = suggestionSets[lang][incidentId ? "incident" : "general"];
  const empty = !detail.isLoading && messages.length === 0 && !live;

  return (
    <div className="flex h-full min-h-0 flex-col">
      {incidentId && (
        <div className="flex items-center gap-2 border-b border-line bg-ai/5 px-4 py-2 text-xs">
          <ShieldAlert className="h-3.5 w-3.5 text-ai" aria-hidden />
          <span className="text-muted">{L.context}:</span>
          <Link
            to={`/incidents/${encodeURIComponent(incidentId)}`}
            className="font-mono text-accent hover:underline"
          >
            {incidentId}
          </Link>
        </div>
      )}

      <div ref={scroller} className="min-h-0 flex-1 space-y-4 overflow-y-auto px-4 py-4">
        {conversationId && detail.isLoading && <LoadingRows rows={3} />}
        {detail.error ? <ApiErrorState error={detail.error} /> : null}
        {empty && (
          <div className="mx-auto flex max-w-xl flex-col items-center gap-3 py-8 text-center">
            <span className="flex h-12 w-12 items-center justify-center rounded-full border border-ai/40 bg-ai/10 text-ai">
              <Bot className="h-6 w-6" aria-hidden />
            </span>
            <h2 className="text-base font-semibold">{L.welcome}</h2>
            <p className="text-sm text-muted">{L.welcomeHint}</p>
            <div className="mt-2 w-full space-y-1.5 text-left">
              <div className="text-[11px] font-semibold uppercase tracking-wide text-muted">
                {L.suggestions}
              </div>
              {suggestions.map((s) => (
                <button
                  key={s}
                  type="button"
                  disabled={busy}
                  onClick={() => onSend(s)}
                  className="block w-full rounded-md border border-line px-3 py-2 text-left text-sm transition-colors hover:border-ai/50 hover:bg-ai/5 disabled:opacity-50"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}
        {messages.map((m) => (
          <MessageBubble key={m.id} m={m} />
        ))}
        {live && <LiveBubble stream={live} />}
      </div>

      <div className="border-t border-line p-3">
        <div className="flex items-end gap-2">
          <Textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={onKeyDown}
            rows={Math.min(6, Math.max(2, draft.split("\n").length))}
            placeholder={L.placeholder}
            aria-label={L.placeholder}
            maxLength={8000}
            className="min-w-0 flex-1 resize-none"
          />
          {busy ? (
            <Button
              variant="outline"
              onClick={onStop}
              aria-label={L.stop}
              title={L.stop}
              className="shrink-0 whitespace-nowrap"
            >
              <CircleStop className="h-4 w-4" aria-hidden />
              {L.stop}
            </Button>
          ) : (
            <Button
              onClick={submit}
              disabled={!draft.trim()}
              aria-label={L.send}
              title={L.send}
              className="shrink-0 whitespace-nowrap"
            >
              <Send className="h-4 w-4" aria-hidden />
              {L.send}
            </Button>
          )}
        </div>
        <div className="mt-1.5 flex flex-wrap justify-between gap-2 text-[11px] text-muted">
          <span>{L.safety}</span>
          <span>{L.hint}</span>
        </div>
      </div>
    </div>
  );
}
