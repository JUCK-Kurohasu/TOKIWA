/**
 * Evidence viewer for normalized events (schemas/events.py). HTTP events are rendered as a formatted
 * request/response; deception / LLM-app / IDS / port / process sections are shown when present.
 *
 * SECURITY: every field here is attacker-controlled telemetry. It is rendered as plain text only
 * (React escaping, no dangerouslySetInnerHTML, no clickable URLs from the payload).
 */
import { Braces, ChevronDown, ChevronRight, Sparkles } from "lucide-react";
import { type ReactNode, useState } from "react";
import { Link } from "react-router";
import type { HttpInfo, TkEvent } from "@/api/types";
import { Badge } from "@/components/ui";
import { formatDateTime } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { JsonView } from "./index";
import { fmt } from "./opsLabels";

const BODY_PREVIEW_CHARS = 4000;

function endpoint(e?: { ip?: string | null; port?: number | null; hostname?: string | null } | null): string {
  if (!e) return "";
  const host = e.ip ?? e.hostname ?? "";
  if (!host) return "";
  return e.port ? `${host.includes(":") ? `[${host}]` : host}:${e.port}` : host;
}

function statusTone(status?: number | null): string {
  if (status == null) return "text-muted";
  if (status >= 500) return "text-sev-critical";
  if (status >= 400) return "text-sev-high";
  if (status >= 300) return "text-sev-low";
  return "text-accent";
}

function prettyBody(body: string, contentType?: string | null): string {
  const looksJson = (contentType ?? "").includes("json") || /^\s*[[{]/.test(body);
  if (!looksJson) return body;
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

function headerEntries(http: HttpInfo): [string, string][] {
  const headers = http.headers ?? {};
  const keys = Object.keys(headers);
  if (!http.header_order?.length) return keys.map((k) => [k, headers[k]]);
  // Keep the observed header order (a client fingerprint signal), then any remaining keys.
  const lower = new Map(keys.map((k) => [k.toLowerCase(), k]));
  const seen = new Set<string>();
  const out: [string, string][] = [];
  for (const name of http.header_order) {
    const k = lower.get(name.toLowerCase());
    if (k && !seen.has(k)) {
      seen.add(k);
      out.push([k, headers[k]]);
    }
  }
  for (const k of keys) if (!seen.has(k)) out.push([k, headers[k]]);
  return out;
}

/** Formatted HTTP request line + headers + body, and response summary. */
export function HttpView({ http }: { http: HttpInfo }) {
  const L = useLocal({
    ja: {
      request: "リクエスト",
      response: "レスポンス",
      showAll: "全文を表示（{n} 文字）",
      collapse: "折りたたむ",
      noBody: "ボディなし",
      bodyNotCaptured: "ボディ {n} バイト（未取得）",
    },
    en: {
      request: "Request",
      response: "Response",
      showAll: "Show all ({n} chars)",
      collapse: "Collapse",
      noBody: "No body",
      bodyNotCaptured: "Body {n} bytes (not captured)",
    },
  });
  const [full, setFull] = useState(false);
  const target = `${http.path ?? "/"}${http.query ? `?${http.query}` : ""}`;
  const proto = http.http_version ? `HTTP/${http.http_version.replace(/^HTTP\//i, "")}` : "";
  const headers = headerEntries(http);
  const hasHost = headers.some(([k]) => k.toLowerCase() === "host");
  const body = http.request_body ? prettyBody(http.request_body, http.content_type) : "";
  const truncated = body.length > BODY_PREVIEW_CHARS && !full;

  return (
    <div className="space-y-2">
      <div>
        <div className="mb-1 text-[11px] font-medium text-muted">{L.request}</div>
        <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap break-all rounded-md border border-line bg-bg p-3 font-mono text-xs leading-relaxed">
          <span className="font-semibold text-accent">{http.method ?? "?"}</span> <span>{target}</span>{" "}
          <span className="text-muted">{proto}</span>
          {"\n"}
          {!hasHost && http.host && (
            <>
              <span className="text-sev-low">Host</span>: {http.host}
              {"\n"}
            </>
          )}
          {headers.map(([k, v]) => (
            <span key={k}>
              <span className="text-sev-low">{k}</span>: {v}
              {"\n"}
            </span>
          ))}
          {body ? (
            <>
              {"\n"}
              {truncated ? body.slice(0, BODY_PREVIEW_CHARS) : body}
              {truncated && <span className="text-muted">{"\n…"}</span>}
            </>
          ) : http.request_body_size ? (
            <span className="text-muted">
              {"\n"}
              {fmt(L.bodyNotCaptured, { n: http.request_body_size })}
            </span>
          ) : null}
        </pre>
        {body.length > BODY_PREVIEW_CHARS && (
          <button
            type="button"
            className="mt-1 text-xs text-accent hover:underline"
            onClick={() => setFull((f) => !f)}
          >
            {full ? L.collapse : fmt(L.showAll, { n: body.length })}
          </button>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-md border border-line bg-surface-2/50 px-3 py-1.5 font-mono text-xs">
        <span className="text-muted">{L.response}</span>
        <span className={cn("font-semibold", statusTone(http.status))}>{http.status ?? "-"}</span>
        {http.response_content_type && <span className="text-muted">{http.response_content_type}</span>}
        {http.response_size != null && <span>{http.response_size} B</span>}
        {http.duration_ms != null && <span>{Math.round(http.duration_ms)} ms</span>}
      </div>
    </div>
  );
}

function KV({ rows }: { rows: [string, unknown][] }) {
  const visible = rows.filter(([, v]) => v !== null && v !== undefined && v !== "");
  if (!visible.length) return null;
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-xs">
      {visible.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted">{k}</dt>
          <dd className="min-w-0 break-all font-mono">
            {Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function summaryLine(e: TkEvent): string {
  if (e.http) {
    const h = e.http;
    return `${h.method ?? ""} ${h.path ?? ""}${h.query ? `?${h.query}` : ""} → ${h.status ?? "-"}`.trim();
  }
  if (e.deception)
    return `${String(e.deception.asset_kind ?? "deception")} ${String(e.deception.detail ?? "")}`;
  if (e.llm_app)
    return `${String(e.llm_app.app ?? "llm_app")}: ${String(e.llm_app.prompt ?? "").slice(0, 120)}`;
  return e.message ?? e.dataset;
}

/** One evidence event: collapsible header + formatted body. Anchor id `ev-<id>` for deep links. */
export function EventDetail({
  event,
  cited,
  defaultOpen = false,
}: {
  event: TkEvent;
  /** The LLM triage cited this event as evidence. */
  cited?: boolean;
  defaultOpen?: boolean;
}) {
  const L = useLocal({
    ja: {
      cited: "LLM が根拠に引用",
      raw: "生データ (JSON)",
      hideRaw: "生データを隠す",
      session: "セッション",
      deception: "デセプション",
      llmApp: "LLM アプリへのプロンプト",
      ids: "IDS",
      port: "ポート",
      process: "プロセス",
      message: "メッセージ",
    },
    en: {
      cited: "Cited by LLM",
      raw: "Raw (JSON)",
      hideRaw: "Hide raw",
      session: "Session",
      deception: "Deception",
      llmApp: "Prompt to LLM app",
      ids: "IDS",
      port: "Port",
      process: "Process",
      message: "Message",
    },
  });
  const [open, setOpen] = useState(defaultOpen);
  const [raw, setRaw] = useState(false);
  const src = endpoint(event.source);
  const dst = endpoint(event.destination);

  return (
    <div
      id={`ev-${event.id}`}
      className={cn(
        "scroll-mt-20 rounded-md border bg-surface target:ring-2 target:ring-ai",
        cited ? "border-ai/50" : "border-line",
      )}
    >
      <button
        type="button"
        className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-surface-2/60"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        {open ? (
          <ChevronDown className="h-4 w-4 shrink-0 text-muted" aria-hidden />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0 text-muted" aria-hidden />
        )}
        <Badge>{event.kind}</Badge>
        <span className="shrink-0 font-mono text-[11px] text-muted">{formatDateTime(event.timestamp)}</span>
        {src && <span className="shrink-0 font-mono text-xs">{src}</span>}
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted">{summaryLine(event)}</span>
        {cited && (
          <Badge tone="ai" className="shrink-0">
            <Sparkles className="h-3 w-3" aria-hidden />
            {L.cited}
          </Badge>
        )}
      </button>

      {open && (
        <div className="space-y-3 border-t border-line px-3 py-3">
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted">
            <span className="font-mono">{event.id}</span>
            <span>{event.dataset}</span>
            {event.sensor_id && <span>sensor: {event.sensor_id}</span>}
            {dst && (
              <span className="font-mono">
                {src || "?"} → {dst}
              </span>
            )}
            {event.session_id && (
              <Link
                to={`/sessions/${encodeURIComponent(event.session_id)}`}
                className="text-accent hover:underline"
              >
                {L.session}: {event.session_id.slice(0, 12)}
              </Link>
            )}
            {event.source?.geo_country && <span>{event.source.geo_country}</span>}
            {event.source?.asn_org && <span>{event.source.asn_org}</span>}
          </div>

          {event.http && <HttpView http={event.http} />}

          {event.deception && (
            <Section title={L.deception}>
              <KV
                rows={[
                  ["asset_id", event.deception.asset_id],
                  ["asset_kind", event.deception.asset_kind],
                  ["token", event.deception.token],
                  ["detail", event.deception.detail],
                ]}
              />
            </Section>
          )}

          {event.llm_app && (
            <Section title={L.llmApp}>
              <KV
                rows={[
                  ["app", event.llm_app.app],
                  ["model", event.llm_app.model],
                  ["role", event.llm_app.role],
                  ["tools", event.llm_app.tool_names],
                ]}
              />
              {typeof event.llm_app.prompt === "string" && event.llm_app.prompt && (
                <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-md border border-line bg-bg p-3 font-mono text-xs">
                  {event.llm_app.prompt}
                </pre>
              )}
            </Section>
          )}

          {event.ids && (
            <Section title={L.ids}>
              <KV rows={Object.entries(event.ids)} />
            </Section>
          )}

          {event.port && (
            <Section title={L.port}>
              {event.port.change && <div className="mb-1 text-xs">{event.port.change}</div>}
              {event.port.socket && (
                <KV
                  rows={[
                    ["protocol", event.port.socket.protocol],
                    ["bind", `${event.port.socket.bind_ip}:${event.port.socket.port}`],
                    ["process", event.port.socket.process?.name],
                  ]}
                />
              )}
              {event.port.listeners && event.port.listeners.length > 0 && (
                <div className="mt-1 font-mono text-xs text-muted">
                  {event.port.listeners
                    .slice(0, 30)
                    .map(
                      (s) =>
                        `${s.protocol} ${s.bind_ip}:${s.port}${s.process?.name ? ` (${s.process.name})` : ""}`,
                    )
                    .join("\n")}
                </div>
              )}
            </Section>
          )}

          {event.process && (
            <Section title={L.process}>
              <KV
                rows={[
                  ["pid", event.process.pid],
                  ["name", event.process.name],
                  ["user", event.process.username],
                  ["cmdline", event.process.cmdline],
                ]}
              />
            </Section>
          )}

          {event.message && !event.http && (
            <Section title={L.message}>
              <p className="whitespace-pre-wrap break-all font-mono text-xs">{event.message}</p>
            </Section>
          )}

          <div>
            <button
              type="button"
              className="inline-flex items-center gap-1 text-xs text-muted hover:text-fg"
              onClick={() => setRaw((r) => !r)}
              aria-expanded={raw}
            >
              <Braces className="h-3.5 w-3.5" aria-hidden />
              {raw ? L.hideRaw : L.raw}
            </button>
            {raw && <JsonView value={event} className="mt-2 max-h-80" />}
          </div>
        </div>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <div className="mb-1 text-[11px] font-medium text-muted">{title}</div>
      {children}
    </div>
  );
}

/** Evidence list for an alert: cited events are flagged; ids referenced but not returned are listed. */
export function EvidenceList({
  events,
  expectedIds = [],
  citedIds = [],
}: {
  events: TkEvent[];
  expectedIds?: string[];
  citedIds?: string[];
}) {
  const L = useLocal({
    ja: {
      empty: "証拠イベントはありません",
      missing: "{n} 件の証拠イベントは取得できませんでした（保持期間外の可能性）",
    },
    en: {
      empty: "No evidence events",
      missing: "{n} evidence event(s) could not be loaded (possibly past retention)",
    },
  });
  const cited = new Set(citedIds);
  const present = new Set(events.map((e) => e.id));
  const missing = expectedIds.filter((id) => !present.has(id));
  if (!events.length && !missing.length)
    return <p className="py-4 text-center text-sm text-muted">{L.empty}</p>;
  return (
    <div className="space-y-2">
      {events.map((e, i) => (
        <EventDetail key={e.id} event={e} cited={cited.has(e.id)} defaultOpen={i < 2} />
      ))}
      {missing.length > 0 && (
        <p className="text-xs text-muted" title={missing.join("\n")}>
          {fmt(L.missing, { n: missing.length })}
        </p>
      )}
    </div>
  );
}
