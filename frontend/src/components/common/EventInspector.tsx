/**
 * Event detail view (overview / HTTP request / raw JSON) and a drawer wrapper.
 *
 * Every string in an event can be attacker-controlled (URL, headers, UA, body). It is rendered as plain
 * React text only — never as HTML.
 */
import { ExternalLink, ShieldAlert } from "lucide-react";
import { type ReactNode, useMemo, useState } from "react";
import { Link } from "react-router";
import type { Endpoint, TkEvent } from "@/api/types";
import { JsonView, Mono } from "@/components/common";
import { Badge, Table, Tabs, TBody, TD, TH, THead, TR } from "@/components/ui";
import { useApiQuery } from "@/hooks/useApi";
import { formatDateTime, timeAgo } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { DataState } from "./DataState";
import { HttpStatusBadge } from "./HttpStatusBadge";
import { formatBytes, formatMs } from "./numfmt";
import { CopyButton } from "./SecretReveal";
import { SideDrawer } from "./SideDrawer";

const strings = {
  ja: {
    overview: "概要",
    http: "HTTP",
    json: "JSON",
    source: "送信元",
    destination: "宛先",
    host: "ホスト",
    sensor: "センサー",
    session: "セッション",
    asset: "資産",
    ingested: "取り込み",
    tags: "タグ",
    labels: "ラベル",
    message: "メッセージ",
    request: "リクエスト",
    response: "レスポンス",
    body: "ボディ",
    noBody: "ボディなし（またはセンサーが取得していません）",
    truncated: "先頭のみ表示",
    headers: "ヘッダ",
    status: "ステータス",
    size: "サイズ",
    duration: "応答時間",
    contentType: "Content-Type",
    untrusted: "表示値は送信元が制御できる非信頼データです（センサー側でマスク済み）。",
    listeners: "リスニングソケット",
    change: "変化",
    protocol: "プロトコル",
    bind: "バインド",
    port: "ポート",
    process: "プロセス",
    title: "イベント詳細",
    openSession: "セッションを開く",
  },
  en: {
    overview: "Overview",
    http: "HTTP",
    json: "JSON",
    source: "Source",
    destination: "Destination",
    host: "Host",
    sensor: "Sensor",
    session: "Session",
    asset: "Asset",
    ingested: "Ingested",
    tags: "Tags",
    labels: "Labels",
    message: "Message",
    request: "Request",
    response: "Response",
    body: "Body",
    noBody: "No body (or not captured by this sensor)",
    truncated: "truncated",
    headers: "Headers",
    status: "Status",
    size: "Size",
    duration: "Duration",
    contentType: "Content-Type",
    untrusted: "Values are untrusted, sender-controlled data (redacted by the sensor).",
    listeners: "Listening sockets",
    change: "Change",
    protocol: "Proto",
    bind: "Bind",
    port: "Port",
    process: "Process",
    title: "Event details",
    openSession: "Open session",
  },
};

export function endpointText(ep: Endpoint | null | undefined): string {
  if (!ep) return "-";
  const ip = ep.ip ?? ep.hostname ?? "-";
  const base = ep.port != null ? (ip.includes(":") ? `[${ip}]:${ep.port}` : `${ip}:${ep.port}`) : ip;
  return base;
}

/** Tags that indicate AI/LLM attribution are highlighted in purple. */
export function isAiTag(tag: string): boolean {
  const t = tag.toLowerCase();
  return t === "ai" || t.startsWith("ai.") || t.startsWith("ai_") || t.startsWith("ai-") || t.includes("llm");
}

export function KindBadge({ kind }: { kind: string }) {
  const ai = kind === "llm_app";
  const deception = kind === "deception";
  return (
    <Badge tone={ai ? "ai" : deception ? "warn" : "neutral"} className="font-mono">
      {kind}
    </Badge>
  );
}

function KV({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] text-muted">{label}</dt>
      <dd className="mt-0.5 break-words text-xs">{children}</dd>
    </div>
  );
}

function Section({
  title,
  children,
  className,
}: {
  title: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("space-y-2", className)}>
      <h4 className="text-[11px] font-semibold uppercase tracking-wider text-muted">{title}</h4>
      {children}
    </section>
  );
}

function renderValue(v: unknown): ReactNode {
  if (v == null || v === "") return <span className="text-muted">-</span>;
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number" || typeof v === "string") return <span className="font-mono">{String(v)}</span>;
  return <span className="font-mono">{JSON.stringify(v)}</span>;
}

/** Generic key/value grid for small nested objects (ids, deception, llm_app, network, process). */
function ObjectGrid({ value }: { value: Record<string, unknown> }) {
  const entries = Object.entries(value).filter(
    ([, v]) => v != null && v !== "" && !(Array.isArray(v) && !v.length),
  );
  if (!entries.length) return <div className="text-xs text-muted">-</div>;
  return (
    <dl className="grid grid-cols-1 gap-x-4 gap-y-2 sm:grid-cols-2">
      {entries.map(([k, v]) => (
        <KV key={k} label={k}>
          {typeof v === "object" && !Array.isArray(v) ? (
            <JsonView value={v} className="max-h-40" />
          ) : (
            renderValue(Array.isArray(v) ? v.join(", ") : v)
          )}
        </KV>
      ))}
    </dl>
  );
}

function prettyBody(body: string, contentType: string | null | undefined): string {
  const looksJson = (contentType ?? "").includes("json") || /^\s*[{[]/.test(body);
  if (!looksJson) return body;
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

function HttpView({ event }: { event: TkEvent }) {
  const L = useLocal(strings);
  const h = event.http;
  if (!h) return null;
  const version = h.http_version
    ? h.http_version.startsWith("HTTP")
      ? h.http_version
      : `HTTP/${h.http_version}`
    : "";
  const target = `${h.path ?? "/"}${h.query ? `?${h.query}` : ""}`;
  const headers = h.headers ?? {};
  const order = [
    ...(h.header_order ?? []).filter((k) => k in headers),
    ...Object.keys(headers).filter((k) => !(h.header_order ?? []).includes(k)),
  ];
  const hasHostHeader = order.some((k) => k.toLowerCase() === "host");
  const body = h.request_body ?? "";
  const truncated = h.request_body_size != null && body.length > 0 && h.request_body_size > body.length;

  return (
    <div className="space-y-5">
      <div className="flex items-start gap-2 rounded-md border border-line bg-surface-2/50 p-2 text-[11px] text-muted">
        <ShieldAlert className="mt-px h-3.5 w-3.5 shrink-0" />
        {L.untrusted}
      </div>
      <Section title={L.request}>
        <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-md border border-line bg-bg p-3 font-mono text-xs leading-relaxed">
          <span className="font-semibold text-accent">{h.method ?? "?"}</span> {target}{" "}
          <span className="text-muted">{version}</span>
          {"\n"}
          {!hasHostHeader && h.host && (
            <>
              <span className="text-muted">host:</span> {h.host}
              {"\n"}
            </>
          )}
          {order.map((k) => (
            <span key={k}>
              <span className="text-muted">{k}:</span> {headers[k]}
              {"\n"}
            </span>
          ))}
        </pre>
      </Section>
      <Section
        title={
          <span className="flex items-center gap-2">
            {L.body}
            {h.content_type && (
              <span className="font-mono normal-case tracking-normal">{h.content_type}</span>
            )}
            {h.request_body_size != null && (
              <span className="normal-case tracking-normal">{formatBytes(h.request_body_size)}</span>
            )}
            {truncated && <Badge tone="warn">{L.truncated}</Badge>}
          </span>
        }
      >
        {body ? (
          <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-md border border-line bg-bg p-3 font-mono text-xs leading-relaxed">
            {prettyBody(body, h.content_type)}
          </pre>
        ) : (
          <div className="text-xs text-muted">{L.noBody}</div>
        )}
      </Section>
      <Section title={L.response}>
        <dl className="grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-4">
          <KV label={L.status}>
            <HttpStatusBadge status={h.status} />
          </KV>
          <KV label={L.size}>{formatBytes(h.response_size)}</KV>
          <KV label={L.duration}>{formatMs(h.duration_ms)}</KV>
          <KV label={L.contentType}>{renderValue(h.response_content_type)}</KV>
        </dl>
      </Section>
    </div>
  );
}

function PortView({ event }: { event: TkEvent }) {
  const L = useLocal(strings);
  const p = event.port;
  if (!p) return null;
  const rows = p.listeners?.length ? p.listeners : p.socket ? [p.socket] : [];
  return (
    <Section title={p.change ? `${L.change}: ${p.change}` : L.listeners}>
      <Table>
        <THead>
          <tr>
            <TH>{L.protocol}</TH>
            <TH>{L.bind}</TH>
            <TH>{L.port}</TH>
            <TH>{L.process}</TH>
          </tr>
        </THead>
        <TBody>
          {rows.map((s, i) => (
            <TR key={i}>
              <TD className="font-mono text-xs">{s.protocol}</TD>
              <TD className="font-mono text-xs">{s.bind_ip}</TD>
              <TD className="font-mono text-xs tabular-nums">{s.port}</TD>
              <TD className="text-xs">
                {s.process?.name ?? "-"}
                {s.process?.pid != null && <span className="ml-1 text-muted">({s.process.pid})</span>}
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </Section>
  );
}

function Overview({ event }: { event: TkEvent }) {
  const L = useLocal(strings);
  const extras: [string, Record<string, unknown> | null | undefined][] = [
    ["ids", event.ids],
    ["deception", event.deception],
    ["llm_app", event.llm_app],
    ["network", event.network],
    ["process", event.process as Record<string, unknown> | null | undefined],
  ];
  return (
    <div className="space-y-5">
      {event.message && (
        <Section title={L.message}>
          <p className="whitespace-pre-wrap break-words text-xs">{event.message}</p>
        </Section>
      )}
      <dl className="grid grid-cols-1 gap-x-4 gap-y-3 sm:grid-cols-2">
        <KV label={L.source}>
          <Mono>{endpointText(event.source)}</Mono>
          {event.source?.geo_country && <span className="ml-1.5 text-muted">{event.source.geo_country}</span>}
          {event.source?.asn_org && (
            <div className="text-muted">
              AS{event.source.asn ?? "?"} {event.source.asn_org}
            </div>
          )}
        </KV>
        <KV label={L.destination}>
          <Mono>{endpointText(event.destination)}</Mono>
        </KV>
        <KV label={L.host}>
          {event.host?.name ?? "-"}
          {event.host?.ip?.length ? (
            <span className="ml-1.5 text-muted">{event.host.ip.join(", ")}</span>
          ) : null}
        </KV>
        <KV label={L.sensor}>
          <Mono>{event.sensor_id ?? "-"}</Mono>
        </KV>
        <KV label={L.session}>
          {event.session_id ? (
            <Link
              to={`/sessions/${event.session_id}`}
              className="inline-flex items-center gap-1 text-accent hover:underline"
            >
              <Mono>{event.session_id.slice(0, 12)}…</Mono>
              <ExternalLink className="h-3 w-3" />
            </Link>
          ) : (
            "-"
          )}
        </KV>
        <KV label={L.asset}>
          <Mono>{event.asset_id ?? "-"}</Mono>
        </KV>
        <KV label={L.ingested}>{formatDateTime(event.ingested_at)}</KV>
      </dl>
      {(event.tags?.length ?? 0) > 0 && (
        <Section title={L.tags}>
          <div className="flex flex-wrap gap-1">
            {event.tags?.map((t) => (
              <Badge key={t} tone={isAiTag(t) ? "ai" : "neutral"} className="font-mono">
                {t}
              </Badge>
            ))}
          </div>
        </Section>
      )}
      {event.labels && Object.keys(event.labels).length > 0 && (
        <Section title={L.labels}>
          <ObjectGrid value={event.labels} />
        </Section>
      )}
      {event.http && (
        <Section title={L.request}>
          <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
            <span className="font-semibold">{event.http.method}</span>
            <span className="break-all">{event.http.path}</span>
            <HttpStatusBadge status={event.http.status} />
            <span className="text-muted">{formatMs(event.http.duration_ms)}</span>
          </div>
          {event.http.user_agent && (
            <div className="break-all text-xs text-muted">{event.http.user_agent}</div>
          )}
        </Section>
      )}
      <PortView event={event} />
      {extras.map(([name, v]) =>
        v && Object.keys(v).length ? (
          <Section key={name} title={name}>
            <ObjectGrid value={v} />
          </Section>
        ) : null,
      )}
    </div>
  );
}

type InspectorTab = "overview" | "http" | "json";

export function EventInspector({ event }: { event: TkEvent }) {
  const L = useLocal(strings);
  const [tab, setTab] = useState<InspectorTab>(event.http ? "http" : "overview");
  const tabs = useMemo(
    () =>
      [
        { value: "overview" as const, label: L.overview },
        ...(event.http ? [{ value: "http" as const, label: L.http }] : []),
        { value: "json" as const, label: L.json },
      ] satisfies { value: InspectorTab; label: string }[],
    [event.http, L],
  );
  return (
    <div>
      <div className="space-y-2 px-4 pt-3">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <KindBadge kind={event.kind} />
          <Mono className="text-muted">{event.dataset}</Mono>
          <span className="text-muted">·</span>
          <span title={event.timestamp}>{formatDateTime(event.timestamp)}</span>
          <span className="text-muted">({timeAgo(event.timestamp)})</span>
        </div>
        <div className="flex items-center gap-2">
          <Mono className="min-w-0 truncate text-muted">{event.id}</Mono>
          <CopyButton text={event.id} label="ID" />
        </div>
      </div>
      <div className="mt-2 px-4">
        <Tabs tabs={tabs} value={tab} onChange={setTab} />
      </div>
      <div className="p-4">
        {tab === "overview" && <Overview event={event} />}
        {tab === "http" && <HttpView event={event} />}
        {tab === "json" && <JsonView value={event} className="max-h-none" />}
      </div>
    </div>
  );
}

/**
 * Drawer that shows an event. Pass `event` when the row data is already loaded; otherwise the event is
 * fetched by id (`GET /events/{id}`), which makes `?event=<id>` deep links work.
 */
export function EventDrawer({
  eventId,
  event,
  onClose,
}: {
  eventId: string | null;
  event?: TkEvent | null;
  onClose: () => void;
}) {
  const L = useLocal(strings);
  const q = useApiQuery<TkEvent>(["events", "detail", eventId], `/events/${eventId}`, undefined, {
    enabled: !!eventId && !event,
  });
  const ev = event ?? q.data ?? null;
  return (
    <SideDrawer
      open={!!eventId}
      onClose={onClose}
      title={ev?.http ? `${ev.http.method ?? ""} ${ev.http.path ?? ""}` : (ev?.message ?? L.title)}
      subtitle={ev ? endpointText(ev.source) : undefined}
      actions={
        ev?.session_id ? (
          <Link
            to={`/sessions/${ev.session_id}`}
            className="hidden items-center gap-1 rounded-md px-2 py-1 text-xs text-ai hover:bg-ai/10 sm:inline-flex"
          >
            {L.openSession}
          </Link>
        ) : null
      }
    >
      {ev ? (
        <EventInspector key={ev.id} event={ev} />
      ) : (
        <DataState loading={q.isLoading} error={q.error} className="p-4" />
      )}
    </SideDrawer>
  );
}
