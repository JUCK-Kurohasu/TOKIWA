/**
 * Events explorer (`/events`): filters kept in the URL, paged table, detail drawer (`?event=<id>`).
 * Data: GET /events, GET /events/{id}, GET /events/stats/timeline; SSE `event.ingested` -> "new events" banner.
 */

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Filter, RotateCcw, ScrollText, Search, Sparkles, X } from "lucide-react";
import { type FormEvent, useEffect, useMemo, useState } from "react";
import { api } from "@/api/client";
import type { EventKind, Page, TkEvent } from "@/api/types";
import { Mono, PageHeader } from "@/components/common";
import { DataState, RowsSkeleton } from "@/components/common/DataState";
import { EventDrawer, endpointText, isAiTag, KindBadge } from "@/components/common/EventInspector";
import { HttpStatusBadge } from "@/components/common/HttpStatusBadge";
import { LiveDot } from "@/components/common/LiveDot";
import { PagerBar } from "@/components/common/PagerBar";
import { Badge, Button, Card, Input, Label, Select, Table, TBody, TD, TH, THead, TR } from "@/components/ui";
import { retryUnlessClientError } from "@/hooks/useApi";
import { useLiveStream } from "@/hooks/useLiveStream";
import { useSearchState } from "@/hooks/useSearchState";
import { formatDateTime, formatNumber } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import type { AppRoute } from "@/routes";
import { VolumeStrip } from "./VolumeStrip";

const KINDS: EventKind[] = [
  "http",
  "port_snapshot",
  "port_change",
  "connection",
  "ids_alert",
  "dns",
  "process",
  "auth",
  "deception",
  "llm_app",
  "custom",
];

const RANGES = ["15m", "1h", "6h", "24h", "7d", "30d", "all", "custom"] as const;
type Range = (typeof RANGES)[number];
const RANGE_MS: Record<Exclude<Range, "all" | "custom">, number> = {
  "15m": 15 * 60_000,
  "1h": 3600_000,
  "6h": 6 * 3600_000,
  "24h": 24 * 3600_000,
  "7d": 7 * 86400_000,
  "30d": 30 * 86400_000,
};
/** Volume strip window per range (backend caps the timeline at 7 days). */
const STRIP: Record<Range, [hours: number, bucketMinutes: number]> = {
  "15m": [1, 5],
  "1h": [1, 5],
  "6h": [6, 15],
  "24h": [24, 60],
  "7d": [168, 360],
  "30d": [168, 360],
  all: [24, 60],
  custom: [24, 60],
};

const KEYS = [
  "kind",
  "dataset",
  "source_ip",
  "session_id",
  "host",
  "q",
  "range",
  "since",
  "until",
  "offset",
  "limit",
  "event",
] as const;
const TEXT_KEYS = ["q", "source_ip", "session_id", "host", "dataset"] as const;
type TextKey = (typeof TEXT_KEYS)[number];

const strings = {
  ja: {
    title: "イベント",
    desc: "正規化テレメトリの検索。行をクリックすると HTTP リクエストの詳細を表示します。",
    kind: "種別",
    all: "すべて",
    q: "パス / UA を検索",
    source_ip: "送信元 IP",
    session_id: "セッション ID",
    host: "ホスト",
    dataset: "データセット",
    range: "期間",
    since: "開始",
    until: "終了",
    apply: "適用",
    reset: "リセット",
    time: "時刻",
    source: "送信元",
    summary: "概要",
    session: "セッション",
    empty: "条件に一致するイベントはありません",
    emptyHint: "期間を広げるか、フィルタを外してみてください",
    newEvents: "件の新しいイベントがあります",
    show: "表示",
    filterBy: "この値で絞り込む",
    open: "詳細",
    matches: "件",
  },
  en: {
    title: "Events",
    desc: "Search normalized telemetry. Click a row to inspect the full HTTP request.",
    kind: "Kind",
    all: "All",
    q: "Search path / UA",
    source_ip: "Source IP",
    session_id: "Session ID",
    host: "Host",
    dataset: "Dataset",
    range: "Range",
    since: "From",
    until: "To",
    apply: "Apply",
    reset: "Reset",
    time: "Time",
    source: "Source",
    summary: "Summary",
    session: "Session",
    empty: "No events match these filters",
    emptyHint: "Widen the time range or remove a filter",
    newEvents: "new events",
    show: "Show",
    filterBy: "Filter by this value",
    open: "Details",
    matches: "matches",
  },
};

const rangeLabels: { ja: Record<Range, string>; en: Record<Range, string> } = {
  ja: {
    "15m": "15分",
    "1h": "1時間",
    "6h": "6時間",
    "24h": "24時間",
    "7d": "7日",
    "30d": "30日",
    all: "全期間",
    custom: "指定",
  },
  en: {
    "15m": "15m",
    "1h": "1h",
    "6h": "6h",
    "24h": "24h",
    "7d": "7d",
    "30d": "30d",
    all: "All time",
    custom: "Custom",
  },
};

/** One-line human summary of an event for the table. */
function summarize(ev: TkEvent): { text: string; status?: number | null; method?: string | null } {
  if (ev.http) {
    const path = `${ev.http.path ?? ""}${ev.http.query ? `?${ev.http.query}` : ""}`;
    return { text: path || "/", status: ev.http.status, method: ev.http.method };
  }
  const pick = (o: Record<string, unknown> | null | undefined, ...keys: string[]) => {
    for (const k of keys) {
      const v = o?.[k];
      if (typeof v === "string" && v) return v;
    }
    return undefined;
  };
  if (ev.port?.change && ev.port.socket)
    return {
      text: `${ev.port.change} ${ev.port.socket.protocol}/${ev.port.socket.port} ${ev.port.socket.process?.name ?? ""}`,
    };
  if (ev.port?.listeners?.length) return { text: `${ev.port.listeners.length} listeners` };
  const text =
    pick(ev.ids, "signature") ??
    pick(ev.deception, "detail", "asset_kind") ??
    pick(ev.llm_app, "prompt") ??
    ev.message ??
    (ev.destination ? `→ ${endpointText(ev.destination)}` : "");
  return { text: text ?? "" };
}

function toIso(local: string): string | undefined {
  if (!local) return undefined;
  const t = Date.parse(local);
  return Number.isNaN(t) ? undefined : new Date(t).toISOString();
}

function toLocalInput(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function EventsPage() {
  const L = useLocal(strings);
  const RL = useLocal(rangeLabels);
  const [f, setF] = useSearchState(KEYS);
  const range = (RANGES as readonly string[]).includes(f.range) ? (f.range as Range) : "24h";
  const limit = Number(f.limit) || 50;
  const offset = Number(f.offset) || 0;

  // Text inputs are drafts applied on submit, so typing does not fire a query per keystroke.
  const [draft, setDraft] = useState<Record<TextKey, string>>(() => ({
    q: f.q,
    source_ip: f.source_ip,
    session_id: f.session_id,
    host: f.host,
    dataset: f.dataset,
  }));
  useEffect(() => {
    setDraft({ q: f.q, source_ip: f.source_ip, session_id: f.session_id, host: f.host, dataset: f.dataset });
  }, [f.q, f.source_ip, f.session_id, f.host, f.dataset]);

  const filterKey = useMemo(
    () => ({
      kind: f.kind,
      dataset: f.dataset,
      source_ip: f.source_ip,
      session_id: f.session_id,
      host: f.host,
      q: f.q,
      range,
      since: f.since,
      until: f.until,
      limit,
      offset,
    }),
    [f.kind, f.dataset, f.source_ip, f.session_id, f.host, f.q, range, f.since, f.until, limit, offset],
  );

  const [newCount, setNewCount] = useState(0);
  const events = useEventsQuery(filterKey, () => setNewCount(0));

  const { status } = useLiveStream({
    topics: ["event.ingested"],
    onMessage: (m) => {
      const n = (m.data as { count?: unknown } | null)?.count;
      setNewCount((c) => c + (typeof n === "number" ? n : 1));
    },
  });

  const selected = f.event || null;
  const selectedEvent = events.data?.items.find((e) => e.id === selected) ?? null;
  const activeFilters = TEXT_KEYS.filter((k) => f[k]).length + (f.kind ? 1 : 0);

  function submit(e: FormEvent) {
    e.preventDefault();
    setF({ ...draft, offset: null });
  }

  function reset() {
    setF({
      kind: null,
      dataset: null,
      source_ip: null,
      session_id: null,
      host: null,
      q: null,
      range: null,
      since: null,
      until: null,
      offset: null,
    });
  }

  const [stripHours, stripBucket] = STRIP[range];

  return (
    <div className="space-y-3">
      <PageHeader title={L.title} description={L.desc} actions={<LiveDot status={status} />} />

      {/* One filter row above everything it scopes */}
      <Card className="p-3">
        <form onSubmit={submit} className="flex flex-wrap items-end gap-2">
          <div className="min-w-[220px] flex-[2]">
            <Label htmlFor="ev-q">{L.q}</Label>
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted" />
              <Input
                id="ev-q"
                value={draft.q}
                onChange={(e) => setDraft({ ...draft, q: e.target.value })}
                placeholder="/api/login, sqlmap, python-httpx…"
                className="pl-8"
              />
            </div>
          </div>
          <div className="w-[130px]">
            <Label htmlFor="ev-kind">{L.kind}</Label>
            <Select
              id="ev-kind"
              value={f.kind}
              onChange={(e) => setF({ kind: e.target.value, offset: null })}
              className="w-full"
            >
              <option value="">{L.all}</option>
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </Select>
          </div>
          <div className="w-[150px]">
            <Label htmlFor="ev-ip">{L.source_ip}</Label>
            <Input
              id="ev-ip"
              value={draft.source_ip}
              onChange={(e) => setDraft({ ...draft, source_ip: e.target.value })}
              className="font-mono text-xs"
            />
          </div>
          <div className="w-[170px]">
            <Label htmlFor="ev-session">{L.session_id}</Label>
            <Input
              id="ev-session"
              value={draft.session_id}
              onChange={(e) => setDraft({ ...draft, session_id: e.target.value })}
              className="font-mono text-xs"
            />
          </div>
          <div className="w-[130px]">
            <Label htmlFor="ev-host">{L.host}</Label>
            <Input
              id="ev-host"
              value={draft.host}
              onChange={(e) => setDraft({ ...draft, host: e.target.value })}
            />
          </div>
          <div className="w-[130px]">
            <Label htmlFor="ev-dataset">{L.dataset}</Label>
            <Input
              id="ev-dataset"
              value={draft.dataset}
              onChange={(e) => setDraft({ ...draft, dataset: e.target.value })}
              placeholder="gate.http"
              className="font-mono text-xs"
            />
          </div>
          <div className="w-[110px]">
            <Label htmlFor="ev-range">{L.range}</Label>
            <Select
              id="ev-range"
              value={range}
              onChange={(e) =>
                setF({ range: e.target.value === "24h" ? null : e.target.value, offset: null })
              }
              className="w-full"
            >
              {RANGES.map((r) => (
                <option key={r} value={r}>
                  {RL[r]}
                </option>
              ))}
            </Select>
          </div>
          {range === "custom" && (
            <>
              <div>
                <Label htmlFor="ev-since">{L.since}</Label>
                <Input
                  id="ev-since"
                  type="datetime-local"
                  value={f.since}
                  onChange={(e) => setF({ since: e.target.value, offset: null })}
                  className="w-[190px]"
                />
              </div>
              <div>
                <Label htmlFor="ev-until">{L.until}</Label>
                <Input
                  id="ev-until"
                  type="datetime-local"
                  value={f.until}
                  onChange={(e) => setF({ until: e.target.value, offset: null })}
                  className="w-[190px]"
                />
              </div>
            </>
          )}
          <div className="flex gap-1.5">
            <Button type="submit">
              <Filter className="h-3.5 w-3.5" />
              {L.apply}
            </Button>
            <Button
              type="button"
              variant="ghost"
              onClick={reset}
              disabled={activeFilters === 0 && range === "24h"}
            >
              <RotateCcw className="h-3.5 w-3.5" />
              {L.reset}
            </Button>
          </div>
        </form>
      </Card>

      <VolumeStrip
        hours={stripHours}
        bucketMinutes={stripBucket}
        onPick={(from, to) =>
          setF({ range: "custom", since: toLocalInput(from), until: toLocalInput(to), offset: null })
        }
      />

      {newCount > 0 && offset === 0 && (
        <div className="flex items-center justify-between gap-2 rounded-md border border-accent/30 bg-accent-soft px-3 py-1.5 text-xs text-accent">
          <span className="flex items-center gap-1.5">
            <Sparkles className="h-3.5 w-3.5" />
            <span className="tabular-nums">{formatNumber(newCount)}</span> {L.newEvents}
          </span>
          <span className="flex items-center gap-1">
            <Button size="sm" variant="outline" onClick={() => events.refetch()}>
              {L.show}
            </Button>
            <Button size="icon" variant="ghost" onClick={() => setNewCount(0)} aria-label="dismiss">
              <X className="h-3.5 w-3.5" />
            </Button>
          </span>
        </div>
      )}

      <Card>
        <DataState
          loading={events.isLoading}
          error={events.error}
          empty={!!events.data && events.data.items.length === 0}
          emptyTitle={L.empty}
          emptyHint={L.emptyHint}
          emptyIcon={<ScrollText className="h-6 w-6 opacity-60" />}
          skeleton={<RowsSkeleton rows={10} className="p-4" />}
          onRetry={() => events.refetch()}
          className="p-4"
        >
          <div className={cn("transition-opacity", events.isFetching && !events.isLoading && "opacity-70")}>
            <Table className="table-fixed">
              <THead>
                <tr>
                  <TH className="w-[150px]">{L.time}</TH>
                  <TH className="w-[110px]">{L.kind}</TH>
                  <TH className="w-[150px]">{L.source}</TH>
                  <TH>{L.summary}</TH>
                  <TH className="hidden w-[130px] lg:table-cell">{L.session}</TH>
                  <TH className="hidden w-[130px] xl:table-cell">{L.dataset}</TH>
                </tr>
              </THead>
              <TBody>
                {events.data?.items.map((ev) => {
                  const s = summarize(ev);
                  const aiTags = (ev.tags ?? []).filter(isAiTag);
                  const isSel = ev.id === selected;
                  return (
                    <TR
                      key={ev.id}
                      onClick={() => setF({ event: ev.id }, false)}
                      className={cn(
                        "cursor-pointer",
                        isSel && "bg-accent-soft/60 hover:bg-accent-soft/60",
                        ev.kind === "llm_app" || aiTags.length ? "border-l-2 border-l-ai" : "",
                      )}
                    >
                      <TD className="whitespace-nowrap text-xs">
                        <button
                          type="button"
                          className="text-left tabular-nums hover:text-accent focus-visible:outline-2 focus-visible:outline-accent"
                          onClick={(e) => {
                            e.stopPropagation();
                            setF({ event: ev.id }, false);
                          }}
                          title={`${L.open}: ${ev.id}`}
                        >
                          {formatDateTime(ev.timestamp)}
                        </button>
                      </TD>
                      <TD>
                        <KindBadge kind={ev.kind} />
                      </TD>
                      <TD className="truncate">
                        {ev.source?.ip ? (
                          <button
                            type="button"
                            className="truncate font-mono text-xs hover:text-accent hover:underline"
                            title={L.filterBy}
                            onClick={(e) => {
                              e.stopPropagation();
                              setF({ source_ip: ev.source?.ip ?? null, offset: null });
                            }}
                          >
                            {ev.source.ip}
                          </button>
                        ) : (
                          <span className="text-muted">-</span>
                        )}
                      </TD>
                      <TD className="min-w-0">
                        <div className="flex min-w-0 items-center gap-2">
                          {s.method && (
                            <span className="shrink-0 font-mono text-xs font-semibold">{s.method}</span>
                          )}
                          <span className="truncate font-mono text-xs" title={s.text}>
                            {s.text || <span className="text-muted">-</span>}
                          </span>
                          {ev.http && <HttpStatusBadge status={s.status} className="shrink-0" />}
                          {aiTags.slice(0, 2).map((t) => (
                            <Badge key={t} tone="ai" className="shrink-0 font-mono">
                              {t}
                            </Badge>
                          ))}
                        </div>
                      </TD>
                      <TD className="hidden truncate lg:table-cell">
                        {ev.session_id ? (
                          <button
                            type="button"
                            className="font-mono text-xs text-muted hover:text-ai hover:underline"
                            title={L.filterBy}
                            onClick={(e) => {
                              e.stopPropagation();
                              setF({ session_id: ev.session_id ?? null, offset: null });
                            }}
                          >
                            {ev.session_id.slice(0, 10)}…
                          </button>
                        ) : (
                          <span className="text-muted">-</span>
                        )}
                      </TD>
                      <TD className="hidden truncate xl:table-cell">
                        <Mono className="text-muted">{ev.dataset}</Mono>
                      </TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          </div>
          {events.data && (
            <PagerBar
              className="border-t border-line px-4 py-2"
              total={events.data.total}
              limit={limit}
              offset={offset}
              busy={events.isFetching}
              onOffset={(o) => setF({ offset: o || null })}
              onLimit={(n) => setF({ limit: n === 50 ? null : n, offset: null })}
            />
          )}
        </DataState>
      </Card>

      <EventDrawer eventId={selected} event={selectedEvent} onClose={() => setF({ event: null }, false)} />
    </div>
  );
}

/** List query with since/until resolved at fetch time from the selected range. */
function useEventsQuery(
  k: {
    kind: string;
    dataset: string;
    source_ip: string;
    session_id: string;
    host: string;
    q: string;
    range: Range;
    since: string;
    until: string;
    limit: number;
    offset: number;
  },
  onFetched: () => void,
) {
  // Params are computed at fetch time so relative ranges ("last 1h") are re-evaluated on every refresh.
  return useQuery<Page<TkEvent>, Error>({
    queryKey: ["events", "list", k],
    placeholderData: keepPreviousData,
    retry: retryUnlessClientError,
    queryFn: async () => {
      let since: string | undefined;
      let until: string | undefined;
      if (k.range === "custom") {
        since = toIso(k.since);
        until = toIso(k.until);
      } else if (k.range !== "all") {
        since = new Date(Date.now() - RANGE_MS[k.range]).toISOString();
      }
      const res = await api.get<Page<TkEvent>>("/events", {
        kind: k.kind,
        dataset: k.dataset,
        source_ip: k.source_ip,
        session_id: k.session_id,
        host: k.host,
        q: k.q,
        since,
        until,
        limit: k.limit,
        offset: k.offset,
      });
      if (k.offset === 0) onFetched();
      return res;
    },
  });
}

export const route: AppRoute = {
  path: "/events",
  component: EventsPage,
  nav: {
    label: { ja: "イベント", en: "Events" },
    icon: ScrollText,
    section: "investigate",
    order: 50,
  },
};
