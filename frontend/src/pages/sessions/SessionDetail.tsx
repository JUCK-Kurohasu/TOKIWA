/** `/sessions/:id`: attribution summary, thinking-rhythm charts, features & indicators, request list. */
import { ArrowLeft, Bot, Flag, ScrollText } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import type { ActorType, TkEvent } from "@/api/types";
import type { SessionDetail } from "@/api/types-core";
import { ActorBadge, Mono, PageHeader } from "@/components/common";
import { DataState } from "@/components/common/DataState";
import { EventDrawer } from "@/components/common/EventInspector";
import { HttpStatusBadge } from "@/components/common/HttpStatusBadge";
import { formatMs, toEpochMs } from "@/components/common/numfmt";
import {
  Badge,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  Skeleton,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/ui";
import { useApiQuery } from "@/hooks/useApi";
import { formatDateTime, formatNumber, pct } from "@/lib/format";
import { useLang, useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { GapHistogram, RhythmScatter } from "./RhythmCharts";
import {
  BURST_MAX_MS,
  buildPoints,
  INDICATOR_KEYS,
  normalizeIndicators,
  rhythmStats,
  THINK_MAX_MS,
  THINK_MIN_MS,
} from "./rhythm";
import { AI_THRESHOLD, ErrorRateBar } from "./SessionsList";

const strings = {
  ja: {
    back: "セッション一覧",
    title: "セッション",
    notFound: "セッションが見つかりません",
    score: "AI エージェントらしさ",
    disclaimer: "振る舞い特徴量にもとづく推定値です。確定判定ではありません。",
    threshold: "しきい値",
    first: "開始",
    last: "最終",
    duration: "継続時間",
    requests: "リクエスト",
    errors: "エラー率",
    paths: "ユニークパス",
    medianGap: "間隔の中央値",
    cv: "間隔のばらつき (CV)",
    burst: "バースト率",
    think: "推論待ち率",
    bimodal: "二峰性リズム",
    yes: "あり",
    no: "なし",
    computed: "タイムラインから UI で算出",
    features: "特徴量",
    featuresDesc: "バックエンドの AI 判定に使われた値",
    indicators: "判定根拠",
    indicatorsDesc: "スコアに寄与した指標（重みの大きい順）",
    noIndicators: "根拠はまだ記録されていません",
    noFeatures: "特徴量はまだありません",
    requestsTitle: "リクエスト",
    requestsDesc: "最大 200 件。行をクリックで詳細",
    time: "時刻",
    gap: "間隔",
    method: "メソッド",
    path: "パス",
    status: "ステータス",
    dur: "応答",
    incident: "インシデント",
    events: "イベントで開く",
    ua: "User-Agent",
    fingerprint: "クライアント指紋",
    noEvents: "リクエストはありません",
    cls_ai_agent: "LLM 駆動の自律エージェントの可能性が高い",
    cls_automated_scanner: "従来型スキャナ（一定で高速、応答に依存しない）",
    cls_human: "人間の操作に近い不規則なリズム",
    cls_benign: "正常な利用者",
    cls_unknown: "判定材料が不足しています",
  },
  en: {
    back: "Sessions",
    title: "Session",
    notFound: "Session not found",
    score: "AI-agent likelihood",
    disclaimer: "Estimated from behavioural features — not a definitive verdict.",
    threshold: "threshold",
    first: "First seen",
    last: "Last seen",
    duration: "Duration",
    requests: "Requests",
    errors: "Error rate",
    paths: "Unique paths",
    medianGap: "Median gap",
    cv: "Gap variability (CV)",
    burst: "Burst share",
    think: "Inference-pause share",
    bimodal: "Bimodal rhythm",
    yes: "Yes",
    no: "No",
    computed: "computed in the UI from the timeline",
    features: "Features",
    featuresDesc: "Values used by the backend AI attribution",
    indicators: "Indicators",
    indicatorsDesc: "What contributed to the score (largest weight first)",
    noIndicators: "No indicators recorded yet",
    noFeatures: "No features yet",
    requestsTitle: "Requests",
    requestsDesc: "Up to 200. Click a row for details",
    time: "Time",
    gap: "Gap",
    method: "Method",
    path: "Path",
    status: "Status",
    dur: "Latency",
    incident: "Incident",
    events: "Open in Events",
    ua: "User-Agent",
    fingerprint: "Client fingerprint",
    noEvents: "No requests",
    cls_ai_agent: "Likely an autonomous LLM-driven agent",
    cls_automated_scanner: "Classic scanner (fast, steady, response-independent)",
    cls_human: "Irregular, human-like rhythm",
    cls_benign: "Benign user",
    cls_unknown: "Not enough evidence",
  },
};

function formatFeature(key: string, v: unknown): string {
  if (v == null) return "-";
  if (typeof v === "number") {
    if (/_ms$|ms$/.test(key)) return formatMs(v);
    if (/(rate|ratio|share|pct|fraction)$/i.test(key) && v >= 0 && v <= 1) return pct(v, 1);
    return Number.isInteger(v) ? formatNumber(v) : v.toFixed(3);
  }
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "string") return v;
  return JSON.stringify(v);
}

function Stat({ label, value, hint, tone }: { label: string; value: string; hint?: string; tone?: "ai" }) {
  return (
    <div className="min-w-0">
      <div className="truncate text-[11px] text-muted" title={hint}>
        {label}
      </div>
      <div className={cn("mt-0.5 text-base font-semibold", tone === "ai" ? "text-ai" : "text-fg")}>
        {value}
      </div>
    </div>
  );
}

export function SessionDetailPage() {
  const L = useLocal(strings);
  const { lang } = useLang();
  const { id = "" } = useParams();
  const q = useApiQuery<SessionDetail>(["sessions", "detail", id], `/sessions/${id}`, undefined, {
    enabled: !!id,
    refetchInterval: 30_000,
  });
  const [openEvent, setOpenEvent] = useState<TkEvent | null>(null);

  const session = q.data?.session;
  const points = useMemo(() => buildPoints(q.data?.timeline, q.data?.events), [q.data]);
  const stats = useMemo(() => rhythmStats(points), [points]);
  const indicators = useMemo(() => normalizeIndicators(session?.features, lang), [session, lang]);
  const featureRows = useMemo(
    () =>
      Object.entries(session?.features ?? {})
        .filter(([k]) => !INDICATOR_KEYS.has(k))
        .sort(([a], [b]) => a.localeCompare(b)),
    [session],
  );
  const events = useMemo(
    () =>
      [...(q.data?.events ?? [])].sort(
        (a, b) => (toEpochMs(a.timestamp) ?? 0) - (toEpochMs(b.timestamp) ?? 0),
      ),
    [q.data],
  );
  const maxWeight = Math.max(0.0001, ...indicators.map((i) => Math.abs(i.weight ?? 0)));

  if (q.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-36 w-full" />
        <Skeleton className="h-72 w-full" />
      </div>
    );
  }
  if (q.error || !session) {
    return (
      <div className="space-y-4">
        <Link to="/sessions" className="inline-flex items-center gap-1 text-sm text-muted hover:text-fg">
          <ArrowLeft className="h-4 w-4" /> {L.back}
        </Link>
        <DataState error={q.error} empty={!q.error} emptyTitle={L.notFound} onRetry={() => q.refetch()} />
      </div>
    );
  }

  const ai = session.classification === "ai_agent" || session.ai_score >= AI_THRESHOLD;
  const durationMs = Date.parse(session.last_seen) - Date.parse(session.first_seen);
  const clsKey = `cls_${session.classification}` as `cls_${ActorType}`;
  const scorePct = Math.round(session.ai_score * 100);

  return (
    <div className="space-y-4">
      <Link to="/sessions" className="inline-flex items-center gap-1 text-sm text-muted hover:text-fg">
        <ArrowLeft className="h-4 w-4" /> {L.back}
      </Link>
      <PageHeader
        title={
          <span className="flex flex-wrap items-center gap-2">
            {L.title} <Mono className="text-base">{session.source_ip}</Mono>
            <ActorBadge actor={session.classification} />
          </span>
        }
        description={<Mono className="text-muted">{session.id}</Mono>}
        actions={
          <>
            {session.incident_id && (
              <Link
                to={`/incidents/${session.incident_id}`}
                className="inline-flex h-7 items-center gap-1.5 rounded-md border border-sev-high/40 px-2.5 text-xs text-sev-high hover:bg-sev-high/10"
              >
                <Flag className="h-3.5 w-3.5" /> {L.incident}
              </Link>
            )}
            <Link
              to={`/events?session_id=${encodeURIComponent(session.id)}`}
              className="inline-flex h-7 items-center gap-1.5 rounded-md border border-line px-2.5 text-xs hover:bg-surface-2"
            >
              <ScrollText className="h-3.5 w-3.5" /> {L.events}
            </Link>
          </>
        }
      />

      {/* Attribution summary */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className={cn("lg:col-span-1", ai && "border-ai/40 bg-ai/[0.04]")}>
          <CardBody className="space-y-3">
            <div className="flex items-center justify-between text-xs text-muted">
              <span className="flex items-center gap-1.5">
                <Bot className={cn("h-4 w-4", ai && "text-ai")} /> {L.score}
              </span>
              <span>
                {L.threshold} {Math.round(AI_THRESHOLD * 100)}%
              </span>
            </div>
            <div className={cn("text-5xl font-semibold leading-none", ai ? "text-ai" : "text-fg")}>
              {scorePct}
              <span className="ml-0.5 text-2xl text-muted">%</span>
            </div>
            <div className="relative h-2 w-full overflow-hidden rounded-full bg-surface-2">
              <div
                className={cn(
                  "absolute inset-y-0 left-0 rounded-full",
                  ai ? "bg-ai" : scorePct >= 40 ? "bg-sev-medium" : "bg-sev-info",
                )}
                style={{ width: `${scorePct}%` }}
              />
              <div
                className="absolute inset-y-0 w-0.5 bg-fg/60"
                style={{ left: `${AI_THRESHOLD * 100}%` }}
                title={`${L.threshold} ${AI_THRESHOLD}`}
              />
            </div>
            <div className="text-sm">{L[clsKey]}</div>
            <div className="text-[11px] text-muted">{L.disclaimer}</div>
          </CardBody>
        </Card>
        <Card className="lg:col-span-2">
          <CardBody className="space-y-4">
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <Stat label={L.requests} value={formatNumber(session.request_count)} />
              <div className="min-w-0">
                <div className="text-[11px] text-muted">{L.errors}</div>
                <div className="mt-1.5">
                  <ErrorRateBar requests={session.request_count} errors={session.error_count} />
                </div>
              </div>
              <Stat label={L.paths} value={formatNumber(session.unique_paths)} />
              <Stat label={L.duration} value={Number.isFinite(durationMs) ? formatMs(durationMs) : "-"} />
            </div>
            <div className="grid grid-cols-2 gap-4 border-t border-line pt-3 sm:grid-cols-5">
              <Stat label={L.medianGap} value={formatMs(stats.medianGap)} hint={L.computed} />
              <Stat label={L.cv} value={stats.cv == null ? "-" : stats.cv.toFixed(2)} hint={L.computed} />
              <Stat
                label={`${L.burst} (≤${BURST_MAX_MS}ms)`}
                value={stats.burstRatio == null ? "-" : pct(stats.burstRatio)}
                hint={L.computed}
              />
              <Stat
                label={`${L.think} (${THINK_MIN_MS / 1000}–${THINK_MAX_MS / 1000}s)`}
                value={stats.thinkRatio == null ? "-" : pct(stats.thinkRatio)}
                hint={L.computed}
                tone={(stats.thinkRatio ?? 0) >= 0.15 ? "ai" : undefined}
              />
              <div className="min-w-0">
                <div className="text-[11px] text-muted" title={L.computed}>
                  {L.bimodal}
                </div>
                <div className="mt-1">
                  {stats.bimodal ? <Badge tone="ai">{L.yes}</Badge> : <Badge>{L.no}</Badge>}
                </div>
              </div>
            </div>
            <dl className="grid grid-cols-1 gap-x-4 gap-y-2 border-t border-line pt-3 text-xs sm:grid-cols-2">
              <div className="min-w-0">
                <dt className="text-[11px] text-muted">{L.ua}</dt>
                <dd className="break-all font-mono">{session.user_agent ?? "-"}</dd>
              </div>
              <div className="min-w-0">
                <dt className="text-[11px] text-muted">{L.fingerprint}</dt>
                <dd className="break-all font-mono">{session.client_fingerprint}</dd>
              </div>
              <div>
                <dt className="text-[11px] text-muted">{L.first}</dt>
                <dd>{formatDateTime(session.first_seen)}</dd>
              </div>
              <div>
                <dt className="text-[11px] text-muted">{L.last}</dt>
                <dd>{formatDateTime(session.last_seen)}</dd>
              </div>
            </dl>
          </CardBody>
        </Card>
      </div>

      {/* Thinking rhythm */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <RhythmScatter points={points} />
        </div>
        <GapHistogram points={points} />
      </div>

      {/* Indicators & features */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title={L.indicators} description={L.indicatorsDesc} />
          {indicators.length === 0 ? (
            <EmptyState title={L.noIndicators} />
          ) : (
            <ul className="divide-y divide-line">
              {indicators.map((ind, i) => (
                <li key={`${ind.label}-${i}`} className="px-4 py-2">
                  <div className="flex items-start justify-between gap-3">
                    <span className="text-sm">{ind.label}</span>
                    {ind.weight != null && (
                      <span
                        className={cn(
                          "shrink-0 text-xs tabular-nums",
                          ind.weight > 0 ? "text-ai" : "text-muted",
                        )}
                      >
                        {ind.weight > 0 ? "+" : ""}
                        {ind.weight.toFixed(2)}
                      </span>
                    )}
                  </div>
                  {ind.weight != null && (
                    <span className="mt-1 block h-1 w-full overflow-hidden rounded-full bg-surface-2">
                      <span
                        className={cn("block h-full rounded-full", ind.weight > 0 ? "bg-ai" : "bg-sev-info")}
                        style={{ width: `${(Math.abs(ind.weight) / maxWeight) * 100}%` }}
                      />
                    </span>
                  )}
                  {(ind.detail || ind.value != null) && (
                    <div className="mt-1 break-words text-xs text-muted">
                      {ind.detail}
                      {ind.value != null && (
                        <Mono className="ml-1">
                          {typeof ind.value === "object" ? JSON.stringify(ind.value) : String(ind.value)}
                        </Mono>
                      )}
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card>
          <CardHeader title={L.features} description={L.featuresDesc} />
          {featureRows.length === 0 ? (
            <EmptyState title={L.noFeatures} />
          ) : (
            <div className="max-h-[420px] overflow-y-auto">
              <Table>
                <TBody>
                  {featureRows.map(([k, v]) => (
                    <TR key={k}>
                      <TD className="w-1/2">
                        <Mono className="text-muted">{k}</Mono>
                      </TD>
                      <TD className="break-all text-right font-mono text-xs tabular-nums">
                        {v && typeof v === "object" ? (
                          <span className="text-muted">{JSON.stringify(v).slice(0, 160)}</span>
                        ) : (
                          formatFeature(k, v)
                        )}
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            </div>
          )}
        </Card>
      </div>

      {/* Requests */}
      <Card>
        <CardHeader title={L.requestsTitle} description={L.requestsDesc} />
        {events.length === 0 ? (
          <EmptyState title={L.noEvents} />
        ) : (
          <div className="max-h-[520px] overflow-y-auto">
            <Table className="table-fixed">
              <THead>
                <tr>
                  <TH className="w-[52px] text-right">#</TH>
                  <TH className="w-[170px]">{L.time}</TH>
                  <TH className="w-[96px] text-right">{L.gap}</TH>
                  <TH className="w-[72px]">{L.method}</TH>
                  <TH>{L.path}</TH>
                  <TH className="w-[72px]">{L.status}</TH>
                  <TH className="hidden w-[84px] text-right md:table-cell">{L.dur}</TH>
                </tr>
              </THead>
              <TBody>
                {events.map((ev, i) => {
                  const prev = events[i - 1];
                  const t = toEpochMs(ev.timestamp);
                  const gap = prev && t != null ? t - (toEpochMs(prev.timestamp) ?? t) : null;
                  const think = gap != null && gap >= THINK_MIN_MS && gap <= THINK_MAX_MS;
                  const burst = gap != null && gap <= BURST_MAX_MS;
                  return (
                    <TR key={ev.id} onClick={() => setOpenEvent(ev)} className="cursor-pointer">
                      <TD className="text-right text-xs tabular-nums text-muted">{i + 1}</TD>
                      <TD className="whitespace-nowrap text-xs tabular-nums">
                        <button
                          type="button"
                          className="hover:text-accent focus-visible:outline-2 focus-visible:outline-accent"
                          onClick={(e) => {
                            e.stopPropagation();
                            setOpenEvent(ev);
                          }}
                        >
                          {formatDateTime(ev.timestamp)}
                        </button>
                      </TD>
                      <TD className="text-right text-xs tabular-nums">
                        <span className="inline-flex items-center justify-end gap-1">
                          {think && <span className="h-1.5 w-1.5 rounded-full bg-ai" title={L.think} />}
                          {burst && <span className="h-1.5 w-1.5 rounded-full bg-sev-info" title={L.burst} />}
                          {gap == null ? "-" : formatMs(gap)}
                        </span>
                      </TD>
                      <TD className="font-mono text-xs font-semibold">{ev.http?.method ?? ev.kind}</TD>
                      <TD className="truncate font-mono text-xs" title={ev.http?.path ?? undefined}>
                        {ev.http
                          ? `${ev.http.path ?? ""}${ev.http.query ? `?${ev.http.query}` : ""}`
                          : (ev.message ?? "-")}
                      </TD>
                      <TD>
                        <HttpStatusBadge status={ev.http?.status} />
                      </TD>
                      <TD className="hidden text-right text-xs tabular-nums text-muted md:table-cell">
                        {formatMs(ev.http?.duration_ms)}
                      </TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          </div>
        )}
      </Card>

      <EventDrawer eventId={openEvent?.id ?? null} event={openEvent} onClose={() => setOpenEvent(null)} />
    </div>
  );
}
