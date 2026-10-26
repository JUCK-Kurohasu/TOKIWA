/** `/sessions`: actor sessions ordered by AI score, with classification / score / IP filters. */
import { Bot, Filter, Flag, RotateCcw } from "lucide-react";
import { type FormEvent, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router";
import type { ActorSession, ActorType, Page } from "@/api/types";
import { ActorBadge, AiScore, Mono, PageHeader } from "@/components/common";
import { DataState, RowsSkeleton } from "@/components/common/DataState";
import { formatMs } from "@/components/common/numfmt";
import { PagerBar } from "@/components/common/PagerBar";
import { Button, Card, Input, Label, Select, Table, TBody, TD, TH, THead, TR } from "@/components/ui";
import { useApiQuery } from "@/hooks/useApi";
import { useSearchState } from "@/hooks/useSearchState";
import { formatNumber, pct, timeAgo } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export const AI_THRESHOLD = 0.7; // mirrors detection.ai_agent_threshold (backend default)

const CLASSES: ActorType[] = ["ai_agent", "automated_scanner", "human", "benign", "unknown"];
const KEYS = ["classification", "min_ai_score", "source_ip", "offset", "limit"] as const;

export const sessionStrings = {
  ja: {
    title: "AI エージェントセッション",
    desc: "送信元 + クライアント指紋ごとの行動まとまり。振る舞い特徴量から AI エージェントらしさを推定します。",
    classification: "分類",
    all: "すべて",
    minScore: "AI スコア下限",
    any: "指定なし",
    sourceIp: "送信元 IP",
    apply: "適用",
    reset: "リセット",
    score: "AI スコア",
    source: "送信元",
    client: "クライアント",
    requests: "リクエスト",
    errorRate: "エラー率",
    paths: "パス数",
    duration: "継続時間",
    lastSeen: "最終観測",
    empty: "セッションはまだありません",
    emptyHint: "HTTP イベントが取り込まれるとセッション化されます",
    incident: "インシデントあり",
    noUa: "(UA なし)",
  },
  en: {
    title: "AI agent sessions",
    desc: "Activity grouped per source + client fingerprint. AI-agent likelihood is estimated from behaviour.",
    classification: "Class",
    all: "All",
    minScore: "Min AI score",
    any: "Any",
    sourceIp: "Source IP",
    apply: "Apply",
    reset: "Reset",
    score: "AI score",
    source: "Source",
    client: "Client",
    requests: "Requests",
    errorRate: "Error rate",
    paths: "Paths",
    duration: "Duration",
    lastSeen: "Last seen",
    empty: "No sessions yet",
    emptyHint: "Sessions appear once HTTP events are ingested",
    incident: "Has incident",
    noUa: "(no UA)",
  },
};

export function ErrorRateBar({ requests, errors }: { requests: number; errors: number }) {
  const rate = requests > 0 ? errors / requests : 0;
  const color = rate >= 0.5 ? "bg-sev-critical" : rate >= 0.2 ? "bg-sev-medium" : "bg-sev-info";
  return (
    <span className="inline-flex items-center gap-1.5 text-xs tabular-nums">
      <span className="relative h-1.5 w-10 overflow-hidden rounded-full bg-surface-2">
        <span
          className={cn("absolute inset-y-0 left-0", color)}
          style={{ width: `${Math.round(rate * 100)}%` }}
        />
      </span>
      {pct(rate)}
    </span>
  );
}

export function SessionsListPage() {
  const L = useLocal(sessionStrings);
  const navigate = useNavigate();
  const [f, setF] = useSearchState(KEYS);
  const limit = Number(f.limit) || 50;
  const offset = Number(f.offset) || 0;
  const [ip, setIp] = useState(f.source_ip);
  useEffect(() => setIp(f.source_ip), [f.source_ip]);

  const params = {
    classification: f.classification || undefined,
    min_ai_score: f.min_ai_score || undefined,
    source_ip: f.source_ip || undefined,
    limit,
    offset,
  };
  const q = useApiQuery<Page<ActorSession>>(["sessions", "list", params], "/sessions", params, {
    keepPrevious: true,
    refetchInterval: 30_000,
  });
  // Contract: ordered by AI score. Sort the page defensively as well.
  const rows = useMemo(() => [...(q.data?.items ?? [])].sort((a, b) => b.ai_score - a.ai_score), [q.data]);

  function submit(e: FormEvent) {
    e.preventDefault();
    setF({ source_ip: ip, offset: null });
  }

  return (
    <div className="space-y-3">
      <PageHeader title={L.title} description={L.desc} />
      <Card className="p-3">
        <form onSubmit={submit} className="flex flex-wrap items-end gap-2">
          <div className="w-[170px]">
            <Label htmlFor="ss-class">{L.classification}</Label>
            <Select
              id="ss-class"
              value={f.classification}
              onChange={(e) => setF({ classification: e.target.value, offset: null })}
              className="w-full"
            >
              <option value="">{L.all}</option>
              {CLASSES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </Select>
          </div>
          <div className="w-[150px]">
            <Label htmlFor="ss-min">{L.minScore}</Label>
            <Select
              id="ss-min"
              value={f.min_ai_score}
              onChange={(e) => setF({ min_ai_score: e.target.value, offset: null })}
              className="w-full"
            >
              <option value="">{L.any}</option>
              <option value="0.4">≥ 40%</option>
              <option value="0.7">≥ 70%</option>
              <option value="0.9">≥ 90%</option>
            </Select>
          </div>
          <div className="w-[180px]">
            <Label htmlFor="ss-ip">{L.sourceIp}</Label>
            <Input
              id="ss-ip"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              className="font-mono text-xs"
            />
          </div>
          <Button type="submit">
            <Filter className="h-3.5 w-3.5" />
            {L.apply}
          </Button>
          <Button
            variant="ghost"
            onClick={() => setF({ classification: null, min_ai_score: null, source_ip: null, offset: null })}
            disabled={!f.classification && !f.min_ai_score && !f.source_ip}
          >
            <RotateCcw className="h-3.5 w-3.5" />
            {L.reset}
          </Button>
        </form>
      </Card>

      <Card>
        <DataState
          loading={q.isLoading}
          error={q.error}
          empty={!!q.data && rows.length === 0}
          emptyTitle={L.empty}
          emptyHint={L.emptyHint}
          emptyIcon={<Bot className="h-6 w-6 opacity-60" />}
          skeleton={<RowsSkeleton rows={8} className="p-4" />}
          onRetry={() => q.refetch()}
          className="p-4"
        >
          <div className={cn("transition-opacity", q.isFetching && !q.isLoading && "opacity-70")}>
            <Table>
              <THead>
                <tr>
                  <TH className="w-[110px]">{L.score}</TH>
                  <TH>{L.classification}</TH>
                  <TH>{L.source}</TH>
                  <TH className="hidden lg:table-cell">{L.client}</TH>
                  <TH className="text-right">{L.requests}</TH>
                  <TH>{L.errorRate}</TH>
                  <TH className="hidden text-right md:table-cell">{L.paths}</TH>
                  <TH className="hidden text-right xl:table-cell">{L.duration}</TH>
                  <TH className="text-right">{L.lastSeen}</TH>
                </tr>
              </THead>
              <TBody>
                {rows.map((s) => {
                  const ai = s.classification === "ai_agent" || s.ai_score >= AI_THRESHOLD;
                  const dur = Date.parse(s.last_seen) - Date.parse(s.first_seen);
                  return (
                    <TR
                      key={s.id}
                      onClick={() => navigate(`/sessions/${s.id}`)}
                      className={cn(
                        "cursor-pointer border-l-2",
                        ai ? "border-l-ai bg-ai/[0.03]" : "border-l-transparent",
                      )}
                    >
                      <TD>
                        <AiScore score={s.ai_score} className={ai ? "font-semibold text-ai" : undefined} />
                      </TD>
                      <TD>
                        <span className="inline-flex items-center gap-1.5">
                          <ActorBadge actor={s.classification} />
                          {s.incident_id && (
                            <Link
                              to={`/incidents/${s.incident_id}`}
                              onClick={(e) => e.stopPropagation()}
                              className="text-sev-high hover:opacity-80"
                              title={L.incident}
                              aria-label={L.incident}
                            >
                              <Flag className="h-3.5 w-3.5" />
                            </Link>
                          )}
                        </span>
                      </TD>
                      <TD>
                        <Link
                          to={`/sessions/${s.id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="font-mono text-xs hover:text-accent hover:underline"
                        >
                          {s.source_ip}
                        </Link>
                      </TD>
                      <TD className="hidden max-w-[280px] lg:table-cell">
                        <div className="truncate text-xs" title={s.user_agent ?? undefined}>
                          {s.user_agent || <span className="text-muted">{L.noUa}</span>}
                        </div>
                        <Mono className="text-[10px] text-muted">{s.client_fingerprint.slice(0, 12)}</Mono>
                      </TD>
                      <TD className="text-right tabular-nums">{formatNumber(s.request_count)}</TD>
                      <TD>
                        <ErrorRateBar requests={s.request_count} errors={s.error_count} />
                      </TD>
                      <TD className="hidden text-right tabular-nums md:table-cell">
                        {formatNumber(s.unique_paths)}
                      </TD>
                      <TD className="hidden text-right text-xs tabular-nums xl:table-cell">
                        {Number.isFinite(dur) ? formatMs(dur) : "-"}
                      </TD>
                      <TD className="whitespace-nowrap text-right text-xs text-muted">
                        {timeAgo(s.last_seen)}
                      </TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          </div>
          {q.data && (
            <PagerBar
              className="border-t border-line px-4 py-2"
              total={q.data.total}
              limit={limit}
              offset={offset}
              busy={q.isFetching}
              onOffset={(o) => setF({ offset: o || null })}
              onLimit={(n) => setF({ limit: n === 50 ? null : n, offset: null })}
            />
          )}
        </DataState>
      </Card>
    </div>
  );
}
