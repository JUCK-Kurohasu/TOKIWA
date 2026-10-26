/**
 * System: version/runtime info, background jobs with manual run, audit log.
 * GET /system/info, GET /system/jobs, POST /system/jobs/{name}/run (admin), GET /audit?action&actor (admin).
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ChevronDown,
  ChevronRight,
  Cpu,
  Filter,
  History,
  Play,
  RotateCcw,
  TriangleAlert,
} from "lucide-react";
import { type FormEvent, Fragment, useState } from "react";
import { api } from "@/api/client";
import type { JobInfo, Page } from "@/api/types";
import type { AuditEntry, SystemInfo } from "@/api/types-core";
import { JsonView, Mono } from "@/components/common";
import { DataState, RowsSkeleton } from "@/components/common/DataState";
import { formatMs } from "@/components/common/numfmt";
import { PagerBar } from "@/components/common/PagerBar";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Input,
  Skeleton,
  Spinner,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/ui";
import { errorMessage, useApiQuery } from "@/hooks/useApi";
import { formatDateTime, formatNumber, timeAgo } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import type { Flash } from "./shared";

const strings = {
  ja: {
    info: "システム情報",
    version: "バージョン",
    env: "環境",
    database: "データベース",
    llm: "LLM プロバイダ",
    available: "利用可",
    unavailable: "利用不可",
    detectors: "検知器",
    jobs: "バックグラウンドジョブ",
    jobsDesc: "定期実行されるジョブ。手動実行はバックグラウンドで開始されます。",
    name: "名前",
    interval: "間隔",
    status: "状態",
    running: "実行中",
    idle: "待機",
    lastRun: "最終実行",
    runs: "実行回数",
    lastError: "最終エラー",
    run: "今すぐ実行",
    started: "ジョブ {name} を開始しました",
    noJobs: "登録されたジョブはありません",
    never: "未実行",
    audit: "監査ログ",
    auditDesc: "ユーザー・トークン・設定・対処などの変更履歴（新しい順）",
    action: "操作",
    actor: "実行者",
    target: "対象",
    time: "時刻",
    details: "詳細",
    apply: "絞り込み",
    reset: "リセット",
    noAudit: "監査ログはありません",
  },
  en: {
    info: "System",
    version: "Version",
    env: "Environment",
    database: "Database",
    llm: "LLM provider",
    available: "available",
    unavailable: "unavailable",
    detectors: "Detectors",
    jobs: "Background jobs",
    jobsDesc: "Periodic jobs. A manual run starts in the background.",
    name: "Name",
    interval: "Interval",
    status: "Status",
    running: "running",
    idle: "idle",
    lastRun: "Last run",
    runs: "Runs",
    lastError: "Last error",
    run: "Run now",
    started: "Started job {name}",
    noJobs: "No jobs registered",
    never: "never",
    audit: "Audit log",
    auditDesc: "Changes to users, tokens, settings, actions … (newest first)",
    action: "Action",
    actor: "Actor",
    target: "Target",
    time: "Time",
    details: "Details",
    apply: "Filter",
    reset: "Reset",
    noAudit: "No audit entries",
  },
};

function InfoCard() {
  const L = useLocal(strings);
  const q = useApiQuery<SystemInfo>(["system", "info"], "/system/info");
  const d = q.data;
  const items: [string, React.ReactNode][] = d
    ? [
        [L.version, <Mono key="v">v{d.version}</Mono>],
        [
          L.env,
          <Badge key="e" className="font-mono">
            {d.env}
          </Badge>,
        ],
        [
          L.database,
          <Mono key="d" className="break-all">
            {d.database}
          </Mono>,
        ],
        [
          L.llm,
          <span key="l" className="inline-flex items-center gap-1.5">
            <Mono>{d.llm_provider}</Mono>
            <Badge tone={d.llm_available ? "accent" : "warn"}>
              {d.llm_available ? L.available : L.unavailable}
            </Badge>
          </span>,
        ],
        [
          L.detectors,
          <span key="n" className="tabular-nums">
            {formatNumber(d.detectors)}
          </span>,
        ],
      ]
    : [];
  return (
    <Card>
      <CardHeader title={L.info} />
      <DataState
        loading={q.isLoading}
        error={q.error}
        onRetry={() => q.refetch()}
        skeleton={<Skeleton className="m-4 h-16" />}
        className="p-4"
      >
        <dl className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-3 lg:grid-cols-5">
          {items.map(([k, v]) => (
            <div key={k} className="min-w-0">
              <dt className="text-[11px] text-muted">{k}</dt>
              <dd className="mt-1 text-sm">{v}</dd>
            </div>
          ))}
        </dl>
      </DataState>
    </Card>
  );
}

function JobsCard({ flash }: { flash: Flash }) {
  const L = useLocal(strings);
  const qc = useQueryClient();
  const q = useApiQuery<JobInfo[]>(["system", "jobs"], "/system/jobs", undefined, {
    refetchInterval: 10_000,
  });
  const run = useMutation({
    mutationFn: (name: string) => api.post<JobInfo>(`/system/jobs/${encodeURIComponent(name)}/run`),
    onSuccess: (_job, name) => {
      flash(L.started.replace("{name}", name));
      void qc.invalidateQueries({ queryKey: ["system", "jobs"] });
      // Pick up the finished state shortly after.
      setTimeout(() => void qc.invalidateQueries({ queryKey: ["system", "jobs"] }), 3000);
    },
    onError: (e) => flash(errorMessage(e), "danger"),
  });
  const jobs = [...(q.data ?? [])].sort((a, b) => a.name.localeCompare(b.name));

  return (
    <Card>
      <CardHeader title={L.jobs} description={L.jobsDesc} />
      <DataState
        loading={q.isLoading}
        error={q.error}
        empty={!!q.data && jobs.length === 0}
        emptyTitle={L.noJobs}
        emptyIcon={<Cpu className="h-6 w-6 opacity-60" />}
        onRetry={() => q.refetch()}
        className="p-4"
      >
        <Table>
          <THead>
            <tr>
              <TH>{L.name}</TH>
              <TH className="text-right">{L.interval}</TH>
              <TH>{L.status}</TH>
              <TH>{L.lastRun}</TH>
              <TH className="hidden text-right md:table-cell">{L.runs}</TH>
              <TH className="hidden lg:table-cell">{L.lastError}</TH>
              <TH className="w-[120px]" />
            </tr>
          </THead>
          <TBody>
            {jobs.map((j) => (
              <TR key={j.name}>
                <TD>
                  <Mono>{j.name}</Mono>
                </TD>
                <TD className="text-right text-xs tabular-nums">{formatMs(j.interval_seconds * 1000)}</TD>
                <TD>
                  {j.running ? (
                    <Badge tone="accent">
                      <Spinner className="h-3 w-3 border" />
                      {L.running}
                    </Badge>
                  ) : (
                    <Badge>{L.idle}</Badge>
                  )}
                </TD>
                <TD
                  className="whitespace-nowrap text-xs text-muted"
                  title={formatDateTime(j.last_finished ?? j.last_started)}
                >
                  {j.last_started ? timeAgo(j.last_finished ?? j.last_started) : L.never}
                </TD>
                <TD className="hidden text-right text-xs tabular-nums md:table-cell">
                  {formatNumber(j.run_count)}
                </TD>
                <TD className="hidden max-w-[320px] lg:table-cell">
                  {j.last_error ? (
                    <span className="flex items-center gap-1 text-xs text-sev-critical" title={j.last_error}>
                      <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
                      <span className="truncate">{j.last_error}</span>
                    </span>
                  ) : (
                    <span className="text-xs text-muted">-</span>
                  )}
                </TD>
                <TD className="text-right">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => run.mutate(j.name)}
                    disabled={j.running || (run.isPending && run.variables === j.name)}
                  >
                    <Play className="h-3.5 w-3.5" />
                    {L.run}
                  </Button>
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      </DataState>
    </Card>
  );
}

function AuditCard() {
  const L = useLocal(strings);
  const [filters, setFilters] = useState({ action: "", actor: "" });
  const [draft, setDraft] = useState(filters);
  const [offset, setOffset] = useState(0);
  const [limit, setLimit] = useState(50);
  const [expanded, setExpanded] = useState<string | null>(null);
  const params = { action: filters.action || undefined, actor: filters.actor || undefined, limit, offset };
  const q = useApiQuery<Page<AuditEntry>>(["audit", params], "/audit", params, { keepPrevious: true });

  function submit(e: FormEvent) {
    e.preventDefault();
    setFilters(draft);
    setOffset(0);
  }

  return (
    <Card>
      <CardHeader
        title={L.audit}
        description={L.auditDesc}
        actions={
          <form onSubmit={submit} className="flex flex-wrap items-center gap-1.5">
            <Input
              value={draft.action}
              onChange={(e) => setDraft({ ...draft, action: e.target.value })}
              placeholder={L.action}
              aria-label={L.action}
              className="h-7 w-36 font-mono text-xs"
            />
            <Input
              value={draft.actor}
              onChange={(e) => setDraft({ ...draft, actor: e.target.value })}
              placeholder={L.actor}
              aria-label={L.actor}
              className="h-7 w-32 text-xs"
            />
            <Button type="submit" size="sm" variant="outline">
              <Filter className="h-3.5 w-3.5" />
              {L.apply}
            </Button>
            {(filters.action || filters.actor) && (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  setDraft({ action: "", actor: "" });
                  setFilters({ action: "", actor: "" });
                  setOffset(0);
                }}
              >
                <RotateCcw className="h-3.5 w-3.5" />
                {L.reset}
              </Button>
            )}
          </form>
        }
      />
      <DataState
        loading={q.isLoading}
        error={q.error}
        empty={!!q.data && q.data.items.length === 0}
        emptyTitle={L.noAudit}
        emptyIcon={<History className="h-6 w-6 opacity-60" />}
        skeleton={<RowsSkeleton rows={6} className="p-4" />}
        onRetry={() => q.refetch()}
        className="p-4"
      >
        <div className={cn("transition-opacity", q.isFetching && !q.isLoading && "opacity-70")}>
          <Table>
            <THead>
              <tr>
                <TH className="w-6" />
                <TH>{L.time}</TH>
                <TH>{L.actor}</TH>
                <TH>{L.action}</TH>
                <TH>{L.target}</TH>
              </tr>
            </THead>
            <TBody>
              {(q.data?.items ?? []).map((a) => {
                const open = expanded === a.id;
                const hasDetails = a.details && Object.keys(a.details).length > 0;
                return (
                  <Fragment key={a.id}>
                    <TR
                      className={cn(hasDetails && "cursor-pointer")}
                      onClick={() => hasDetails && setExpanded(open ? null : a.id)}
                    >
                      <TD className="text-muted">
                        {hasDetails && (
                          <button
                            type="button"
                            aria-expanded={open}
                            aria-label={L.details}
                            onClick={(e) => {
                              e.stopPropagation();
                              setExpanded(open ? null : a.id);
                            }}
                            className="rounded hover:text-fg focus-visible:outline-2 focus-visible:outline-accent"
                          >
                            {open ? (
                              <ChevronDown className="h-3.5 w-3.5" />
                            ) : (
                              <ChevronRight className="h-3.5 w-3.5" />
                            )}
                          </button>
                        )}
                      </TD>
                      <TD className="whitespace-nowrap text-xs">{formatDateTime(a.created_at)}</TD>
                      <TD className="text-sm">{a.actor}</TD>
                      <TD>
                        <Mono>{a.action}</Mono>
                      </TD>
                      <TD className="max-w-[320px] truncate">
                        <Mono className="text-muted">{a.target ?? "-"}</Mono>
                      </TD>
                    </TR>
                    {open && (
                      <tr>
                        <td colSpan={5} className="bg-bg/40 px-3 pb-3">
                          <JsonView value={a.details} className="max-h-60" />
                        </td>
                      </tr>
                    )}
                  </Fragment>
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
            onOffset={setOffset}
            onLimit={(n) => {
              setLimit(n);
              setOffset(0);
            }}
          />
        )}
      </DataState>
    </Card>
  );
}

export function SystemTab({ flash }: { flash: Flash }) {
  return (
    <div className="space-y-4">
      <InfoCard />
      <JobsCard flash={flash} />
      <AuditCard />
    </div>
  );
}
