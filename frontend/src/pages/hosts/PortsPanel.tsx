/** Host list + listening ports of the selected host (allowed vs deviation) + "learn current state". */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { CircleCheck, GraduationCap, Plus, Server, TriangleAlert } from "lucide-react";
import { useMemo, useState } from "react";
import { api } from "@/api/client";
import type { HostPort, HostSummary, PortBaseline } from "@/api/types-core";
import { Mono } from "@/components/common";
import { DataState, RowsSkeleton } from "@/components/common/DataState";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Dialog,
  ErrorState,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/ui";
import { useApiQuery } from "@/hooks/useApi";
import { formatDateTime, formatNumber, timeAgo } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import type { BaselineDraft } from "./BaselineDialog";

const PUBLIC_BINDS = new Set(["0.0.0.0", "::", "[::]", "*", ""]);
export const isPublicBind = (ip: string) => PUBLIC_BINDS.has(ip);

const strings = {
  ja: {
    hosts: "ホスト",
    hostsDesc: "センサーが報告したホスト",
    noHosts: "ホストはまだありません",
    noHostsHint: "tokiwa agent を起動するとポートのスナップショットが届きます",
    open: "開放ポート",
    deviations: "逸脱",
    lastSeen: "最終",
    ports: "リスニングポート",
    portsDesc: "ベースライン外のポートは「逸脱」として表示します",
    learn: "現状を学習",
    learnTitle: "現在の状態をベースラインとして学習",
    learnBody:
      "ホスト {host} で現在開いているすべての listener をベースライン（許可リスト）に登録します。逸脱中のポートも許可扱いになるため、内容を確認してから実行してください。",
    learnRun: "学習を実行",
    learned: "{n} 件のベースラインを登録しました",
    cancel: "キャンセル",
    onlyDev: "逸脱のみ",
    showClosed: "クローズ済みも表示",
    status: "判定",
    allowed: "許可",
    deviation: "逸脱",
    proto: "プロトコル",
    bind: "バインド",
    port: "ポート",
    process: "プロセス",
    first: "初回",
    last: "最終",
    state: "状態",
    openState: "開",
    closedState: "閉",
    allIf: "全IF",
    allIfHint: "全インタフェースで待ち受け（外部公開の可能性）",
    allow: "許可に追加",
    noPorts: "表示するポートはありません",
    selectHost: "左の一覧からホストを選択してください",
  },
  en: {
    hosts: "Hosts",
    hostsDesc: "Hosts reported by sensors",
    noHosts: "No hosts yet",
    noHostsHint: "Start `tokiwa agent` to receive port snapshots",
    open: "Open ports",
    deviations: "Deviations",
    lastSeen: "Last",
    ports: "Listening ports",
    portsDesc: "Ports outside the baseline are shown as deviations",
    learn: "Learn current state",
    learnTitle: "Learn the current state as baseline",
    learnBody:
      "Every listener currently open on {host} will be added to the baseline (allow-list). Deviating ports become allowed too, so review the list before running this.",
    learnRun: "Learn",
    learned: "Added {n} baseline entries",
    cancel: "Cancel",
    onlyDev: "Deviations only",
    showClosed: "Show closed",
    status: "Verdict",
    allowed: "Allowed",
    deviation: "Deviation",
    proto: "Proto",
    bind: "Bind",
    port: "Port",
    process: "Process",
    first: "First",
    last: "Last",
    state: "State",
    openState: "open",
    closedState: "closed",
    allIf: "all IFs",
    allIfHint: "Listening on all interfaces (possibly exposed)",
    allow: "Allow",
    noPorts: "No ports to show",
    selectHost: "Select a host from the list",
  },
};

export function PortsPanel({
  host,
  onSelectHost,
  canWrite,
  onAddBaseline,
  flash,
}: {
  host: string;
  onSelectHost: (h: string) => void;
  canWrite: boolean;
  onAddBaseline: (draft: BaselineDraft) => void;
  flash: (msg: string, tone?: "success" | "danger") => void;
}) {
  const L = useLocal(strings);
  const qc = useQueryClient();
  const [onlyDev, setOnlyDev] = useState(false);
  const [showClosed, setShowClosed] = useState(false);
  const [learnOpen, setLearnOpen] = useState(false);

  const hostsQ = useApiQuery<HostSummary[]>(["hosts", "list"], "/hosts", undefined, {
    refetchInterval: 30_000,
  });
  const hosts = useMemo(
    () =>
      [...(hostsQ.data ?? [])].sort((a, b) => b.deviations - a.deviations || a.host.localeCompare(b.host)),
    [hostsQ.data],
  );
  const selected = host || hosts[0]?.host || "";

  const portsQ = useApiQuery<HostPort[]>(
    ["hosts", "ports", selected],
    "/hosts/ports",
    { host: selected },
    {
      enabled: !!selected,
      keepPrevious: true,
      refetchInterval: 30_000,
    },
  );
  const ports = useMemo(
    () =>
      [...(portsQ.data ?? [])]
        .filter((p) => (showClosed ? true : p.open))
        .filter((p) => (onlyDev ? !p.allowed : true))
        .sort((a, b) => Number(a.allowed) - Number(b.allowed) || a.port - b.port),
    [portsQ.data, onlyDev, showClosed],
  );
  const openListeners = (portsQ.data ?? []).filter((p) => p.open).length;

  const learn = useMutation({
    mutationFn: () => api.post<PortBaseline[]>("/hosts/baselines/learn", { host: selected }),
    onSuccess: (rows) => {
      setLearnOpen(false);
      void qc.invalidateQueries({ queryKey: ["hosts"] });
      flash(L.learned.replace("{n}", String(Array.isArray(rows) ? rows.length : 0)));
    },
  });

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[280px_minmax(0,1fr)]">
      <Card className="self-start">
        <CardHeader title={L.hosts} description={L.hostsDesc} />
        <DataState
          loading={hostsQ.isLoading}
          error={hostsQ.error}
          empty={!!hostsQ.data && hosts.length === 0}
          emptyTitle={L.noHosts}
          emptyHint={L.noHostsHint}
          emptyIcon={<Server className="h-6 w-6 opacity-60" />}
          onRetry={() => hostsQ.refetch()}
          className="p-3"
        >
          <ul className="max-h-[560px] divide-y divide-line overflow-y-auto">
            {hosts.map((h) => (
              <li key={h.host}>
                <button
                  type="button"
                  onClick={() => onSelectHost(h.host)}
                  aria-current={h.host === selected}
                  className={cn(
                    "flex w-full items-center gap-3 border-l-2 px-3 py-2.5 text-left transition-colors focus-visible:outline-2 focus-visible:outline-accent",
                    h.host === selected
                      ? "border-l-accent bg-accent-soft/50"
                      : "border-l-transparent hover:bg-surface-2/60",
                  )}
                >
                  <Server className="h-4 w-4 shrink-0 text-muted" />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">{h.host}</span>
                    <span className="block text-[11px] text-muted">
                      {L.open} {formatNumber(h.ports_open)} · {timeAgo(h.last_seen)}
                    </span>
                  </span>
                  {h.deviations > 0 ? (
                    <Badge tone="danger" title={L.deviations}>
                      <TriangleAlert className="h-3 w-3" />
                      {h.deviations}
                    </Badge>
                  ) : (
                    <CircleCheck className="h-4 w-4 text-accent" aria-label={L.allowed} />
                  )}
                </button>
              </li>
            ))}
          </ul>
        </DataState>
      </Card>

      <Card className="min-w-0">
        <CardHeader
          title={
            selected ? (
              <span className="flex items-center gap-2">
                {L.ports}
                <Mono className="text-muted">{selected}</Mono>
              </span>
            ) : (
              L.ports
            )
          }
          description={L.portsDesc}
          actions={
            <>
              <label className="flex items-center gap-1.5 text-xs text-muted">
                <input
                  type="checkbox"
                  checked={onlyDev}
                  onChange={(e) => setOnlyDev(e.target.checked)}
                  className="h-3.5 w-3.5 accent-[var(--tk-accent)]"
                />
                {L.onlyDev}
              </label>
              <label className="hidden items-center gap-1.5 text-xs text-muted sm:flex">
                <input
                  type="checkbox"
                  checked={showClosed}
                  onChange={(e) => setShowClosed(e.target.checked)}
                  className="h-3.5 w-3.5 accent-[var(--tk-accent)]"
                />
                {L.showClosed}
              </label>
              {canWrite && selected && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setLearnOpen(true)}
                  disabled={openListeners === 0}
                >
                  <GraduationCap className="h-3.5 w-3.5" />
                  {L.learn}
                </Button>
              )}
            </>
          }
        />
        {!selected ? (
          <div className="p-6 text-center text-sm text-muted">{hostsQ.isLoading ? null : L.selectHost}</div>
        ) : (
          <DataState
            loading={portsQ.isLoading}
            error={portsQ.error}
            empty={!!portsQ.data && ports.length === 0}
            emptyTitle={L.noPorts}
            skeleton={<RowsSkeleton rows={6} className="p-4" />}
            onRetry={() => portsQ.refetch()}
            className="p-4"
          >
            <div className={cn("transition-opacity", portsQ.isFetching && !portsQ.isLoading && "opacity-70")}>
              <Table>
                <THead>
                  <tr>
                    <TH>{L.status}</TH>
                    <TH>{L.proto}</TH>
                    <TH>{L.bind}</TH>
                    <TH className="text-right">{L.port}</TH>
                    <TH>{L.process}</TH>
                    <TH className="hidden md:table-cell">{L.first}</TH>
                    <TH className="hidden md:table-cell">{L.last}</TH>
                    <TH>{L.state}</TH>
                    {canWrite && <TH className="w-[110px]" />}
                  </tr>
                </THead>
                <TBody>
                  {ports.map((p) => {
                    const pub = isPublicBind(p.bind_ip);
                    return (
                      <TR
                        key={`${p.protocol}-${p.bind_ip}-${p.port}`}
                        className={cn(!p.allowed && "bg-sev-critical/[0.04]", !p.open && "opacity-60")}
                      >
                        <TD>
                          {p.allowed ? (
                            <Badge tone="accent">
                              <CircleCheck className="h-3 w-3" />
                              {L.allowed}
                            </Badge>
                          ) : (
                            <Badge tone="danger">
                              <TriangleAlert className="h-3 w-3" />
                              {L.deviation}
                            </Badge>
                          )}
                        </TD>
                        <TD className="font-mono text-xs">{p.protocol}</TD>
                        <TD className="whitespace-nowrap">
                          <Mono>{p.bind_ip || "*"}</Mono>
                          {pub && (
                            <Badge tone="warn" className="ml-1.5" title={L.allIfHint}>
                              {L.allIf}
                            </Badge>
                          )}
                        </TD>
                        <TD className="text-right font-mono text-xs font-semibold tabular-nums">{p.port}</TD>
                        <TD className="text-xs">
                          {p.process_name ?? <span className="text-muted">-</span>}
                          {p.pid != null && <span className="ml-1 text-muted">({p.pid})</span>}
                        </TD>
                        <TD className="hidden whitespace-nowrap text-xs text-muted md:table-cell">
                          {formatDateTime(p.first_seen)}
                        </TD>
                        <TD className="hidden whitespace-nowrap text-xs text-muted md:table-cell">
                          {timeAgo(p.last_seen)}
                        </TD>
                        <TD className="text-xs">{p.open ? L.openState : L.closedState}</TD>
                        {canWrite && (
                          <TD className="text-right">
                            {!p.allowed && (
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() =>
                                  onAddBaseline({
                                    host: p.host || selected,
                                    protocol: p.protocol,
                                    port: String(p.port),
                                    process_name: p.process_name ?? "",
                                    allow_public: pub,
                                    note: "",
                                  })
                                }
                              >
                                <Plus className="h-3.5 w-3.5" />
                                {L.allow}
                              </Button>
                            )}
                          </TD>
                        )}
                      </TR>
                    );
                  })}
                </TBody>
              </Table>
            </div>
          </DataState>
        )}
      </Card>

      <Dialog
        open={learnOpen}
        onClose={() => setLearnOpen(false)}
        title={L.learnTitle}
        footer={
          <>
            <Button variant="ghost" onClick={() => setLearnOpen(false)}>
              {L.cancel}
            </Button>
            <Button onClick={() => learn.mutate()} disabled={learn.isPending}>
              <GraduationCap className="h-3.5 w-3.5" />
              {L.learnRun}
            </Button>
          </>
        }
      >
        <p className="text-sm">{L.learnBody.replace("{host}", selected)}</p>
        <p className="mt-2 text-xs text-muted">
          {L.open}: {formatNumber(openListeners)} · {L.deviations}:{" "}
          {formatNumber((portsQ.data ?? []).filter((p) => p.open && !p.allowed).length)}
        </p>
        {learn.error && <ErrorState error={learn.error} />}
      </Dialog>
    </div>
  );
}
