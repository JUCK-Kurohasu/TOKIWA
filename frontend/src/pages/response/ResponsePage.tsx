/**
 * Response (/response): tabs = awaiting approval / active / history. Approve, reject (with reason), revert.
 * Shows TTL and expiry, and states in the UI that nothing executes without human approval (FR-12).
 *
 * GET /response/actions is queried once per status (the contract documents a single `status` filter);
 * results are merged, de-duplicated and re-filtered client-side so a backend that ignores the filter
 * still renders correctly.
 */
import { useQueries } from "@tanstack/react-query";
import { History, Play, RefreshCw, ShieldCheck, ShieldPlus, Sparkles } from "lucide-react";
import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api } from "@/api/client";
import type { ActionStatus, Page, ResponseAction } from "@/api/types";
import { KpiCard, Mono, PageHeader } from "@/components/common";
import { TableSkeleton } from "@/components/common/OpsKit";
import { formatTtl, useCanOperate } from "@/components/common/opsLabels";
import {
  ActionCard,
  ActionStatusBadge,
  ActionTypeTag,
  ApprovalNotice,
  ProposeActionDialog,
  ProposerBadge,
} from "@/components/common/ResponseActions";
import { useOpsLive } from "@/components/common/useOpsLive";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  Table,
  Tabs,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/ui";
import { formatDateTime, timeAgo } from "@/lib/format";
import { useLocal, useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

type TabKey = "pending" | "active" | "history";

const TAB_STATUSES: Record<TabKey, ActionStatus[]> = {
  pending: ["proposed"],
  active: ["approved", "active"],
  history: ["expired", "reverted", "rejected", "failed"],
};

const PAGE = 100;

function useActions(statuses: ActionStatus[], limit: number, enabled = true) {
  const results = useQueries({
    queries: statuses.map((status) => ({
      queryKey: ["response", "actions", status, limit],
      queryFn: () => api.get<Page<ResponseAction>>("/response/actions", { status, limit, offset: 0 }),
      refetchInterval: 30_000,
      enabled,
    })),
  });
  const byId = new Map<string, ResponseAction>();
  for (const r of results)
    for (const a of r.data?.items ?? []) if (statuses.includes(a.status)) byId.set(a.id, a);
  const items = [...byId.values()].sort((a, b) => b.updated_at.localeCompare(a.updated_at));
  return {
    items,
    total: results.reduce((s, r) => s + (r.data?.total ?? 0), 0),
    hasMore: results.some((r) => (r.data?.total ?? 0) > (r.data?.items.length ?? 0)),
    isLoading: enabled && results.some((r) => r.isLoading),
    isFetching: results.some((r) => r.isFetching),
    error: results.find((r) => r.error)?.error ?? null,
    refetch: () => {
      for (const r of results) void r.refetch();
    },
  };
}

const strings = {
  ja: {
    title: "対処",
    desc: "可逆な対処（遮断・レート制限・ターピット・デコイ誘導など）の提案・承認・実行・取り消し。",
    pending: "承認待ち",
    active: "実行中",
    history: "履歴",
    llmPending: "うち LLM 提案",
    kpiPendingHint: "承認されるまで何も実行されません",
    kpiActiveHint: "TTL 経過で自動解除",
    kpiLlmHint: "対象と理由を証拠と照合してください",
    propose: "新規提案",
    emptyPending: "承認待ちの対処はありません",
    emptyPendingHint: "LLM トリアージの推奨対処やルールからの提案がここに並びます。",
    emptyActive: "実行中の対処はありません",
    emptyHistory: "履歴はまだありません",
    colStatus: "状態",
    colType: "種別",
    colTarget: "対象",
    colReason: "理由",
    colProposer: "提案元",
    colBy: "承認者",
    colCreated: "作成",
    colEnded: "終了",
    colResult: "結果",
    ttl: "TTL",
    loadMore: "さらに読み込む",
    incident: "INC",
    alert: "ALT",
    retry: "再試行",
    resultDetail: "結果",
    activeOrder: "期限が近い順",
  },
  en: {
    title: "Response",
    desc: "Propose, approve, execute and revert reversible actions (block, rate-limit, tarpit, divert to decoys …).",
    pending: "Awaiting approval",
    active: "Active",
    history: "History",
    llmPending: "of which LLM-proposed",
    kpiPendingHint: "Nothing runs until approved",
    kpiActiveHint: "Lifted automatically when the TTL ends",
    kpiLlmHint: "Check target and reason against the evidence",
    propose: "New proposal",
    emptyPending: "No actions awaiting approval",
    emptyPendingHint: "Recommendations from LLM triage and rule-based proposals appear here.",
    emptyActive: "No active actions",
    emptyHistory: "No history yet",
    colStatus: "Status",
    colType: "Type",
    colTarget: "Target",
    colReason: "Reason",
    colProposer: "Proposed by",
    colBy: "Approved by",
    colCreated: "Created",
    colEnded: "Ended",
    colResult: "Result",
    ttl: "TTL",
    loadMore: "Load more",
    incident: "INC",
    alert: "ALT",
    retry: "Retry",
    resultDetail: "Result",
    activeOrder: "Soonest expiry first",
  },
};

function endedAt(a: ResponseAction): string | null {
  if (a.status === "reverted") return a.reverted_at ?? a.updated_at;
  if (a.status === "expired") return a.expires_at ?? a.updated_at;
  return a.updated_at;
}

function resultError(a: ResponseAction): string | null {
  const e = a.result?.error ?? a.result?.message;
  return typeof e === "string" && e ? e : null;
}

export function ResponsePage() {
  const L = useLocal(strings);
  const t = useT();
  const canOperate = useCanOperate();
  const [sp, setSp] = useSearchParams();
  const tabParam = sp.get("tab");
  const tab: TabKey = tabParam === "active" || tabParam === "history" ? tabParam : "pending";
  const setTab = (v: TabKey) =>
    setSp(
      (prev) => {
        const n = new URLSearchParams(prev);
        if (v === "pending") n.delete("tab");
        else n.set("tab", v);
        return n;
      },
      { replace: true },
    );
  const [historyLimit, setHistoryLimit] = useState(PAGE);
  const [proposeOpen, setProposeOpen] = useState(false);

  const pending = useActions(TAB_STATUSES.pending, PAGE);
  const active = useActions(TAB_STATUSES.active, PAGE);
  const history = useActions(TAB_STATUSES.history, historyLimit, tab === "history");
  useOpsLive(["action."], [["response"]]);

  const llmPending = pending.items.filter((a) => a.proposed_by === "llm").length;
  const current = tab === "pending" ? pending : tab === "active" ? active : history;
  const activeSorted = [...active.items].sort((a, b) =>
    (a.expires_at ?? "9999").localeCompare(b.expires_at ?? "9999"),
  );

  return (
    <div className="space-y-4">
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-accent" aria-hidden />
            {L.title}
          </span>
        }
        description={L.desc}
        actions={
          <>
            <Button variant="outline" size="sm" onClick={current.refetch} disabled={current.isFetching}>
              <RefreshCw className={cn("h-3.5 w-3.5", current.isFetching && "animate-spin")} aria-hidden />
              {t("common.refresh")}
            </Button>
            {canOperate && (
              <Button size="sm" onClick={() => setProposeOpen(true)}>
                <ShieldPlus className="h-3.5 w-3.5" aria-hidden />
                {L.propose}
              </Button>
            )}
          </>
        }
      />

      <ApprovalNotice />

      <div className="grid gap-3 sm:grid-cols-3">
        <KpiCard
          label={L.pending}
          value={pending.isLoading ? "…" : `${pending.items.length}${pending.hasMore ? "+" : ""}`}
          hint={L.kpiPendingHint}
          tone={pending.items.length ? "danger" : "neutral"}
          icon={<ShieldCheck className="h-4 w-4" aria-hidden />}
        />
        <KpiCard
          label={L.active}
          value={active.isLoading ? "…" : `${active.items.length}${active.hasMore ? "+" : ""}`}
          hint={L.kpiActiveHint}
          tone="accent"
          icon={<Play className="h-4 w-4" aria-hidden />}
        />
        <KpiCard
          label={L.llmPending}
          value={pending.isLoading ? "…" : llmPending}
          hint={L.kpiLlmHint}
          tone="ai"
          icon={<Sparkles className="h-4 w-4" aria-hidden />}
        />
      </div>

      <div>
        <Tabs<TabKey>
          value={tab}
          onChange={setTab}
          tabs={[
            {
              value: "pending",
              label: (
                <span className="flex items-center gap-1.5">
                  {L.pending}
                  {pending.items.length > 0 && <Badge tone="warn">{pending.items.length}</Badge>}
                </span>
              ),
            },
            {
              value: "active",
              label: (
                <span className="flex items-center gap-1.5">
                  {L.active}
                  {active.items.length > 0 && <Badge tone="accent">{active.items.length}</Badge>}
                </span>
              ),
            },
            {
              value: "history",
              label: (
                <span className="flex items-center gap-1.5">
                  <History className="h-3.5 w-3.5" aria-hidden />
                  {L.history}
                </span>
              ),
            },
          ]}
        />

        <div className="pt-4">
          {current.error ? (
            <div className="space-y-2">
              <ErrorState error={current.error} />
              <Button size="sm" variant="outline" onClick={current.refetch}>
                {L.retry}
              </Button>
            </div>
          ) : current.isLoading ? (
            <Card>
              <TableSkeleton rows={4} />
            </Card>
          ) : tab === "pending" ? (
            pending.items.length ? (
              <div className="grid gap-3 xl:grid-cols-2">
                {pending.items.map((a) => (
                  <ActionCard key={a.id} action={a} />
                ))}
              </div>
            ) : (
              <Card>
                <EmptyState
                  icon={<ShieldCheck className="h-8 w-8" aria-hidden />}
                  title={L.emptyPending}
                  hint={L.emptyPendingHint}
                />
              </Card>
            )
          ) : tab === "active" ? (
            activeSorted.length ? (
              <div className="space-y-2">
                <p className="text-xs text-muted">{L.activeOrder}</p>
                <div className="grid gap-3 xl:grid-cols-2">
                  {activeSorted.map((a) => (
                    <ActionCard key={a.id} action={a} />
                  ))}
                </div>
              </div>
            ) : (
              <Card>
                <EmptyState icon={<Play className="h-8 w-8" aria-hidden />} title={L.emptyActive} />
              </Card>
            )
          ) : history.items.length ? (
            <Card>
              <Table>
                <THead>
                  <tr>
                    <TH>{L.colStatus}</TH>
                    <TH>{L.colType}</TH>
                    <TH>{L.colTarget}</TH>
                    <TH>{L.colReason}</TH>
                    <TH>{L.colProposer}</TH>
                    <TH>{L.colBy}</TH>
                    <TH>{L.colCreated}</TH>
                    <TH>{L.colEnded}</TH>
                    <TH>{L.colResult}</TH>
                  </tr>
                </THead>
                <TBody>
                  {history.items.map((a) => {
                    const err = resultError(a);
                    const ended = endedAt(a);
                    return (
                      <TR key={a.id}>
                        <TD>
                          <ActionStatusBadge status={a.status} />
                        </TD>
                        <TD className="whitespace-nowrap">
                          <ActionTypeTag type={a.action_type} className="text-xs" />
                        </TD>
                        <TD>
                          <Mono className="break-all">{a.target}</Mono>
                          <div className="mt-0.5 flex gap-2 text-[11px]">
                            {a.ttl_minutes != null && (
                              <span className="text-muted">
                                {L.ttl} {formatTtl(a.ttl_minutes)}
                              </span>
                            )}
                            {a.incident_id && (
                              <Link
                                to={`/incidents/${a.incident_id}`}
                                className="text-accent hover:underline"
                              >
                                {L.incident}-{a.incident_id.slice(0, 6)}
                              </Link>
                            )}
                            {a.alert_id && (
                              <Link to={`/alerts/${a.alert_id}`} className="text-accent hover:underline">
                                {L.alert}-{a.alert_id.slice(0, 6)}
                              </Link>
                            )}
                          </div>
                        </TD>
                        <TD className="max-w-[280px] text-xs">
                          <span className="line-clamp-2 break-words" title={a.reason}>
                            {a.reason}
                          </span>
                        </TD>
                        <TD>
                          <ProposerBadge proposer={a.proposed_by} />
                        </TD>
                        <TD className="text-xs">{a.approved_by ?? <span className="text-muted">-</span>}</TD>
                        <TD
                          className="whitespace-nowrap text-xs text-muted"
                          title={formatDateTime(a.created_at)}
                        >
                          {timeAgo(a.created_at)}
                        </TD>
                        <TD className="whitespace-nowrap text-xs text-muted" title={formatDateTime(ended)}>
                          {timeAgo(ended)}
                        </TD>
                        <TD className="max-w-[220px] text-xs">
                          {err ? (
                            <span className="text-sev-critical" title={err}>
                              {err}
                            </span>
                          ) : a.result && Object.keys(a.result).length ? (
                            <details>
                              <summary className="cursor-pointer text-muted hover:text-fg">
                                {L.resultDetail}
                              </summary>
                              <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-bg p-2 font-mono text-[11px]">
                                {JSON.stringify(a.result, null, 2)}
                              </pre>
                            </details>
                          ) : (
                            <span className="text-muted">-</span>
                          )}
                        </TD>
                      </TR>
                    );
                  })}
                </TBody>
              </Table>
              {history.hasMore && (
                <div className="border-t border-line p-2 text-center">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setHistoryLimit((l) => Math.min(500, l + PAGE))}
                    disabled={historyLimit >= 500 || history.isFetching}
                  >
                    {L.loadMore}
                  </Button>
                </div>
              )}
            </Card>
          ) : (
            <Card>
              <EmptyState icon={<History className="h-8 w-8" aria-hidden />} title={L.emptyHistory} />
            </Card>
          )}
        </div>
      </div>

      {proposeOpen && <ProposeActionDialog open onClose={() => setProposeOpen(false)} />}
    </div>
  );
}
