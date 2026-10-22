/** Feed source health: last sync, record count, last error, manual sync (runs in the background server-side). */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleAlert, CircleCheck, CircleMinus, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "@/api/client";
import type { Page } from "@/api/types";
import { asList, type IntelSourceStatus } from "@/api/types-intel";
import { InlineNotice, useFlash } from "@/components/common/InlineNotice";
import { ApiErrorState, QueryView } from "@/components/common/QueryView";
import { useCan } from "@/components/common/RoleGate";
import { Button, Card, EmptyState, Table, TBody, TD, TH, THead, TR } from "@/components/ui";
import { formatDateTime, formatNumber, timeAgo } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const strings = {
  ja: {
    syncAll: "全ソースを同期",
    sync: "同期",
    source: "ソース",
    state: "状態",
    lastSync: "最終同期",
    records: "件数",
    lastError: "直近のエラー",
    ok: "正常",
    error: "エラー",
    disabled: "無効",
    never: "未同期",
    started: "同期を開始しました（バックグラウンドで実行されます）",
    empty: "インテルソースが登録されていません",
    note: "サンドボックスやオフライン環境では外部フィードに接続できず、エラーになることがあります。",
  },
  en: {
    syncAll: "Sync all sources",
    sync: "Sync",
    source: "Source",
    state: "State",
    lastSync: "Last sync",
    records: "Records",
    lastError: "Last error",
    ok: "OK",
    error: "Error",
    disabled: "Disabled",
    never: "Never",
    started: "Sync started (runs in the background)",
    empty: "No intel sources registered",
    note: "In sandboxed or offline environments external feeds may be unreachable and show errors.",
  },
};

export function SourcesTab() {
  const L = useLocal(strings);
  const can = useCan();
  const qc = useQueryClient();
  const [notice, flash] = useFlash(6000);
  const [pollUntil, setPollUntil] = useState(0);
  const [pending, setPending] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["intel", "sources"],
    queryFn: () => api.get<IntelSourceStatus[] | Page<IntelSourceStatus>>("/intel/sources"),
    select: asList,
    refetchInterval: pollUntil > 0 ? 3000 : false,
  });

  // Poll for ~30s after a manual sync so the table reflects the background job.
  useEffect(() => {
    if (!pollUntil) return;
    const h = setTimeout(() => setPollUntil(0), Math.max(0, pollUntil - Date.now()));
    return () => clearTimeout(h);
  }, [pollUntil]);

  const sync = useMutation({
    mutationFn: (source?: string) => api.post<{ started: boolean }>("/intel/sync", source ? { source } : {}),
    onMutate: (source) => setPending(source ?? "*"),
    onSettled: () => setPending(null),
    onSuccess: () => {
      flash(L.started);
      setPollUntil(Date.now() + 30_000);
      qc.invalidateQueries({ queryKey: ["intel", "sources"] });
    },
  });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-muted">{L.note}</p>
        <div className="flex items-center gap-3">
          {notice && <InlineNotice tone={notice.tone}>{notice.text}</InlineNotice>}
          {can.analyst && (
            <Button variant="outline" onClick={() => sync.mutate(undefined)} disabled={sync.isPending}>
              <RefreshCw className={cn("h-4 w-4", pending === "*" && "animate-spin")} aria-hidden />
              {L.syncAll}
            </Button>
          )}
        </div>
      </div>
      {sync.error ? <ApiErrorState error={sync.error} /> : null}
      <Card>
        <QueryView
          query={query}
          className="p-4"
          isEmpty={(d) => d.length === 0}
          empty={<EmptyState title={L.empty} />}
        >
          {(sources) => (
            <Table>
              <THead>
                <tr>
                  <TH>{L.source}</TH>
                  <TH>{L.state}</TH>
                  <TH>{L.lastSync}</TH>
                  <TH className="text-right">{L.records}</TH>
                  <TH>{L.lastError}</TH>
                  <TH className="w-24" />
                </tr>
              </THead>
              <TBody>
                {sources.map((s) => {
                  const state = !s.enabled
                    ? "disabled"
                    : s.last_error
                      ? "error"
                      : s.last_sync
                        ? "ok"
                        : "never";
                  return (
                    <TR key={s.id}>
                      <TD>
                        <div className="text-sm font-medium">{s.name || s.id}</div>
                        <div className="font-mono text-[11px] text-muted">{s.id}</div>
                      </TD>
                      <TD>
                        {state === "ok" && (
                          <span className="inline-flex items-center gap-1 text-xs text-accent">
                            <CircleCheck className="h-3.5 w-3.5" aria-hidden />
                            {L.ok}
                          </span>
                        )}
                        {state === "error" && (
                          <span className="inline-flex items-center gap-1 text-xs text-sev-critical">
                            <CircleAlert className="h-3.5 w-3.5" aria-hidden />
                            {L.error}
                          </span>
                        )}
                        {(state === "disabled" || state === "never") && (
                          <span className="inline-flex items-center gap-1 text-xs text-muted">
                            <CircleMinus className="h-3.5 w-3.5" aria-hidden />
                            {state === "disabled" ? L.disabled : L.never}
                          </span>
                        )}
                      </TD>
                      <TD className="text-xs" title={formatDateTime(s.last_sync)}>
                        {s.last_sync ? timeAgo(s.last_sync) : <span className="text-muted">{L.never}</span>}
                      </TD>
                      <TD className="text-right tabular-nums text-xs">{formatNumber(s.records)}</TD>
                      <TD className="max-w-md">
                        {s.last_error ? (
                          <span
                            className="line-clamp-2 break-all font-mono text-[11px] text-sev-critical"
                            title={s.last_error}
                          >
                            {s.last_error}
                          </span>
                        ) : (
                          <span className="text-xs text-muted">-</span>
                        )}
                      </TD>
                      <TD className="text-right">
                        {can.analyst && s.enabled && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => sync.mutate(s.id)}
                            disabled={sync.isPending}
                          >
                            <RefreshCw
                              className={cn("h-3.5 w-3.5", pending === s.id && "animate-spin")}
                              aria-hidden
                            />
                            {L.sync}
                          </Button>
                        )}
                      </TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          )}
        </QueryView>
      </Card>
    </div>
  );
}
