/** LLM advisories: prioritized list (P1..P4) with a detail pane (summary, impact, mitigations, Sigma proposals). */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileText } from "lucide-react";
import { api } from "@/api/client";
import type { Advisory, Page, Priority } from "@/api/types";
import { ADVISORY_STATUSES } from "@/api/types-intel";
import { PriorityBadge } from "@/components/common/IntelBadges";
import { OffsetPager } from "@/components/common/OffsetPager";
import { ApiErrorState, LoadingRows, QueryView } from "@/components/common/QueryView";
import { useCan } from "@/components/common/RoleGate";
import { useUrlParams } from "@/components/common/urlState";
import { Badge, Card, EmptyState, Select } from "@/components/ui";
import { timeAgo } from "@/lib/format";
import { useLocal, useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { AdvisoryView } from "./AdvisoryView";
import { useAdvisoryStatusLabel } from "./labels";

const LIMIT = 30;
const PRIORITIES: Priority[] = ["P1", "P2", "P3", "P4"];

const strings = {
  ja: {
    priority: "優先度",
    empty: "アドバイザリはありません",
    emptyHint: "脆弱性詳細から「アドバイザリを生成」するか、資産一致・KEV 追加時の自動生成を待ってください。",
    select: "左の一覧からアドバイザリを選択してください",
    statusLabel: "対応状況",
    rules: "ルール提案",
  },
  en: {
    priority: "Priority",
    empty: "No advisories",
    emptyHint:
      "Generate one from a vulnerability's detail, or wait for automatic generation on matches / KEV additions.",
    select: "Select an advisory from the list",
    statusLabel: "Status",
    rules: "rule proposals",
  },
};

export function AdvisoriesTab({ onOpenVuln }: { onOpenVuln: (id: string) => void }) {
  const L = useLocal(strings);
  const t = useT();
  const can = useCan();
  const qc = useQueryClient();
  const statusLabel = useAdvisoryStatusLabel();
  const [params, update] = useUrlParams();
  const priority = params.get("priority") ?? "";
  const status = params.get("status") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const selected = params.get("adv");

  const list = useQuery({
    queryKey: ["intel", "advisories", { priority, status, offset }],
    queryFn: () => api.get<Page<Advisory>>("/intel/advisories", { priority, status, limit: LIMIT, offset }),
    placeholderData: keepPreviousData,
  });

  const fromList = list.data?.items.find((a) => a.id === selected);
  const detail = useQuery({
    queryKey: ["intel", "advisory", selected],
    queryFn: () => api.get<Advisory>(`/intel/advisories/${encodeURIComponent(selected ?? "")}`),
    enabled: !!selected && !fromList,
  });
  const current = fromList ?? detail.data;

  const patch = useMutation({
    mutationFn: ({ id, next }: { id: string; next: string }) =>
      api.patch<Advisory>(`/intel/advisories/${encodeURIComponent(id)}`, { status: next }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["intel", "advisories"] });
      qc.invalidateQueries({ queryKey: ["intel", "advisory"] });
    },
  });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Select
          aria-label={L.priority}
          value={priority}
          onChange={(e) => update({ priority: e.target.value, offset: null })}
        >
          <option value="">
            {L.priority}: {t("common.all")}
          </option>
          {PRIORITIES.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </Select>
        <Select
          aria-label={L.statusLabel}
          value={status}
          onChange={(e) => update({ status: e.target.value, offset: null })}
        >
          <option value="">
            {L.statusLabel}: {t("common.all")}
          </option>
          {ADVISORY_STATUSES.map((s) => (
            <option key={s} value={s}>
              {statusLabel(s)}
            </option>
          ))}
        </Select>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <Card className="h-fit">
          <QueryView
            query={list}
            className="p-4"
            rows={6}
            isEmpty={(d) => d.items.length === 0}
            empty={<EmptyState title={L.empty} hint={L.emptyHint} icon={<FileText className="h-6 w-6" />} />}
          >
            {(page) => (
              <>
                <ul className="divide-y divide-line">
                  {page.items.map((a) => (
                    <li key={a.id}>
                      <button
                        type="button"
                        aria-current={a.id === selected ? "true" : undefined}
                        onClick={() => update({ adv: a.id })}
                        className={cn(
                          "flex w-full flex-col gap-1 px-3 py-2.5 text-left transition-colors hover:bg-surface-2",
                          a.id === selected &&
                            "bg-accent-soft/60 shadow-[inset_3px_0_0_0_var(--color-accent)]",
                        )}
                      >
                        <span className="flex items-center gap-2">
                          <PriorityBadge priority={a.priority} />
                          <span className="min-w-0 flex-1 truncate text-sm font-medium">{a.title}</span>
                        </span>
                        <span className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-muted">
                          <span className="font-mono">{a.vuln_ids.slice(0, 2).join(", ")}</span>
                          {a.vuln_ids.length > 2 && <span>+{a.vuln_ids.length - 2}</span>}
                          <Badge tone={a.status === "new" ? "accent" : "neutral"}>
                            {statusLabel(a.status)}
                          </Badge>
                          {(a.analysis?.proposed_rules?.length ?? 0) > 0 && (
                            <Badge tone="ai">
                              {a.analysis.proposed_rules.length} {L.rules}
                            </Badge>
                          )}
                          <span className="ml-auto">{timeAgo(a.created_at)}</span>
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
                <OffsetPager
                  total={page.total}
                  limit={LIMIT}
                  offset={offset}
                  onChange={(o) => update({ offset: o || null })}
                />
              </>
            )}
          </QueryView>
        </Card>

        <Card className="min-w-0">
          {!selected ? (
            <EmptyState title={L.select} />
          ) : detail.isLoading && !current ? (
            <LoadingRows rows={8} className="p-4" />
          ) : detail.error && !current ? (
            <ApiErrorState error={detail.error} className="m-4" />
          ) : current ? (
            <div className="space-y-3 p-4">
              <div className="flex flex-wrap items-center justify-end gap-2">
                {patch.error ? <ApiErrorState error={patch.error} className="mr-auto py-1.5" /> : null}
                <span className="flex items-center gap-1.5 text-xs text-muted">
                  {L.statusLabel}
                  <Select
                    aria-label={L.statusLabel}
                    className="h-8 text-xs"
                    value={current.status}
                    disabled={!can.analyst || patch.isPending}
                    onChange={(e) => patch.mutate({ id: current.id, next: e.target.value })}
                  >
                    {ADVISORY_STATUSES.map((s) => (
                      <option key={s} value={s}>
                        {statusLabel(s)}
                      </option>
                    ))}
                  </Select>
                </span>
              </div>
              <AdvisoryView advisory={current} onOpenVuln={onOpenVuln} />
            </div>
          ) : null}
        </Card>
      </div>
    </div>
  );
}
