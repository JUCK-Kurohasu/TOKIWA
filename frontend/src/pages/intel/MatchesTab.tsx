/** Asset ↔ vulnerability matches with triage status (open / mitigated / accepted / false positive). */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "@/api/client";
import type { Page } from "@/api/types";
import { MATCH_STATUSES, type MatchStatus, type VulnMatchWithAsset } from "@/api/types-intel";
import { OffsetPager } from "@/components/common/OffsetPager";
import { ApiErrorState, QueryView } from "@/components/common/QueryView";
import { useCan } from "@/components/common/RoleGate";
import { useUrlParams } from "@/components/common/urlState";
import { Badge, Card, EmptyState, Select, Table, TBody, TD, TH, THead, TR } from "@/components/ui";
import { formatDateTime, pct } from "@/lib/format";
import { useLocal, useT } from "@/lib/i18n";
import { softwareLabel, useMatchStatusLabel } from "./labels";

const LIMIT = 50;

const strings = {
  ja: {
    vuln: "脆弱性",
    asset: "資産",
    software: "一致したソフトウェア",
    reason: "照合理由",
    confidence: "信頼度",
    created: "検出",
    empty: "資産一致はありません",
    emptyHint: "資産画面でソフトウェア（製品名・バージョン・CPE）を登録すると照合されます。",
    statusFilter: "状態で絞り込み",
    changeStatus: "状態を変更",
  },
  en: {
    vuln: "Vulnerability",
    asset: "Asset",
    software: "Matched software",
    reason: "Reason",
    confidence: "Confidence",
    created: "Detected",
    empty: "No asset matches",
    emptyHint:
      "Register software (product, version, CPE) on the Assets page to match against vulnerabilities.",
    statusFilter: "Filter by status",
    changeStatus: "Change status",
  },
};

export function MatchesTab({ onOpenVuln }: { onOpenVuln: (id: string) => void }) {
  const L = useLocal(strings);
  const t = useT();
  const can = useCan();
  const qc = useQueryClient();
  const label = useMatchStatusLabel();
  const [params, update] = useUrlParams();
  const status = params.get("status") ?? "open";
  const offset = Number(params.get("offset") ?? 0) || 0;

  const query = useQuery({
    queryKey: ["intel", "matches", { status, offset }],
    queryFn: () =>
      api.get<Page<VulnMatchWithAsset>>("/intel/matches", {
        status: status === "all" ? undefined : status,
        limit: LIMIT,
        offset,
      }),
    placeholderData: keepPreviousData,
  });

  const patch = useMutation({
    mutationFn: ({ id, next }: { id: string; next: MatchStatus }) =>
      api.patch(`/intel/matches/${encodeURIComponent(id)}`, { status: next }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["intel", "matches"] });
      qc.invalidateQueries({ queryKey: ["intel", "summary"] });
    },
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Select
          aria-label={L.statusFilter}
          value={status}
          onChange={(e) =>
            update({ status: e.target.value === "open" ? null : e.target.value, offset: null })
          }
        >
          <option value="all">{t("common.all")}</option>
          {MATCH_STATUSES.map((s) => (
            <option key={s} value={s}>
              {label(s)}
            </option>
          ))}
        </Select>
      </div>
      {patch.error ? <ApiErrorState error={patch.error} /> : null}
      <Card>
        <QueryView
          query={query}
          className="p-4"
          rows={6}
          isEmpty={(d) => d.items.length === 0}
          empty={<EmptyState title={L.empty} hint={L.emptyHint} />}
        >
          {(page) => (
            <>
              <Table>
                <THead>
                  <tr>
                    <TH>{L.vuln}</TH>
                    <TH>{L.asset}</TH>
                    <TH>{L.software}</TH>
                    <TH>{L.reason}</TH>
                    <TH>{L.confidence}</TH>
                    <TH>{t("common.status")}</TH>
                    <TH>{L.created}</TH>
                  </tr>
                </THead>
                <TBody>
                  {page.items.map((m) => (
                    <TR key={m.id}>
                      <TD>
                        <button
                          type="button"
                          className="font-mono text-xs text-accent hover:underline"
                          onClick={() => onOpenVuln(m.vuln_id)}
                        >
                          {m.vuln_id}
                        </button>
                      </TD>
                      <TD>
                        <Link
                          to={`/assets?asset=${encodeURIComponent(m.asset_id)}`}
                          className="hover:text-accent hover:underline"
                        >
                          {m.asset_name || <span className="font-mono text-xs">{m.asset_id}</span>}
                        </Link>
                      </TD>
                      <TD className="font-mono text-xs">{softwareLabel(m.software)}</TD>
                      <TD className="max-w-xs text-xs text-muted">{m.reason}</TD>
                      <TD className="tabular-nums text-xs">{pct(m.confidence)}</TD>
                      <TD>
                        {can.analyst ? (
                          <Select
                            aria-label={L.changeStatus}
                            className="h-7 text-xs"
                            value={m.status}
                            disabled={patch.isPending}
                            onChange={(e) => patch.mutate({ id: m.id, next: e.target.value as MatchStatus })}
                          >
                            {MATCH_STATUSES.map((s) => (
                              <option key={s} value={s}>
                                {label(s)}
                              </option>
                            ))}
                          </Select>
                        ) : (
                          <Badge tone={m.status === "open" ? "danger" : "neutral"}>{label(m.status)}</Badge>
                        )}
                      </TD>
                      <TD className="whitespace-nowrap text-xs text-muted">{formatDateTime(m.created_at)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
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
    </div>
  );
}
