/**
 * Suppressions tab of the Response page (audit #63): what humans said "do not propose / auto-approve again".
 *
 * Written by reject / revert (or POST /response/suppressions). While in force, rule / LLM proposals of the same
 * type for the same target are dropped ("suppress"), or only never auto-approved ("manual_only", the cooldown
 * after every human reject / revert). Lifting restores normal proposals.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BellOff } from "lucide-react";
import { useState } from "react";
import { api } from "@/api/client";
import type { Page } from "@/api/types";
import type { ResponseSuppression } from "@/api/types-ops";
import { Mono } from "@/components/common";
import { TableSkeleton } from "@/components/common/OpsKit";
import { fmt, useCanOperate } from "@/components/common/opsLabels";
import { ActionTypeTag } from "@/components/common/ResponseActions";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/ui";
import { dateTimeTitle, formatDateTime, timeAgo } from "@/lib/format";
import { useLocal } from "@/lib/i18n";

const strings = {
  ja: {
    lead: "却下・取り消しの記録です。「抑止」はルール・LLM からの同じ種別・同じ対象（重なる CIDR を含む）の提案を作らず、「自動承認なし」は提案はするが自動承認しません（却下・取り消しのたびに一定時間作られます）。",
    showAll: "期限切れ・解除済みも表示",
    empty: "有効な抑止はありません",
    colMode: "種類",
    colType: "種別",
    colTarget: "対象",
    colReason: "理由",
    colBy: "記録者",
    colUntil: "期限",
    colHits: "止めた提案",
    colCreated: "作成",
    suppress: "抑止",
    manualOnly: "自動承認なし",
    permanent: "恒久",
    lifted: "解除済み（{by}）",
    expired: "期限切れ",
    lift: "解除",
    liftConfirm: "{t} の抑止を解除しますか？以後は通常どおり提案（と自動承認）されます。",
  },
  en: {
    lead: "Records of rejects and reverts. “Suppress” stops rule / LLM proposals of the same type for the same target (including overlapping CIDRs); “No auto-approve” still proposes but never auto-approves (written for a while after every reject / revert).",
    showAll: "Include expired / lifted",
    empty: "No suppressions in force",
    colMode: "Kind",
    colType: "Type",
    colTarget: "Target",
    colReason: "Reason",
    colBy: "By",
    colUntil: "Until",
    colHits: "Stopped",
    colCreated: "Created",
    suppress: "Suppress",
    manualOnly: "No auto-approve",
    permanent: "Permanent",
    lifted: "Lifted ({by})",
    expired: "Expired",
    lift: "Lift",
    liftConfirm: "Lift the suppression for {t}? It will be proposed (and auto-approved) as usual again.",
  },
};

export function SuppressionsPanel() {
  const L = useLocal(strings);
  const canOperate = useCanOperate();
  const qc = useQueryClient();
  const [all, setAll] = useState(false);
  const q = useQuery({
    queryKey: ["response", "suppressions", all],
    queryFn: () =>
      api.get<Page<ResponseSuppression>>("/response/suppressions", {
        active: all ? "false" : "true",
        limit: 200,
      }),
    refetchInterval: 60_000,
  });
  const lift = useMutation({
    mutationFn: (id: string) => api.post<ResponseSuppression>(`/response/suppressions/${id}/lift`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["response", "suppressions"] }),
  });

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="max-w-3xl text-xs text-muted">{L.lead}</p>
        <label className="flex items-center gap-1.5 text-xs">
          <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} />
          {L.showAll}
        </label>
      </div>
      {lift.error && <ErrorState error={lift.error} />}
      {q.error ? (
        <ErrorState error={q.error} />
      ) : q.isLoading ? (
        <Card>
          <TableSkeleton rows={3} />
        </Card>
      ) : q.data?.items.length ? (
        <Card>
          <Table>
            <THead>
              <tr>
                <TH>{L.colMode}</TH>
                <TH>{L.colType}</TH>
                <TH>{L.colTarget}</TH>
                <TH>{L.colReason}</TH>
                <TH>{L.colBy}</TH>
                <TH>{L.colUntil}</TH>
                <TH>{L.colHits}</TH>
                <TH>{L.colCreated}</TH>
                <TH />
              </tr>
            </THead>
            <TBody>
              {q.data.items.map((s) => (
                <TR key={s.id}>
                  <TD>
                    <Badge tone={s.mode === "suppress" ? "warn" : "neutral"}>
                      <BellOff className="h-3 w-3" aria-hidden />
                      {s.mode === "suppress" ? L.suppress : L.manualOnly}
                    </Badge>
                  </TD>
                  <TD className="whitespace-nowrap">
                    <ActionTypeTag type={s.action_type} className="text-xs" />
                  </TD>
                  <TD>
                    <Mono className="break-all">{s.target}</Mono>
                  </TD>
                  <TD className="max-w-[260px] text-xs">
                    <span className="line-clamp-2 break-words" title={s.reason}>
                      {s.reason || "-"}
                    </span>
                  </TD>
                  <TD className="text-xs">{s.created_by}</TD>
                  <TD className="whitespace-nowrap text-xs" title={dateTimeTitle(s.expires_at)}>
                    {s.lifted_at
                      ? fmt(L.lifted, { by: s.lifted_by ?? "-" })
                      : !s.active
                        ? L.expired
                        : s.expires_at
                          ? formatDateTime(s.expires_at)
                          : L.permanent}
                  </TD>
                  <TD className="text-xs tabular-nums">{s.hits}</TD>
                  <TD className="whitespace-nowrap text-xs text-muted" title={dateTimeTitle(s.created_at)}>
                    {timeAgo(s.created_at)}
                  </TD>
                  <TD>
                    {canOperate && s.active && (
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={lift.isPending}
                        onClick={() => {
                          if (window.confirm(fmt(L.liftConfirm, { t: s.target }))) lift.mutate(s.id);
                        }}
                      >
                        {L.lift}
                      </Button>
                    )}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </Card>
      ) : (
        <Card>
          <EmptyState icon={<BellOff className="h-8 w-8" aria-hidden />} title={L.empty} />
        </Card>
      )}
    </div>
  );
}
