/**
 * Alert suppressions table (audit #166 / #173), shared by the Suppressions & allowlists page and the alert detail
 * (the suppression made when that alert was marked false positive). Lifting needs analyst; the API enforces it.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { BellOff, ShieldCheck } from "lucide-react";
import { Link } from "react-router";
import { api } from "@/api/client";
import type { AlertSuppression } from "@/api/types-ops";
import { Mono } from "@/components/common";
import { fmt, useCanOperate } from "@/components/common/opsLabels";
import { Badge, Button, ErrorState, Table, TBody, TD, TH, THead, TR } from "@/components/ui";
import { dateTimeTitle, formatDateTime, timeAgo } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { matchSummary, suppressionState } from "./suppression";

const strings = {
  ja: {
    colKind: "種類",
    colScope: "対象",
    colReason: "理由",
    colBy: "作成者",
    colUntil: "期限",
    colHits: "抑えた件数",
    colCreated: "作成",
    fp: "誤検知",
    allowlist: "許可リスト",
    modeSuppress: "記録しない",
    modeDowngrade: "info で記録",
    modeFpHint: "同じ検知は元のアラートの件数に加算",
    anyRule: "全ルール",
    anyPath: "全パス",
    anySource: "全送信元",
    maxSev: "重大度 {s} まで",
    fromAlert: "元のアラート",
    permanent: "恒久",
    lifted: "解除済み（{by}）",
    expired: "期限切れ",
    lastHit: "最終 {t}",
    lift: "解除",
    liftConfirmFp:
      "この誤検知の抑制を解除しますか？以後、同じ検知は新しいアラートとしてトリアージ・通知されます。アラートの状態（誤検知）は変わりません。",
    liftConfirmAllow:
      "{cidr} の許可リストを解除しますか？以後、この送信元からの検知は通常どおりアラート・提案・通知されます。",
  },
  en: {
    colKind: "Kind",
    colScope: "Scope",
    colReason: "Reason",
    colBy: "By",
    colUntil: "Until",
    colHits: "Held back",
    colCreated: "Created",
    fp: "False positive",
    allowlist: "Allowlist",
    modeSuppress: "Not recorded",
    modeDowngrade: "Recorded as info",
    modeFpHint: "Recurrences are counted on the original alert",
    anyRule: "All rules",
    anyPath: "All paths",
    anySource: "All sources",
    maxSev: "Up to {s}",
    fromAlert: "Source alert",
    permanent: "Permanent",
    lifted: "Lifted ({by})",
    expired: "Expired",
    lastHit: "last {t}",
    lift: "Lift",
    liftConfirmFp:
      "Lift this false-positive suppression? The same finding will raise, triage and notify as a new alert again. The alert keeps its false-positive status.",
    liftConfirmAllow:
      "Lift the allowlist for {cidr}? Detections from this source raise alerts, proposals and notifications as usual again.",
  },
};

export function SuppressionTable({
  items,
  invalidate = [["alert-suppressions"]],
  showSourceAlert = true,
}: {
  items: AlertSuppression[];
  invalidate?: unknown[][];
  showSourceAlert?: boolean;
}) {
  const L = useLocal(strings);
  const canOperate = useCanOperate();
  const qc = useQueryClient();
  const lift = useMutation({
    mutationFn: (id: string) =>
      api.post<AlertSuppression>(`/alert-suppressions/${encodeURIComponent(id)}/lift`),
    onSuccess: () => {
      for (const key of invalidate) void qc.invalidateQueries({ queryKey: key });
    },
  });

  return (
    <div className="space-y-2">
      {lift.error ? <ErrorState error={lift.error} /> : null}
      <Table>
        <THead>
          <tr>
            <TH>{L.colKind}</TH>
            <TH>{L.colScope}</TH>
            <TH>{L.colReason}</TH>
            <TH>{L.colBy}</TH>
            <TH>{L.colUntil}</TH>
            <TH>{L.colHits}</TH>
            <TH>{L.colCreated}</TH>
            <TH />
          </tr>
        </THead>
        <TBody>
          {items.map((s) => {
            const state = suppressionState(s);
            const isFp = s.kind === "false_positive";
            const match = matchSummary(s.match ?? {});
            return (
              <TR key={s.id} className={state === "active" ? undefined : "opacity-70"}>
                <TD className="whitespace-nowrap">
                  <div className="flex flex-col items-start gap-1">
                    <Badge tone={isFp ? "neutral" : "warn"}>
                      {isFp ? (
                        <BellOff className="h-3 w-3" aria-hidden />
                      ) : (
                        <ShieldCheck className="h-3 w-3" aria-hidden />
                      )}
                      {isFp ? L.fp : L.allowlist}
                    </Badge>
                    <span className="text-[11px] text-muted">
                      {isFp ? L.modeFpHint : s.mode === "suppress" ? L.modeSuppress : L.modeDowngrade}
                    </span>
                  </div>
                </TD>
                <TD className="max-w-[320px] text-xs">
                  <div className="space-y-0.5">
                    <div>
                      <Mono className="break-all">{s.rule_id ?? L.anyRule}</Mono>
                    </div>
                    <div className="text-muted">
                      <Mono className="break-all">{s.path_key ?? L.anyPath}</Mono>
                      {" · "}
                      <Mono className="break-all">{s.source_cidr ?? L.anySource}</Mono>
                    </div>
                    {match.map((m) => (
                      <div key={m} className="break-all text-muted">
                        {m}
                      </div>
                    ))}
                    {s.max_severity && (
                      <div className="text-muted">{fmt(L.maxSev, { s: s.max_severity })}</div>
                    )}
                    {showSourceAlert && s.source_alert_id && (
                      <Link to={`/alerts/${s.source_alert_id}`} className="text-accent hover:underline">
                        {L.fromAlert} {s.source_alert_id.slice(0, 8)}
                      </Link>
                    )}
                  </div>
                </TD>
                <TD className="max-w-[240px] text-xs">
                  <span className="line-clamp-2 break-words" title={s.reason}>
                    {s.reason || "-"}
                  </span>
                </TD>
                <TD className="text-xs">{s.created_by || "-"}</TD>
                <TD className="whitespace-nowrap text-xs" title={dateTimeTitle(s.expires_at)}>
                  {state === "lifted"
                    ? fmt(L.lifted, { by: s.lifted_by ?? "-" })
                    : state === "expired"
                      ? L.expired
                      : s.expires_at
                        ? formatDateTime(s.expires_at)
                        : L.permanent}
                </TD>
                <TD className="text-xs tabular-nums">
                  {s.hits}
                  {s.last_hit_at && (
                    <div className="text-[11px] text-muted" title={dateTimeTitle(s.last_hit_at)}>
                      {fmt(L.lastHit, { t: timeAgo(s.last_hit_at) })}
                    </div>
                  )}
                </TD>
                <TD className="whitespace-nowrap text-xs text-muted" title={dateTimeTitle(s.created_at)}>
                  {timeAgo(s.created_at)}
                </TD>
                <TD>
                  {canOperate && state === "active" && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={lift.isPending}
                      onClick={() => {
                        const msg = isFp
                          ? L.liftConfirmFp
                          : fmt(L.liftConfirmAllow, { cidr: s.source_cidr ?? "-" });
                        if (window.confirm(msg)) lift.mutate(s.id);
                      }}
                    >
                      {L.lift}
                    </Button>
                  )}
                </TD>
              </TR>
            );
          })}
        </TBody>
      </Table>
    </div>
  );
}
