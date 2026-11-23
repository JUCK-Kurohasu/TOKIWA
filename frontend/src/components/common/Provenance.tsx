/**
 * "Which token / sensor delivered this evidence" (audit #40), on the alert detail and in the approval dialog.
 *
 * A stolen ingest token can forge any source IP and sensor_id; the server-owned `ingest.*` labels are what
 * shows where the evidence really came from. Gate-only telemetry from a token without the `gate` scope is
 * flagged as low trust and raises a warning before anyone approves a block on its say-so.
 */
import { useQueries, useQuery } from "@tanstack/react-query";
import { KeyRound, ShieldAlert } from "lucide-react";
import { api } from "@/api/client";
import type { AlertDetail, IncidentDetail, ResponseAction, TkEvent } from "@/api/types";
import { Badge, Skeleton } from "@/components/ui";
import { useLocal } from "@/lib/i18n";
import { Mono } from "./index";
import { Notice } from "./OpsKit";
import { fmt } from "./opsLabels";
import { summarizeProvenance } from "./provenanceSummary";

/** Incident-only actions: provenance from at most this many of its alerts (one request each). */
export const MAX_INCIDENT_ALERTS = 5;

const strings = {
  ja: {
    title: "証拠を送ったトークン / センサー",
    token: "トークン",
    sensors: "センサー",
    datasets: "データセット",
    events: "{n} 件",
    noRecord: "出所の記録なし",
    noRecordHint:
      "出所ラベルが付く前のデータか、TOKIWA 内部で生成されたイベントです（安全という意味ではありません）。",
    claimed: "名乗った sensor_id: {s}（トークンの紐付けにより置き換え）",
    lowBadge: "低信頼 {n} 件",
    lowTitle: "gate スコープの無いトークンから届いた Gate / デセプションのテレメトリを含みます",
    lowBody:
      "{n} 件の証拠は、本来 TOKIWA Gate（gate スコープのトークン）だけが送るデータセットですが、gate スコープの無いトークンから届きました。そのトークンが盗まれていれば、送信元 IP やデコイ踏みを偽造して無実の IP を遮断させられます。承認の前に、送信元を別の証拠（Gate のログ・他のセンサー）で確かめてください。",
    scanned: "証拠イベント {n} 件から集計",
    scannedOf: "証拠イベント {total} 件のうち最新 {n} 件から集計",
    incidentScope: "インシデントのアラート {n} 件の証拠から集計（最大 {max} 件のアラート）",
    none: "証拠イベントがありません",
  },
  en: {
    title: "Token / sensor that delivered the evidence",
    token: "Token",
    sensors: "Sensors",
    datasets: "Datasets",
    events: "{n} event(s)",
    noRecord: "No provenance record",
    noRecordHint:
      "Data from before provenance labels, or events generated inside TOKIWA (this does not mean safe).",
    claimed: "Claimed sensor_id: {s} (replaced by the token's binding)",
    lowBadge: "{n} low trust",
    lowTitle: "Contains Gate / deception telemetry from a token without the gate scope",
    lowBody:
      "{n} evidence event(s) are datasets only TOKIWA Gate (a gate-scoped token) should send, but they came from a token without the gate scope. If that token was stolen, the source IP and decoy trips can be forged to get an innocent IP blocked. Before approving, confirm the source with other evidence (Gate logs, other sensors).",
    scanned: "From {n} evidence event(s)",
    scannedOf: "From the latest {n} of {total} evidence events",
    incidentScope: "From the evidence of {n} alert(s) of the incident (at most {max} alerts)",
    none: "No evidence events",
  },
};

export function ProvenancePanel({
  events,
  total,
  scope,
}: {
  events: readonly TkEvent[];
  /** Evidence ids on the alert (the API returns the newest 200 events). */
  total?: number;
  scope?: string;
}) {
  const L = useLocal(strings);
  const sum = summarizeProvenance(events);
  return (
    <div className="space-y-2 text-xs">
      {sum.lowTrust > 0 && (
        <Notice
          tone="danger"
          icon={<ShieldAlert className="h-4 w-4 text-sev-critical" aria-hidden />}
          title={L.lowTitle}
        >
          {fmt(L.lowBody, { n: sum.lowTrust })}
        </Notice>
      )}
      {sum.events === 0 ? (
        <p className="text-muted">{L.none}</p>
      ) : (
        <ul className="space-y-1.5">
          {sum.sources.map((s) => {
            const labelled = s.tokenId !== null || s.tokenName !== null;
            return (
              <li
                key={s.tokenId ?? s.tokenName ?? "-"}
                className="rounded border border-line bg-surface-2/50 p-2"
              >
                <div className="flex flex-wrap items-center gap-1.5">
                  <KeyRound className="h-3.5 w-3.5 text-muted" aria-hidden />
                  {labelled ? (
                    <>
                      <span className="text-muted">{L.token}</span>
                      <Mono className="font-medium text-fg">{s.tokenName ?? "?"}</Mono>
                      {s.tokenId && <Mono className="text-muted">({s.tokenId.slice(0, 8)})</Mono>}
                    </>
                  ) : (
                    <span className="font-medium text-muted" title={L.noRecordHint}>
                      {L.noRecord}
                    </span>
                  )}
                  <span className="text-muted">· {fmt(L.events, { n: s.events })}</span>
                  {s.lowTrust > 0 && <Badge tone="danger">{fmt(L.lowBadge, { n: s.lowTrust })}</Badge>}
                </div>
                <div className="mt-1 grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5">
                  <span className="text-muted">{L.sensors}</span>
                  <Mono className="break-all">{s.sensors.join(", ") || "-"}</Mono>
                  <span className="text-muted">{L.datasets}</span>
                  <Mono className="break-all">{s.datasets.join(", ") || "-"}</Mono>
                </div>
                {s.claimedSensors.length > 0 && (
                  <p className="mt-1 text-sev-medium">{fmt(L.claimed, { s: s.claimedSensors.join(", ") })}</p>
                )}
                {!labelled && <p className="mt-1 text-muted">{L.noRecordHint}</p>}
              </li>
            );
          })}
        </ul>
      )}
      <p className="text-[11px] text-muted">
        {scope ??
          (total !== undefined && total > sum.events
            ? fmt(L.scannedOf, { n: sum.events, total })
            : fmt(L.scanned, { n: sum.events }))}
      </p>
    </div>
  );
}

/** For the approval dialog: the evidence of the action's alert, or of (some of) its incident's alerts. */
export function ActionProvenance({ action }: { action: ResponseAction }) {
  const L = useLocal(strings);
  const alertId = action.alert_id ?? null;
  const incidentId = alertId ? null : (action.incident_id ?? null);
  const alertQ = useQuery({
    queryKey: ["alerts", "detail", alertId],
    queryFn: () => api.get<AlertDetail>(`/alerts/${encodeURIComponent(alertId ?? "")}`),
    enabled: !!alertId,
  });
  const incidentQ = useQuery({
    queryKey: ["incidents", "detail", incidentId],
    queryFn: () => api.get<IncidentDetail>(`/incidents/${encodeURIComponent(incidentId ?? "")}`),
    enabled: !!incidentId,
  });
  const incidentAlerts = (incidentQ.data?.alerts ?? []).slice(0, MAX_INCIDENT_ALERTS);
  const alertQs = useQueries({
    queries: incidentAlerts.map((a) => ({
      queryKey: ["alerts", "detail", a.id],
      queryFn: () => api.get<AlertDetail>(`/alerts/${encodeURIComponent(a.id)}`),
    })),
  });
  if (!alertId && !incidentId) return null; // a manual proposal without a linked alert / incident

  const loading = alertId ? alertQ.isLoading : incidentQ.isLoading || alertQs.some((x) => x.isLoading);
  const failed = alertId ? alertQ.error : (incidentQ.error ?? alertQs.find((x) => x.error)?.error);
  return (
    <section className="space-y-1.5">
      <h4 className="text-xs font-semibold text-muted">{L.title}</h4>
      {loading ? (
        <Skeleton className="h-14" />
      ) : failed ? (
        <p className="text-xs text-muted">{failed instanceof Error ? failed.message : String(failed)}</p>
      ) : alertId && alertQ.data ? (
        <ProvenancePanel events={alertQ.data.evidence ?? []} total={alertQ.data.evidence_event_ids?.length} />
      ) : (
        <ProvenancePanel
          events={alertQs.flatMap((x) => x.data?.evidence ?? [])}
          scope={fmt(L.incidentScope, { n: incidentAlerts.length, max: MAX_INCIDENT_ALERTS })}
        />
      )}
    </section>
  );
}
