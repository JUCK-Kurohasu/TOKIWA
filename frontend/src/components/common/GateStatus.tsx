/**
 * Is an approved Gate action actually enforced? (audit #145)
 *
 * Approval only marks block_ip / rate_limit / tarpit / deceive as `active`; a TOKIWA Gate enforces it once it
 * pulls a policy that contains it, and only for requests that pass through that Gate. `GET /gate/status` says
 * which Gates polled and when; these components turn that into "no Gate" / "approved, not yet applied" /
 * "applied by n Gates (hh:mm)" so "active" is never read as "blocked everywhere".
 */
import { useQuery } from "@tanstack/react-query";
import { CircleAlert, CircleCheck, CircleDashed, ServerOff } from "lucide-react";
import { api } from "@/api/client";
import type { ActionType, GateStatus, ResponseAction } from "@/api/types";
import { dateTimeTitle } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { formatClock } from "./numfmt";
import { fmt } from "./opsLabels";

/** Action types enforced by the Gate policy (respond/validate.py GATE_ACTIONS). */
export const GATE_ACTION_TYPES: ReadonlySet<ActionType> = new Set<ActionType>([
  "block_ip",
  "rate_limit",
  "tarpit",
  "deceive",
]);

export function useGateStatus(enabled = true) {
  return useQuery({
    queryKey: ["gate", "status"],
    queryFn: () => api.get<GateStatus>("/gate/status"),
    enabled,
    staleTime: 15_000,
    refetchInterval: 30_000,
    retry: false,
  });
}

export type Reflection =
  | { kind: "unknown" }
  | { kind: "no_gate" }
  | { kind: "pending" }
  | { kind: "applied"; gates: number; at: string | null }
  | { kind: "applied_stale"; gates: number; at: string | null };

/** Pure: where does this action stand according to /gate/status? */
export function reflectionOf(status: GateStatus | undefined, actionId: string): Reflection {
  if (!status) return { kind: "unknown" };
  if (status.gates.length === 0) return { kind: "no_gate" };
  const ref = status.actions.find((a) => a.action_id === actionId);
  if (!ref || ref.gates_applied === 0) return { kind: "pending" };
  if (ref.gates_applied_fresh > 0)
    return { kind: "applied", gates: ref.gates_applied_fresh, at: ref.last_applied_at };
  return { kind: "applied_stale", gates: ref.gates_applied, at: ref.last_applied_at };
}

const strings = {
  ja: {
    unknown: "Gate への反映状況を取得できません。",
    noGate: "反映先 Gate なし — ポリシーを取得した Gate が 1 台もないため、この対処は強制されていません。",
    pending: "承認済み（未反映）— Gate がまだこの対処を含むポリシーを取得していません。",
    applied: "Gate {n} 台に反映済み（{t}）",
    appliedStale:
      "Gate {n} 台に反映済み（{t}）。ただし最終取得から {m} 分以上経過しています（Gate が停止している可能性）。",
    noticeNoGate:
      "TOKIWA Gate が 1 台もポリシーを取得していません。IP 遮断・レート制限・ターピット・デコイ誘導は「実行中」でも強制されていません。Gate を設置・起動してください。",
    noticeStale: "Gate {n} 台が {m} 分以上ポリシーを取得していません: {names}",
    noticeOk: "Gate {n} 台がポリシーを取得中（最新 {t}）。",
    scope: "遮断などは Gate を経由するリクエストにだけ効きます（Gate を通らない経路は対象外）。",
  },
  en: {
    unknown: "Cannot tell whether a Gate has applied this.",
    noGate: "No Gate to apply it — no Gate has pulled the policy, so this action is not enforced.",
    pending: "Approved (not applied yet) — no Gate has pulled a policy containing this action yet.",
    applied: "Applied by {n} Gate(s) ({t})",
    appliedStale:
      "Applied by {n} Gate(s) ({t}), but none has polled for over {m} min (the Gate may be down).",
    noticeNoGate:
      "No TOKIWA Gate has pulled the policy. Block / rate-limit / tarpit / divert actions are not enforced even while 'Active'. Deploy and start a Gate.",
    noticeStale: "{n} Gate(s) have not pulled the policy for over {m} min: {names}",
    noticeOk: "{n} Gate(s) pulling the policy (latest {t}).",
    scope: "Blocks and the like only affect requests that pass through a Gate (other paths are not covered).",
  },
};

function minutes(status: GateStatus): number {
  return Math.round(status.stale_after_seconds / 60);
}

/** One line under an active Gate action (ActionCard). Renders nothing for other action types / states. */
export function GateReflection({ action, className }: { action: ResponseAction; className?: string }) {
  const L = useLocal(strings);
  const relevant =
    GATE_ACTION_TYPES.has(action.action_type) && (action.status === "active" || action.status === "approved");
  const q = useGateStatus(relevant);
  if (!relevant || q.isLoading) return null;
  const r = reflectionOf(q.data, action.id);
  const base = "mt-1 flex items-start gap-1.5 text-xs";
  switch (r.kind) {
    case "unknown":
      return (
        <p className={cn(base, "text-muted", className)}>
          <CircleDashed className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden />
          {L.unknown}
        </p>
      );
    case "no_gate":
      return (
        <p className={cn(base, "font-medium text-sev-critical", className)} role="status">
          <ServerOff className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden />
          {L.noGate}
        </p>
      );
    case "pending":
      return (
        <p className={cn(base, "text-sev-medium", className)} role="status">
          <CircleDashed className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden />
          {L.pending}
        </p>
      );
    case "applied":
      return (
        <p className={cn(base, "text-accent", className)} title={dateTimeTitle(r.at)}>
          <CircleCheck className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden />
          {fmt(L.applied, { n: r.gates, t: r.at ? formatClock(r.at) : "-" })}
        </p>
      );
    case "applied_stale":
      return (
        <p className={cn(base, "text-sev-medium", className)} title={dateTimeTitle(r.at)} role="status">
          <CircleAlert className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden />
          {fmt(L.appliedStale, {
            n: r.gates,
            t: r.at ? formatClock(r.at) : "-",
            m: q.data ? minutes(q.data) : "-",
          })}
        </p>
      );
  }
}

/** Page-level summary for the Response page: no Gate / stale Gates / n Gates polling. */
export function GateStatusNotice({ className }: { className?: string }) {
  const L = useLocal(strings);
  const q = useGateStatus();
  const s = q.data;
  if (!s) return null;
  const stale = s.gates.filter((g) => g.stale);
  const fresh = s.gates.filter((g) => !g.stale);
  const latest = s.gates.reduce<string | null>(
    (m, g) => (m == null || g.last_seen > m ? g.last_seen : m),
    null,
  );
  const tone =
    s.gates.length === 0 || fresh.length === 0
      ? "border-sev-critical/40 bg-sev-critical/10"
      : stale.length
        ? "border-sev-medium/40 bg-sev-medium/10"
        : "border-line bg-surface-2/50";
  return (
    <div className={cn("space-y-0.5 rounded-md border px-3 py-2 text-xs", tone, className)} role="status">
      {s.gates.length === 0 ? (
        <p className="font-medium text-sev-critical">{L.noticeNoGate}</p>
      ) : (
        <>
          {fresh.length > 0 && (
            <p title={dateTimeTitle(latest)}>
              {fmt(L.noticeOk, { n: fresh.length, t: latest ? formatClock(latest) : "-" })}
            </p>
          )}
          {stale.length > 0 && (
            <p className={fresh.length ? "text-sev-medium" : "font-medium text-sev-critical"}>
              {fmt(L.noticeStale, {
                n: stale.length,
                m: minutes(s),
                names: stale.map((g) => `${g.token_name} (${g.source_ip})`).join(", "),
              })}
            </p>
          )}
        </>
      )}
      <p className="text-muted">{L.scope}</p>
    </div>
  );
}
