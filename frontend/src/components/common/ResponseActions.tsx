/**
 * Response-action UI shared by the Response page and incident detail (FR-12).
 *
 * Every action goes proposed -> (human approves) -> executor -> active (TTL) -> expired / reverted.
 * The UI states explicitly that nothing runs without approval, shows what the executor will do before
 * the analyst confirms, and flags LLM-authored proposals so the target is checked against evidence.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Ban,
  BellRing,
  Bird,
  BrickWall,
  Check,
  Gauge,
  Ghost,
  Hourglass,
  type LucideIcon,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
  Undo2,
  Webhook,
  X,
} from "lucide-react";
import { type FormEvent, useState } from "react";
import { Link } from "react-router";
import { api } from "@/api/client";
import type { ActionStatus, ActionType, ResponseAction } from "@/api/types";
import { ACTION_TYPES, type ActionProposal, type ActionRejectBody, IP_TARGET_ACTIONS } from "@/api/types-ops";
import { Badge, Button, Dialog, ErrorState, Input, Label, Select, Textarea } from "@/components/ui";
import { formatDateTime, timeAgo } from "@/lib/format";
import { useLabel, useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { Notice } from "./OpsKit";
import {
  actionStatusLabel,
  actionTypeEffect,
  actionTypeLabel,
  fmt,
  formatDuration,
  formatTtl,
  labelOf,
  proposerLabel,
  useCanOperate,
  useNow,
} from "./opsLabels";

export const actionTypeIcon: Record<ActionType, LucideIcon> = {
  block_ip: Ban,
  rate_limit: Gauge,
  tarpit: Hourglass,
  deceive: Ghost,
  deploy_canary: Bird,
  notify: BellRing,
  webhook: Webhook,
  nftables_block: BrickWall,
};

const statusTone: Record<ActionStatus, "neutral" | "accent" | "ai" | "warn" | "danger"> = {
  proposed: "warn",
  approved: "accent",
  active: "accent",
  expired: "neutral",
  reverted: "neutral",
  rejected: "neutral",
  failed: "danger",
};

export function ActionStatusBadge({ status }: { status: ActionStatus }) {
  const label = useLabel();
  return (
    <Badge tone={statusTone[status] ?? "neutral"}>
      {status === "active" && (
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" aria-hidden />
      )}
      {label(labelOf(actionStatusLabel, status))}
    </Badge>
  );
}

export function ProposerBadge({ proposer }: { proposer: ResponseAction["proposed_by"] }) {
  const label = useLabel();
  if (proposer === "llm")
    return (
      <Badge tone="ai">
        <Sparkles className="h-3 w-3" aria-hidden />
        {label(proposerLabel.llm)}
      </Badge>
    );
  return <Badge>{label(labelOf(proposerLabel, proposer))}</Badge>;
}

export function ActionTypeTag({ type, className }: { type: ActionType; className?: string }) {
  const label = useLabel();
  const Icon = actionTypeIcon[type] ?? ShieldCheck;
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-sm font-medium", className)}>
      <Icon className="h-4 w-4 text-accent" aria-hidden />
      {label(labelOf(actionTypeLabel, type))}
    </span>
  );
}

const noticeStrings = {
  ja: {
    title: "承認なしでは実行されません",
    body: "対処は「提案」として作成され、analyst 以上の担当者が承認した時点で初めて実行されます。遮断はすべて TTL 付きで可逆です（期限切れ・取り消しで解除）。LLM の提案も同じ承認フローを通ります。",
    short: "承認なしでは実行されません。すべて TTL 付き・取り消し可能。",
  },
  en: {
    title: "Nothing runs without approval",
    body: "Actions are created as proposals and execute only when an analyst approves them. Every block is reversible with a TTL (expiry or manual revert). LLM proposals go through the same approval flow.",
    short: "Nothing runs without human approval. All actions are TTL-bound and reversible.",
  },
};

/** The human-in-the-loop guarantee, stated in the UI. */
export function ApprovalNotice({ compact = false, className }: { compact?: boolean; className?: string }) {
  const L = useLocal(noticeStrings);
  if (compact)
    return (
      <p className={cn("flex items-center gap-1.5 text-xs text-muted", className)}>
        <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-accent" aria-hidden />
        {L.short}
      </p>
    );
  return (
    <Notice
      tone="accent"
      icon={<ShieldCheck className="h-4 w-4 text-accent" aria-hidden />}
      title={L.title}
      className={className}
    >
      {L.body}
    </Notice>
  );
}

function useInvalidateActions() {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: ["response"] });
    void qc.invalidateQueries({ queryKey: ["incidents", "detail"] });
  };
}

const cardStrings = {
  ja: {
    approve: "承認…",
    reject: "却下…",
    revert: "取り消し…",
    ttl: "TTL",
    noTtl: "TTL 未指定（サーバー既定）",
    created: "作成",
    incident: "インシデント",
    alert: "アラート",
    approvedBy: "承認",
    autoApproved: "ポリシーにより自動承認",
    remaining: "残り {d}",
    until: "{t} まで",
    expiredAt: "期限 {t}",
    noExpiry: "期限なし（手動で取り消すまで有効）",
    viewerHint: "操作には analyst 以上の権限が必要です",
    notReversible: "取り消し不可",
    error: "エラー",
  },
  en: {
    approve: "Approve…",
    reject: "Reject…",
    revert: "Revert…",
    ttl: "TTL",
    noTtl: "No TTL (server default)",
    created: "Created",
    incident: "Incident",
    alert: "Alert",
    approvedBy: "Approved by",
    autoApproved: "Auto-approved by policy",
    remaining: "{d} left",
    until: "until {t}",
    expiredAt: "Expires {t}",
    noExpiry: "No expiry (active until reverted)",
    viewerHint: "Requires analyst role",
    notReversible: "Not reversible",
    error: "Error",
  },
};

/** TTL progress for an active action. */
export function ExpiryBar({ action }: { action: ResponseAction }) {
  const L = useLocal(cardStrings);
  const now = useNow(30_000);
  if (!action.expires_at) return <p className="text-xs text-muted">{L.noExpiry}</p>;
  const end = new Date(action.expires_at).getTime();
  const start = new Date(action.executed_at ?? action.approved_at ?? action.created_at).getTime();
  const total = Math.max(1, end - start);
  const left = end - now;
  const pct = Math.min(100, Math.max(0, ((now - start) / total) * 100));
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className={cn("font-medium tabular-nums", left < 5 * 60_000 ? "text-sev-medium" : "text-fg")}>
          {left > 0
            ? fmt(L.remaining, { d: formatDuration(left) })
            : fmt(L.expiredAt, { t: formatDateTime(action.expires_at) })}
        </span>
        <span className="text-muted">{fmt(L.until, { t: formatDateTime(action.expires_at) })}</span>
      </div>
      <div className="h-1 overflow-hidden rounded-full bg-surface-2">
        <div className="h-full bg-accent" style={{ width: `${100 - pct}%` }} />
      </div>
    </div>
  );
}

function failureMessage(a: ResponseAction): string | null {
  const err = a.result?.error ?? a.result?.message;
  return typeof err === "string" && err ? err : null;
}

/** A single action with the controls that make sense for its status. */
export function ActionCard({ action, showLinks = true }: { action: ResponseAction; showLinks?: boolean }) {
  const L = useLocal(cardStrings);
  const label = useLabel();
  const canOperate = useCanOperate();
  const [dialog, setDialog] = useState<null | "approve" | "reject" | "revert">(null);
  const isPending = action.status === "proposed";
  const isActive = action.status === "active" || action.status === "approved";
  const failure = action.status === "failed" ? failureMessage(action) : null;

  return (
    <div
      className={cn(
        "rounded-lg border bg-surface p-3",
        isPending ? "border-sev-medium/40" : isActive ? "border-accent/40" : "border-line",
      )}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <ActionTypeTag type={action.action_type} />
            <span className="break-all rounded bg-surface-2 px-1.5 py-0.5 font-mono text-sm">
              {action.target}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <ActionStatusBadge status={action.status} />
            <ProposerBadge proposer={action.proposed_by} />
            {action.approved_by === "policy" && <Badge tone="warn">{L.autoApproved}</Badge>}
            {!action.reversible && (
              <Badge tone="danger">
                <TriangleAlert className="h-3 w-3" aria-hidden />
                {L.notReversible}
              </Badge>
            )}
          </div>
        </div>
        {canOperate ? (
          <div className="flex shrink-0 gap-1.5">
            {isPending && (
              <>
                <Button size="sm" onClick={() => setDialog("approve")}>
                  <Check className="h-3.5 w-3.5" aria-hidden />
                  {L.approve}
                </Button>
                <Button size="sm" variant="outline" onClick={() => setDialog("reject")}>
                  <X className="h-3.5 w-3.5" aria-hidden />
                  {L.reject}
                </Button>
              </>
            )}
            {isActive && action.reversible && (
              <Button size="sm" variant="outline" onClick={() => setDialog("revert")}>
                <Undo2 className="h-3.5 w-3.5" aria-hidden />
                {L.revert}
              </Button>
            )}
          </div>
        ) : (
          (isPending || isActive) && <span className="text-[11px] text-muted">{L.viewerHint}</span>
        )}
      </div>

      {action.reason && (
        <p className="mt-2 whitespace-pre-wrap break-words text-sm text-fg/90">{action.reason}</p>
      )}
      <p className="mt-1 text-xs text-muted">{label(labelOf(actionTypeEffect, action.action_type))}</p>

      {failure && (
        <p className="mt-2 rounded border border-sev-critical/30 bg-sev-critical/10 px-2 py-1 text-xs text-sev-critical">
          {L.error}: {failure}
        </p>
      )}

      {action.status === "active" && (
        <div className="mt-3">
          <ExpiryBar action={action} />
        </div>
      )}

      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted">
        <span>
          {L.ttl}: {action.ttl_minutes ? formatTtl(action.ttl_minutes) : L.noTtl}
        </span>
        <span title={formatDateTime(action.created_at)}>
          {L.created}: {timeAgo(action.created_at)}
        </span>
        {action.approved_by && (
          <span title={formatDateTime(action.approved_at)}>
            {L.approvedBy}: {action.approved_by}
          </span>
        )}
        {showLinks && action.incident_id && (
          <Link to={`/incidents/${action.incident_id}`} className="text-accent hover:underline">
            {L.incident} {action.incident_id.slice(0, 8)}
          </Link>
        )}
        {showLinks && action.alert_id && (
          <Link to={`/alerts/${action.alert_id}`} className="text-accent hover:underline">
            {L.alert} {action.alert_id.slice(0, 8)}
          </Link>
        )}
      </div>

      <ApproveDialog action={action} open={dialog === "approve"} onClose={() => setDialog(null)} />
      <RejectDialog action={action} open={dialog === "reject"} onClose={() => setDialog(null)} />
      <RevertDialog action={action} open={dialog === "revert"} onClose={() => setDialog(null)} />
    </div>
  );
}

const dialogStrings = {
  ja: {
    approveTitle: "対処を承認して実行",
    approveConfirm: "承認して実行",
    approveLead: "承認すると、次の対処が直ちに実行されます。",
    target: "対象",
    type: "種別",
    reason: "理由",
    ttl: "有効期間",
    ttlAuto: "{d} 後に自動で解除されます",
    ttlNone: "TTL 未指定 — サーバー既定値が適用されます",
    llmWarn:
      "この提案は LLM が生成しました。対象（IP/CIDR）と理由が証拠と一致するか確認してから承認してください。",
    notReversible: "この対処は取り消せません。",
    doneActive: "実行しました。対処は有効です。",
    doneOther: "承認しました（状態: {s}）。",
    doneFailed: "実行に失敗しました",
    close: "閉じる",
    cancel: "キャンセル",
    rejectTitle: "提案を却下",
    rejectConfirm: "却下する",
    rejectReason: "却下理由（任意・監査ログに残ります）",
    rejectPlaceholder: "例: 正規の監視サービスからのアクセス",
    revertTitle: "対処を取り消し",
    revertConfirm: "取り消す",
    revertLead: "取り消すと、この対処は直ちに解除されます（Gate は次回のポリシー取得で反映）。",
  },
  en: {
    approveTitle: "Approve and execute action",
    approveConfirm: "Approve & execute",
    approveLead: "Approving executes the following action immediately.",
    target: "Target",
    type: "Type",
    reason: "Reason",
    ttl: "Duration",
    ttlAuto: "Automatically lifted after {d}",
    ttlNone: "No TTL — the server default applies",
    llmWarn:
      "This proposal was generated by the LLM. Check that the target (IP/CIDR) and reason match the evidence before approving.",
    notReversible: "This action cannot be reverted.",
    doneActive: "Executed. The action is now active.",
    doneOther: "Approved (status: {s}).",
    doneFailed: "Execution failed",
    close: "Close",
    cancel: "Cancel",
    rejectTitle: "Reject proposal",
    rejectConfirm: "Reject",
    rejectReason: "Reason (optional, recorded in the audit log)",
    rejectPlaceholder: "e.g. traffic from a legitimate monitoring service",
    revertTitle: "Revert action",
    revertConfirm: "Revert",
    revertLead: "Reverting lifts this action immediately (the Gate applies it on its next policy pull).",
  },
};

function ActionSummary({ action }: { action: ResponseAction }) {
  const L = useLocal(dialogStrings);
  const label = useLabel();
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2 rounded-md border border-line bg-surface-2/50 p-3 text-sm">
      <dt className="text-muted">{L.type}</dt>
      <dd>
        <ActionTypeTag type={action.action_type} />
        <p className="mt-0.5 text-xs text-muted">{label(labelOf(actionTypeEffect, action.action_type))}</p>
      </dd>
      <dt className="text-muted">{L.target}</dt>
      <dd className="break-all font-mono">{action.target}</dd>
      <dt className="text-muted">{L.ttl}</dt>
      <dd className="text-xs">
        {action.ttl_minutes ? fmt(L.ttlAuto, { d: formatTtl(action.ttl_minutes) }) : L.ttlNone}
      </dd>
      {action.reason && (
        <>
          <dt className="text-muted">{L.reason}</dt>
          <dd className="whitespace-pre-wrap break-words text-xs">{action.reason}</dd>
        </>
      )}
    </dl>
  );
}

function ApproveDialog({
  action,
  open,
  onClose,
}: {
  action: ResponseAction;
  open: boolean;
  onClose: () => void;
}) {
  const L = useLocal(dialogStrings);
  const label = useLabel();
  const invalidate = useInvalidateActions();
  const m = useMutation({
    mutationFn: () => api.post<ResponseAction>(`/response/actions/${action.id}/approve`),
    onSuccess: invalidate,
  });
  const close = () => {
    m.reset();
    onClose();
  };
  const done = m.data;
  return (
    <Dialog
      open={open}
      onClose={close}
      title={L.approveTitle}
      footer={
        done ? (
          <Button onClick={close}>{L.close}</Button>
        ) : (
          <>
            <Button variant="ghost" onClick={close}>
              {L.cancel}
            </Button>
            <Button onClick={() => m.mutate()} disabled={m.isPending}>
              <Check className="h-4 w-4" aria-hidden />
              {L.approveConfirm}
            </Button>
          </>
        )
      }
    >
      <div className="space-y-3">
        {!done && <p className="text-sm">{L.approveLead}</p>}
        <ActionSummary action={done ?? action} />
        {!done && action.proposed_by === "llm" && (
          <Notice tone="ai" icon={<Sparkles className="h-4 w-4 text-ai" aria-hidden />}>
            {L.llmWarn}
          </Notice>
        )}
        {!done && !action.reversible && (
          <Notice tone="danger" icon={<TriangleAlert className="h-4 w-4 text-sev-critical" aria-hidden />}>
            {L.notReversible}
          </Notice>
        )}
        {m.error && <ErrorState error={m.error} />}
        {done &&
          (done.status === "failed" ? (
            <Notice tone="danger" title={L.doneFailed}>
              {failureMessage(done) ?? JSON.stringify(done.result)}
            </Notice>
          ) : (
            <Notice tone="accent" icon={<ShieldCheck className="h-4 w-4 text-accent" aria-hidden />}>
              {done.status === "active"
                ? L.doneActive
                : fmt(L.doneOther, { s: label(labelOf(actionStatusLabel, done.status)) })}
            </Notice>
          ))}
      </div>
    </Dialog>
  );
}

function RejectDialog({
  action,
  open,
  onClose,
}: {
  action: ResponseAction;
  open: boolean;
  onClose: () => void;
}) {
  const L = useLocal(dialogStrings);
  const invalidate = useInvalidateActions();
  const [reason, setReason] = useState("");
  const m = useMutation({
    mutationFn: () =>
      api.post<ResponseAction>(`/response/actions/${action.id}/reject`, {
        reason: reason.trim() || undefined,
      } satisfies ActionRejectBody),
    onSuccess: () => {
      invalidate();
      setReason("");
      onClose();
    },
  });
  const close = () => {
    m.reset();
    onClose();
  };
  const fieldId = `reject-reason-${action.id}`;
  return (
    <Dialog
      open={open}
      onClose={close}
      title={L.rejectTitle}
      footer={
        <>
          <Button variant="ghost" onClick={close}>
            {L.cancel}
          </Button>
          <Button variant="danger" onClick={() => m.mutate()} disabled={m.isPending}>
            <X className="h-4 w-4" aria-hidden />
            {L.rejectConfirm}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <ActionSummary action={action} />
        <div>
          <Label htmlFor={fieldId}>{L.rejectReason}</Label>
          <Textarea
            id={fieldId}
            rows={3}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder={L.rejectPlaceholder}
            maxLength={1000}
          />
        </div>
        {m.error && <ErrorState error={m.error} />}
      </div>
    </Dialog>
  );
}

function RevertDialog({
  action,
  open,
  onClose,
}: {
  action: ResponseAction;
  open: boolean;
  onClose: () => void;
}) {
  const L = useLocal(dialogStrings);
  const invalidate = useInvalidateActions();
  const m = useMutation({
    mutationFn: () => api.post<ResponseAction>(`/response/actions/${action.id}/revert`),
    onSuccess: () => {
      invalidate();
      onClose();
    },
  });
  const close = () => {
    m.reset();
    onClose();
  };
  return (
    <Dialog
      open={open}
      onClose={close}
      title={L.revertTitle}
      footer={
        <>
          <Button variant="ghost" onClick={close}>
            {L.cancel}
          </Button>
          <Button variant="danger" onClick={() => m.mutate()} disabled={m.isPending}>
            <Undo2 className="h-4 w-4" aria-hidden />
            {L.revertConfirm}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-sm">{L.revertLead}</p>
        <ActionSummary action={action} />
        {m.error && <ErrorState error={m.error} />}
      </div>
    </Dialog>
  );
}

const proposeStrings = {
  ja: {
    title: "対処を提案",
    type: "種別",
    target: "対象",
    targetIp: "IP アドレスまたは CIDR（例: 203.0.113.7, 198.51.100.0/24）",
    targetOther: "対象（例: チャネル名・資産名）",
    ttl: "TTL（分, 1〜10080）",
    ttlHint: "空欄でサーバー既定値",
    reason: "理由",
    reasonPlaceholder: "なぜこの対処が必要か（監査ログに残ります）",
    submit: "提案を作成",
    cancel: "キャンセル",
    created: "提案を作成しました。承認待ちです。",
    open: "対処画面を開く",
    close: "閉じる",
    errTarget: "対象を入力してください",
    errReason: "理由を入力してください",
    errTtl: "TTL は 1〜10080 分の整数で指定してください",
  },
  en: {
    title: "Propose action",
    type: "Type",
    target: "Target",
    targetIp: "IP address or CIDR (e.g. 203.0.113.7, 198.51.100.0/24)",
    targetOther: "Target (e.g. channel or asset name)",
    ttl: "TTL (minutes, 1–10080)",
    ttlHint: "Leave empty for the server default",
    reason: "Reason",
    reasonPlaceholder: "Why this action is needed (recorded in the audit log)",
    submit: "Create proposal",
    cancel: "Cancel",
    created: "Proposal created. It is awaiting approval.",
    open: "Open Response",
    close: "Close",
    errTarget: "Enter a target",
    errReason: "Enter a reason",
    errTtl: "TTL must be an integer between 1 and 10080 minutes",
  },
};

/** Manual proposal (status=proposed). Validation is repeated server-side (allow-list, protected CIDRs, TTL cap). */
export function ProposeActionDialog({
  open,
  onClose,
  defaults,
}: {
  open: boolean;
  onClose: () => void;
  defaults?: Partial<Pick<ActionProposal, "target" | "incident_id" | "alert_id" | "action_type" | "reason">>;
}) {
  const L = useLocal(proposeStrings);
  const label = useLabel();
  const invalidate = useInvalidateActions();
  const [type, setType] = useState<ActionType>(defaults?.action_type ?? "block_ip");
  const [target, setTarget] = useState(defaults?.target ?? "");
  const [ttl, setTtl] = useState("60");
  const [reason, setReason] = useState(defaults?.reason ?? "");
  const [formError, setFormError] = useState<string | null>(null);
  const m = useMutation({
    mutationFn: (body: ActionProposal) => api.post<ResponseAction>("/response/actions", body),
    onSuccess: invalidate,
  });

  const close = () => {
    m.reset();
    setFormError(null);
    onClose();
  };

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!target.trim()) return setFormError(L.errTarget);
    if (!reason.trim()) return setFormError(L.errReason);
    let ttlMinutes: number | null = null;
    if (ttl.trim()) {
      const n = Number(ttl);
      if (!Number.isInteger(n) || n < 1 || n > 10080) return setFormError(L.errTtl);
      ttlMinutes = n;
    }
    setFormError(null);
    m.mutate({
      action_type: type,
      target: target.trim(),
      reason: reason.trim(),
      ttl_minutes: ttlMinutes,
      incident_id: defaults?.incident_id ?? null,
      alert_id: defaults?.alert_id ?? null,
      proposed_by: "user",
    });
  }

  const ipTarget = IP_TARGET_ACTIONS.includes(type);
  return (
    <Dialog open={open} onClose={close} title={L.title}>
      {m.data ? (
        <div className="space-y-3">
          <Notice tone="accent" icon={<ShieldCheck className="h-4 w-4 text-accent" aria-hidden />}>
            {L.created}
          </Notice>
          <ActionSummary action={m.data} />
          <div className="flex justify-end gap-2">
            <Link
              to="/response"
              className="inline-flex h-9 items-center rounded-md px-3 text-sm text-accent hover:bg-surface-2"
            >
              {L.open}
            </Link>
            <Button onClick={close}>{L.close}</Button>
          </div>
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-3">
          <div>
            <Label htmlFor="pa-type">{L.type}</Label>
            <Select
              id="pa-type"
              className="w-full"
              value={type}
              onChange={(e) => setType(e.target.value as ActionType)}
            >
              {ACTION_TYPES.map((t) => (
                <option key={t} value={t}>
                  {label(actionTypeLabel[t])}
                </option>
              ))}
            </Select>
            <p className="mt-1 text-xs text-muted">{label(actionTypeEffect[type])}</p>
          </div>
          <div>
            <Label htmlFor="pa-target">{L.target}</Label>
            <Input
              id="pa-target"
              className="font-mono"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={ipTarget ? L.targetIp : L.targetOther}
            />
          </div>
          <div>
            <Label htmlFor="pa-ttl">{L.ttl}</Label>
            <Input
              id="pa-ttl"
              type="number"
              min={1}
              max={10080}
              value={ttl}
              onChange={(e) => setTtl(e.target.value)}
              placeholder={L.ttlHint}
            />
          </div>
          <div>
            <Label htmlFor="pa-reason">{L.reason}</Label>
            <Textarea
              id="pa-reason"
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder={L.reasonPlaceholder}
              maxLength={2000}
            />
          </div>
          {formError && <p className="text-xs text-sev-critical">{formError}</p>}
          {m.error && <ErrorState error={m.error} />}
          <ApprovalNotice compact />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={close}>
              {L.cancel}
            </Button>
            <Button type="submit" disabled={m.isPending}>
              {L.submit}
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
