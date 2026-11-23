/**
 * "Mark as false positive" with the suppression choice (audit #166). Used by the alert detail and by the bulk
 * status change of the alert list, so neither marks silently: the server suppresses recurrences by default.
 */
import { BellOff, TriangleAlert } from "lucide-react";
import { useState } from "react";
import type { AlertUpdate } from "@/api/types-ops";
import { Notice } from "@/components/common/OpsKit";
import { fmt } from "@/components/common/opsLabels";
import { Button, Dialog, ErrorState, Input, Label, Select, Textarea } from "@/components/ui";
import { useLocal } from "@/lib/i18n";
import {
  DEFAULT_FP_OPTIONS,
  type FpOptions,
  type FpSuppressChoice,
  falsePositiveBody,
  MAX_SUPPRESS_HOURS,
} from "./suppression";

const strings = {
  ja: {
    title: "誤検知にする",
    titleMany: "{n} 件を誤検知にする",
    lead: "同じ検知（同じルール・一致した署名・パス・送信元）が再発したとき、新しいアラート・トリアージ・通知を出さず、このアラートの件数に加算します。",
    choice: "再発の抑制",
    cDefault: "サーバー既定（detection.fp_suppress_hours。既定 168 時間、0 なら抑制しない）",
    cNone: "抑制しない（再発は通常どおりアラートになる）",
    cHours: "指定した時間だけ抑制",
    cPermanent: "恒久的に抑制（解除するまで）",
    hours: "時間（1〜{max}）",
    hoursErr: "時間は 0 より大きく {max} 以下で指定してください",
    anySource: "送信元を問わず抑制する",
    anySourceWarn:
      "同じルート・パラメータへの同種の検知が、どの送信元からでも黙ります。攻撃者が同じ形で狙えば見逃します。送信元が多数で毎回変わる正規の入力に限って使ってください。",
    newSignal:
      "新しい署名・別のパラメータ・別の送信元・重大度の上昇は抑制されず、通常どおりアラートになります。",
    newSignalAny: "新しい署名・別のパラメータ・重大度の上昇は抑制されず、通常どおりアラートになります。",
    reason: "理由（任意・抑制の一覧と監査ログに残ります）",
    reasonPh: "例: 社内ドキュメント検索で SQL の解説文が送られる",
    manyNote: "抑制は各アラートの内容から 1 件ずつ作られます。",
    liftHint: "抑制は「抑制・許可リスト」画面で確認・解除できます。誤検知から状態を戻しても解除されます。",
    cancel: "キャンセル",
    confirm: "誤検知にする",
  },
  en: {
    title: "Mark as false positive",
    titleMany: "Mark {n} alerts as false positive",
    lead: "When the same finding (same rule, matched signatures, path and source) recurs, it is counted on this alert instead of raising, triaging and notifying again.",
    choice: "Suppress recurrences",
    cDefault: "Server default (detection.fp_suppress_hours: 168 h by default, 0 = off)",
    cNone: "Don't suppress (recurrences raise alerts as usual)",
    cHours: "Suppress for a number of hours",
    cPermanent: "Suppress permanently (until lifted)",
    hours: "Hours (1–{max})",
    hoursErr: "Hours must be greater than 0 and at most {max}",
    anySource: "Suppress for every source",
    anySourceWarn:
      "The same kind of finding on this route and parameter goes quiet from any source - an attacker using the same shape is missed too. Use it only for legitimate input that arrives from many changing sources.",
    newSignal: "New signatures, another parameter, another source or a higher severity are not suppressed.",
    newSignalAny: "New signatures, another parameter or a higher severity are not suppressed.",
    reason: "Reason (optional, shown in the suppression list and the audit log)",
    reasonPh: "e.g. the internal docs search sends text about SQL",
    manyNote: "One suppression is created from each alert's own finding.",
    liftHint:
      "Review or lift suppressions on the Suppressions & allowlists page. Changing the status back also lifts them.",
    cancel: "Cancel",
    confirm: "Mark as false positive",
  },
};

export function FalsePositiveDialog({
  open,
  count = 1,
  pending,
  error,
  onCancel,
  onConfirm,
}: {
  open: boolean;
  count?: number;
  pending?: boolean;
  error?: unknown;
  onCancel: () => void;
  onConfirm: (body: AlertUpdate) => void;
}) {
  const L = useLocal(strings);
  const [o, setO] = useState<FpOptions>(DEFAULT_FP_OPTIONS);
  const set = (patch: Partial<FpOptions>) => setO((prev) => ({ ...prev, ...patch }));
  const body = falsePositiveBody(o);
  const close = () => {
    setO(DEFAULT_FP_OPTIONS);
    onCancel();
  };
  return (
    <Dialog
      open={open}
      onClose={close}
      title={count > 1 ? fmt(L.titleMany, { n: count }) : L.title}
      footer={
        <>
          <Button variant="ghost" onClick={close}>
            {L.cancel}
          </Button>
          <Button onClick={() => body && onConfirm(body)} disabled={!body || pending}>
            {L.confirm}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-sm">{L.lead}</p>
        <div>
          <Label htmlFor="fp-choice">{L.choice}</Label>
          <Select
            id="fp-choice"
            className="w-full"
            value={o.choice}
            onChange={(e) => set({ choice: e.target.value as FpSuppressChoice })}
          >
            <option value="default">{L.cDefault}</option>
            <option value="none">{L.cNone}</option>
            <option value="hours">{L.cHours}</option>
            <option value="permanent">{L.cPermanent}</option>
          </Select>
        </div>
        {o.choice === "hours" && (
          <div>
            <Label htmlFor="fp-hours">{fmt(L.hours, { max: MAX_SUPPRESS_HOURS })}</Label>
            <Input
              id="fp-hours"
              type="number"
              min={1}
              max={MAX_SUPPRESS_HOURS}
              value={o.hours}
              onChange={(e) => set({ hours: e.target.value })}
            />
            {!body && (
              <p className="mt-1 text-xs text-sev-critical">{fmt(L.hoursErr, { max: MAX_SUPPRESS_HOURS })}</p>
            )}
          </div>
        )}
        {o.choice !== "none" && (
          <>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={o.anySource}
                onChange={(e) => set({ anySource: e.target.checked })}
              />
              {L.anySource}
            </label>
            {o.anySource && (
              <Notice tone="warn" icon={<TriangleAlert className="h-4 w-4 text-sev-medium" aria-hidden />}>
                {L.anySourceWarn}
              </Notice>
            )}
            <p className="text-xs text-muted">{o.anySource ? L.newSignalAny : L.newSignal}</p>
          </>
        )}
        <div>
          <Label htmlFor="fp-reason">{L.reason}</Label>
          <Textarea
            id="fp-reason"
            rows={2}
            maxLength={2000}
            value={o.reason}
            placeholder={L.reasonPh}
            onChange={(e) => set({ reason: e.target.value })}
          />
        </div>
        {count > 1 && <p className="text-xs text-muted">{L.manyNote}</p>}
        <p className="flex items-start gap-1.5 text-xs text-muted">
          <BellOff className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
          {L.liftHint}
        </p>
        {error ? <ErrorState error={error} /> : null}
      </div>
    </Dialog>
  );
}
