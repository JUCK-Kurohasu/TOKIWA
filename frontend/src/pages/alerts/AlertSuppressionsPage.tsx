/**
 * Suppressions & allowlists (/alert-suppressions; audit #166 / #173).
 *
 * - False-positive suppressions are written when an alert is marked false_positive: recurrences of the same finding
 *   are counted on that alert (no new alert, triage, notification or incident).
 * - Allowlists declare an authorised scan / load test ahead of time: a source CIDR for a limited time, optionally
 *   one rule / path. Creating one silences detection for a range, so it needs admin; the API enforces it.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BellOff, Plus, ShieldCheck, TriangleAlert } from "lucide-react";
import { type FormEvent, useState } from "react";
import { api } from "@/api/client";
import type { Page } from "@/api/types";
import type { AlertSuppression, AlertSuppressionKind, AlertSuppressionMode } from "@/api/types-ops";
import { PageHeader } from "@/components/common";
import { Notice, TableSkeleton } from "@/components/common/OpsKit";
import { fmt } from "@/components/common/opsLabels";
import {
  Button,
  Card,
  Dialog,
  EmptyState,
  ErrorState,
  Input,
  Label,
  Select,
  Tabs,
  Textarea,
} from "@/components/ui";
import { useHasRole } from "@/hooks/useRole";
import { useLocal } from "@/lib/i18n";
import { SuppressionTable } from "./SuppressionTable";
import { type AllowlistForm, allowlistBody, EMPTY_ALLOWLIST, MAX_SUPPRESS_HOURS } from "./suppression";

const strings = {
  ja: {
    title: "抑制・許可リスト",
    desc: "誤検知にしたアラートの再発抑制と、許可済みの診断・負荷試験の許可リストです。抑制中の検知は新しいアラート・トリアージ・通知・対処提案になりません。",
    tabAll: "すべて",
    tabFp: "誤検知",
    tabAllow: "許可リスト",
    showAll: "期限切れ・解除済みも表示",
    empty: "有効な抑制・許可リストはありません",
    emptyHint: "アラートを誤検知にすると、ここに抑制が表示されます。",
    create: "許可リストを作成",
    adminOnly: "許可リストの作成には admin 権限が必要です",
    total: "{n} 件",
  },
  en: {
    title: "Suppressions & allowlists",
    desc: "Recurrence suppressions of alerts marked false positive, and allowlists for authorised scans / load tests. Suppressed findings raise no new alert, triage, notification or response proposal.",
    tabAll: "All",
    tabFp: "False positives",
    tabAllow: "Allowlists",
    showAll: "Include expired / lifted",
    empty: "No suppressions or allowlists in force",
    emptyHint: "Marking an alert false positive creates a suppression here.",
    create: "Create allowlist",
    adminOnly: "Creating an allowlist requires the admin role",
    total: "{n} total",
  },
};

type KindTab = "all" | AlertSuppressionKind;

export function AlertSuppressionsPage() {
  const L = useLocal(strings);
  const isAdmin = useHasRole("admin");
  const [tab, setTab] = useState<KindTab>("all");
  const [all, setAll] = useState(false);
  const [creating, setCreating] = useState(false);
  const q = useQuery({
    queryKey: ["alert-suppressions", "list", tab, all],
    queryFn: () =>
      api.get<Page<AlertSuppression>>("/alert-suppressions", {
        active: all ? "false" : "true",
        kind: tab === "all" ? undefined : tab,
        limit: 500,
      }),
    refetchInterval: 60_000,
  });

  return (
    <div>
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <BellOff className="h-5 w-5 text-accent" aria-hidden />
            {L.title}
          </span>
        }
        description={L.desc}
        actions={
          isAdmin ? (
            <Button size="sm" onClick={() => setCreating(true)}>
              <Plus className="h-3.5 w-3.5" aria-hidden />
              {L.create}
            </Button>
          ) : (
            <span className="text-xs text-muted">{L.adminOnly}</span>
          )
        }
      />
      <div className="mb-3 flex flex-wrap items-end justify-between gap-2">
        <Tabs<KindTab>
          tabs={[
            { value: "all", label: L.tabAll },
            { value: "false_positive", label: L.tabFp },
            { value: "allowlist", label: L.tabAllow },
          ]}
          value={tab}
          onChange={setTab}
        />
        <div className="flex items-center gap-3 text-xs">
          {q.data && <span className="text-muted">{fmt(L.total, { n: q.data.total })}</span>}
          <label className="flex items-center gap-1.5">
            <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} />
            {L.showAll}
          </label>
        </div>
      </div>
      {q.error ? (
        <ErrorState error={q.error} />
      ) : q.isLoading ? (
        <Card>
          <TableSkeleton rows={3} />
        </Card>
      ) : q.data?.items.length ? (
        <Card>
          <SuppressionTable items={q.data.items} />
        </Card>
      ) : (
        <Card>
          <EmptyState icon={<BellOff className="h-8 w-8" aria-hidden />} title={L.empty} hint={L.emptyHint} />
        </Card>
      )}
      {isAdmin && creating && <AllowlistDialog open onClose={() => setCreating(false)} />}
    </div>
  );
}

const dialogStrings = {
  ja: {
    title: "許可リストを作成",
    lead: "許可済みの脆弱性診断・負荷試験の送信元を、期間を区切って宣言します。期間が過ぎると自動で失効します。",
    cidr: "送信元 CIDR（必須）",
    cidrHint: "例: 10.20.0.70/32、192.0.2.0/24。IPv4 は /8、IPv6 は /32 より広い範囲は作れません。",
    cidrErr: "IP アドレスまたは CIDR を入力してください",
    hours: "期間（時間・必須）",
    hoursHint:
      "上限はサーバー設定 detection.allowlist_max_hours（既定 720 時間）。恒久の許可リストは作れません。",
    hoursErr: "期間は 0 より大きく {max} 以下で指定してください",
    rule: "ルール ID（任意）",
    rulePh: "例: web.request_flood（空欄 = 全ルール）",
    path: "パス（任意）",
    pathPh: "例: /api/search（空欄 = 全パス）",
    mode: "扱い",
    modeDowngrade: "info で記録する（既定。トリアージ・通知・提案なし、アラート一覧には残る）",
    modeSuppress: "記録しない（件数だけ数える）",
    reason: "理由（任意・監査ログに残ります）",
    reasonPh: "例: 2026-11 定期脆弱性診断（委託先 A 社）",
    wideWarn:
      "ルールを絞らない許可リストは、デセプション（デコイ踏み）や AI エージェント判定のアラートも静かにします。診断元が侵害された場合も気づけなくなるため、範囲と期間は最小にしてください。",
    cancel: "キャンセル",
    submit: "作成",
  },
  en: {
    title: "Create allowlist",
    lead: "Declare the source of an authorised vulnerability scan or load test for a limited time. It expires on its own.",
    cidr: "Source CIDR (required)",
    cidrHint: "e.g. 10.20.0.70/32, 192.0.2.0/24. Ranges wider than IPv4 /8 or IPv6 /32 are refused.",
    cidrErr: "Enter an IP address or CIDR",
    hours: "Duration in hours (required)",
    hoursHint:
      "Capped by the server setting detection.allowlist_max_hours (720 h by default). Permanent allowlists are not possible.",
    hoursErr: "Duration must be greater than 0 and at most {max}",
    rule: "Rule ID (optional)",
    rulePh: "e.g. web.request_flood (empty = all rules)",
    path: "Path (optional)",
    pathPh: "e.g. /api/search (empty = all paths)",
    mode: "Handling",
    modeDowngrade: "Record as info (default: no triage, notification or proposal; still listed)",
    modeSuppress: "Don't record (count only)",
    reason: "Reason (optional, recorded in the audit log)",
    reasonPh: "e.g. 2026-11 scheduled pentest (vendor A)",
    wideWarn:
      "An allowlist without a rule also silences deception (decoy trips) and AI-agent alerts. If the scanner host is compromised you will not notice either, so keep the range and duration minimal.",
    cancel: "Cancel",
    submit: "Create",
  },
};

function AllowlistDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const L = useLocal(dialogStrings);
  const qc = useQueryClient();
  const [f, setF] = useState<AllowlistForm>(EMPTY_ALLOWLIST);
  const [touched, setTouched] = useState(false);
  const set = (patch: Partial<AllowlistForm>) => setF((prev) => ({ ...prev, ...patch }));
  const { body, error } = allowlistBody(f);
  const m = useMutation({
    mutationFn: () => api.post<AlertSuppression>("/alert-suppressions", body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["alert-suppressions"] });
      onClose();
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (body) m.mutate();
  };
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={
        <span className="flex items-center gap-1.5">
          <ShieldCheck className="h-4 w-4 text-accent" aria-hidden />
          {L.title}
        </span>
      }
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {L.cancel}
          </Button>
          <Button type="submit" form="allowlist-form" disabled={m.isPending || (touched && !body)}>
            {L.submit}
          </Button>
        </>
      }
    >
      <form id="allowlist-form" className="space-y-3" onSubmit={submit}>
        <p className="text-sm">{L.lead}</p>
        <div>
          <Label htmlFor="al-cidr">{L.cidr}</Label>
          <Input
            id="al-cidr"
            className="font-mono"
            required
            value={f.cidr}
            placeholder="10.20.0.70/32"
            onChange={(e) => set({ cidr: e.target.value })}
          />
          <p className="mt-1 text-xs text-muted">{L.cidrHint}</p>
          {touched && error === "cidr" && <p className="mt-1 text-xs text-sev-critical">{L.cidrErr}</p>}
        </div>
        <div>
          <Label htmlFor="al-hours">{L.hours}</Label>
          <Input
            id="al-hours"
            type="number"
            required
            min={1}
            max={MAX_SUPPRESS_HOURS}
            value={f.hours}
            onChange={(e) => set({ hours: e.target.value })}
          />
          <p className="mt-1 text-xs text-muted">{L.hoursHint}</p>
          {touched && error === "hours" && (
            <p className="mt-1 text-xs text-sev-critical">{fmt(L.hoursErr, { max: MAX_SUPPRESS_HOURS })}</p>
          )}
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="al-rule">{L.rule}</Label>
            <Input
              id="al-rule"
              className="font-mono"
              maxLength={128}
              value={f.ruleId}
              placeholder={L.rulePh}
              onChange={(e) => set({ ruleId: e.target.value })}
            />
          </div>
          <div>
            <Label htmlFor="al-path">{L.path}</Label>
            <Input
              id="al-path"
              className="font-mono"
              maxLength={512}
              value={f.path}
              placeholder={L.pathPh}
              onChange={(e) => set({ path: e.target.value })}
            />
          </div>
        </div>
        <div>
          <Label htmlFor="al-mode">{L.mode}</Label>
          <Select
            id="al-mode"
            className="w-full"
            value={f.mode}
            onChange={(e) => set({ mode: e.target.value as AlertSuppressionMode })}
          >
            <option value="downgrade">{L.modeDowngrade}</option>
            <option value="suppress">{L.modeSuppress}</option>
          </Select>
        </div>
        {!f.ruleId.trim() && (
          <Notice tone="warn" icon={<TriangleAlert className="h-4 w-4 text-sev-medium" aria-hidden />}>
            {L.wideWarn}
          </Notice>
        )}
        <div>
          <Label htmlFor="al-reason">{L.reason}</Label>
          <Textarea
            id="al-reason"
            rows={2}
            maxLength={2000}
            value={f.reason}
            placeholder={L.reasonPh}
            onChange={(e) => set({ reason: e.target.value })}
          />
        </div>
        {m.error ? <ErrorState error={m.error} /> : null}
      </form>
    </Dialog>
  );
}
