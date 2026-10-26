/**
 * Incident detail (/incidents/:id): summary, ATT&CK kill chain, actor attribution (AI agents emphasised),
 * linked alerts, response actions (approve / reject), LLM triage panel, assignee / status changes.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Bot,
  ListTree,
  Loader2,
  MessageSquare,
  ShieldCheck,
  ShieldPlus,
  Sparkles,
  UserRound,
} from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import { ApiError, api } from "@/api/client";
import type { Incident, IncidentDetail, IncidentStatus, ResponseAction } from "@/api/types";
import { INCIDENT_STATUSES, type IncidentUpdate } from "@/api/types-ops";
import { ActorBadge, AiScore, Mono, SeverityBadge } from "@/components/common";
import { KillChain } from "@/components/common/KillChain";
import {
  AlertStatusBadge,
  BackLink,
  CategoryBadge,
  IncidentStatusBadge,
  MetaItem,
  MitreChips,
  SectionTitle,
} from "@/components/common/OpsKit";
import { incidentStatusLabel, useCanOperate } from "@/components/common/opsLabels";
import { ActionCard, ApprovalNotice, ProposeActionDialog } from "@/components/common/ResponseActions";
import { TriagePanel } from "@/components/common/TriagePanel";
import { useOpsLive } from "@/components/common/useOpsLive";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  Input,
  Select,
  Skeleton,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/ui";
import { formatDateTime, pct, timeAgo } from "@/lib/format";
import { useLabel, useLocal, useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { useAuth } from "@/stores/auth";

const strings = {
  ja: {
    back: "インシデント一覧",
    notFound: "インシデントが見つかりません",
    notFoundHint: "削除されたか、ID が間違っている可能性があります。",
    statusLabel: "状態",
    assignee: "担当者",
    assigneePh: "未割り当て",
    save: "保存",
    assignMe: "自分に割り当て",
    copilot: "コパイロットに聞く",
    firstSeen: "初回検知",
    lastSeen: "最終検知",
    alertCount: "アラート数",
    sources: "送信元",
    summary: "要約",
    noSummary: "要約はまだありません",
    mitre: "MITRE ATT&CK",
    tags: "タグ",
    killChain: "キルチェーン（ATT&CK 戦術）",
    alerts: "関連アラート",
    openInAlerts: "アラート一覧で開く",
    noAlerts: "関連アラートはありません",
    actions: "対処",
    propose: "対処を提案",
    noActions:
      "このインシデントに紐づく対処はまだありません。トリアージの推奨対処から提案するか、手動で提案できます。",
    viewerHint: "操作には analyst 以上の権限が必要です",
    colTitle: "タイトル",
    colAi: "AI",
    colCount: "件数",
    colLast: "最終",
  },
  en: {
    back: "Incidents",
    notFound: "Incident not found",
    notFoundHint: "It may have been deleted, or the id is wrong.",
    statusLabel: "Status",
    assignee: "Assignee",
    assigneePh: "Unassigned",
    save: "Save",
    assignMe: "Assign to me",
    copilot: "Ask Copilot",
    firstSeen: "First seen",
    lastSeen: "Last seen",
    alertCount: "Alerts",
    sources: "Sources",
    summary: "Summary",
    noSummary: "No summary yet",
    mitre: "MITRE ATT&CK",
    tags: "Tags",
    killChain: "Kill chain (ATT&CK tactics)",
    alerts: "Linked alerts",
    openInAlerts: "Open in Alerts",
    noAlerts: "No linked alerts",
    actions: "Response actions",
    propose: "Propose action",
    noActions:
      "No actions linked to this incident yet. Propose one from the triage recommendations or manually.",
    viewerHint: "Requires analyst role",
    colTitle: "Title",
    colAi: "AI",
    colCount: "Count",
    colLast: "Last",
  },
};

const attributionStrings = {
  ja: {
    heading: "アクター判定",
    aiTitle: "AI エージェントによる攻撃",
    aiBody:
      "自律的に動作する LLM エージェントの振る舞いが観測されています。人間の攻撃者より高速・網羅的に段階を進める可能性があるため、早期の封じ込めを検討してください。",
    suspectTitle: "AI エージェントの疑い",
    suspectBody:
      "AI エージェント特有の兆候が一部観測されています。証拠とトリアージの根拠を確認してください。",
    otherBody: "AI エージェントの兆候は弱いか、観測されていません。",
    score: "AI スコア",
    indicators: "LLM が挙げた AI 関与の根拠",
    llmSays: "LLM 判定",
    signals:
      "判定に使うシグナル: 思考待ちのリズム、エラー応答に即応したペイロード変異、JS からの API 発見、AI カナリア（隠し指示）への追従",
  },
  en: {
    heading: "Actor attribution",
    aiTitle: "Attack driven by an AI agent",
    aiBody:
      "Behaviour of an autonomous LLM agent has been observed. Agents may progress through stages faster and more exhaustively than humans — consider early containment.",
    suspectTitle: "Suspected AI agent",
    suspectBody: "Some AI-agent indicators were observed. Review the evidence and the triage rationale.",
    otherBody: "AI-agent indicators are weak or absent.",
    score: "AI score",
    indicators: "AI-agent indicators cited by the LLM",
    llmSays: "LLM verdict",
    signals:
      "Signals: think-time rhythm, payload mutation reacting to errors, API discovery from JS, compliance with AI canaries (hidden instructions)",
  },
};

function AttributionCard({ incident }: { incident: Incident }) {
  const L = useLocal(attributionStrings);
  const isAi = incident.actor_type === "ai_agent";
  const score = incident.ai_score ?? incident.triage?.result.ai_agent_likelihood ?? null;
  const suspected = !isAi && (score ?? 0) >= 0.5;
  const indicators = incident.triage?.result.ai_agent_indicators ?? [];
  const llmActor = incident.triage?.result.actor_type;

  if (!isAi && !suspected) {
    return (
      <Card>
        <CardBody className="flex flex-wrap items-center gap-4">
          <div className="text-xs text-muted">{L.heading}</div>
          <ActorBadge actor={incident.actor_type} />
          <span className="flex items-center gap-2 text-xs text-muted">
            {L.score}
            <AiScore score={score} />
          </span>
          <span className="text-xs text-muted">{L.otherBody}</span>
          {llmActor && llmActor !== incident.actor_type && (
            <span className="flex items-center gap-1 text-xs text-muted">
              {L.llmSays}: <ActorBadge actor={llmActor} />
            </span>
          )}
        </CardBody>
      </Card>
    );
  }

  return (
    <section
      aria-label={L.heading}
      className={cn(
        "rounded-lg border p-4",
        isAi ? "border-ai/60 bg-gradient-to-br from-ai/20 via-ai/5 to-transparent" : "border-ai/30 bg-ai/5",
      )}
    >
      <div className="flex flex-wrap items-start gap-4">
        <div
          className={cn(
            "flex h-12 w-12 shrink-0 items-center justify-center rounded-lg",
            isAi ? "bg-ai/25 text-ai" : "bg-ai/10 text-ai",
          )}
        >
          <Bot className="h-7 w-7" aria-hidden />
        </div>
        <div className="min-w-0 flex-1 space-y-1">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-ai">{L.heading}</div>
          <div className="text-lg font-semibold text-ai">{isAi ? L.aiTitle : L.suspectTitle}</div>
          <p className="text-xs leading-relaxed text-muted">{isAi ? L.aiBody : L.suspectBody}</p>
          {llmActor && llmActor !== incident.actor_type && (
            <p className="flex items-center gap-1 text-xs text-muted">
              {L.llmSays}: <ActorBadge actor={llmActor} />
            </p>
          )}
        </div>
        <div className="text-right">
          <div className="text-3xl font-bold tabular-nums text-ai">{pct(score)}</div>
          <div className="text-[11px] text-muted">{L.score}</div>
        </div>
      </div>
      {indicators.length > 0 && (
        <div className="mt-3 border-t border-ai/20 pt-3">
          <SectionTitle icon={<Sparkles className="h-3.5 w-3.5 text-ai" aria-hidden />}>
            {L.indicators}
          </SectionTitle>
          <ul className="grid gap-1 text-xs sm:grid-cols-2">
            {indicators.map((ind, i) => (
              <li key={i} className="flex gap-1.5">
                <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-ai" aria-hidden />
                <span className="break-words">{ind}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <p className="mt-3 text-[11px] text-muted">{L.signals}</p>
    </section>
  );
}

const actionOrder: Record<string, number> = { proposed: 0, approved: 1, active: 2 };
function sortActions(actions: ResponseAction[]): ResponseAction[] {
  return [...actions].sort(
    (a, b) =>
      (actionOrder[a.status] ?? 9) - (actionOrder[b.status] ?? 9) || b.created_at.localeCompare(a.created_at),
  );
}

export function IncidentDetailPage() {
  const { id = "" } = useParams();
  const L = useLocal(strings);
  const t = useT();
  const label = useLabel();
  const canOperate = useCanOperate();
  const { user } = useAuth();
  const qc = useQueryClient();
  const key = ["incidents", "detail", id];
  const [proposeOpen, setProposeOpen] = useState(false);
  const [assignee, setAssignee] = useState("");

  const q = useQuery({
    queryKey: key,
    queryFn: () => api.get<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`),
    enabled: !!id,
  });
  useOpsLive(["incident.", "action.", "alert."], [key]);

  const inc = q.data;
  useEffect(() => {
    setAssignee(inc?.assignee ?? "");
  }, [inc?.assignee]);

  const merge = (i: Incident) => {
    qc.setQueryData<IncidentDetail>(key, (old) => (old ? { ...old, ...i } : old));
    void qc.invalidateQueries({ queryKey: ["incidents", "list"] });
  };
  const patch = useMutation({
    mutationFn: (body: IncidentUpdate) => api.patch<Incident>(`/incidents/${encodeURIComponent(id)}`, body),
    onSuccess: merge,
  });
  const retriage = useMutation({
    mutationFn: () => api.post<Incident>(`/incidents/${encodeURIComponent(id)}/triage`),
    onSuccess: merge,
  });

  if (q.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-6 w-40" />
        <Skeleton className="h-10 w-2/3" />
        <Skeleton className="h-24" />
        <Skeleton className="h-20" />
        <Skeleton className="h-64" />
      </div>
    );
  }
  if (q.error || !inc) {
    const notFound = q.error instanceof ApiError && q.error.status === 404;
    return (
      <div>
        <BackLink to="/incidents">{L.back}</BackLink>
        {notFound || !q.error ? (
          <EmptyState title={L.notFound} hint={L.notFoundHint} />
        ) : (
          <ErrorState error={q.error} />
        )}
      </div>
    );
  }

  const saveAssignee = (e: FormEvent) => {
    e.preventDefault();
    const v = assignee.trim();
    if (v === (inc.assignee ?? "")) return;
    patch.mutate({ assignee: v || null });
  };
  const actions = sortActions(inc.actions ?? []);
  const pendingCount = actions.filter((a) => a.status === "proposed").length;

  return (
    <div className="space-y-4">
      <div>
        <BackLink to="/incidents">{L.back}</BackLink>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={inc.severity} />
              <IncidentStatusBadge status={inc.status} />
              <CategoryBadge category={inc.category} />
              <Mono className="text-muted">INC-{inc.id.slice(0, 8)}</Mono>
            </div>
            <h1 className="break-words text-xl font-semibold tracking-tight">{inc.title}</h1>
          </div>
          <div className="flex flex-wrap items-end gap-2">
            <div>
              <label htmlFor="inc-status" className="mb-1 block text-[11px] text-muted">
                {L.statusLabel}
              </label>
              <Select
                id="inc-status"
                value={inc.status}
                disabled={!canOperate || patch.isPending}
                title={canOperate ? undefined : L.viewerHint}
                onChange={(e) => patch.mutate({ status: e.target.value as IncidentStatus })}
              >
                {INCIDENT_STATUSES.map((s) => (
                  <option key={s} value={s}>
                    {label(incidentStatusLabel[s])}
                  </option>
                ))}
              </Select>
            </div>
            <form onSubmit={saveAssignee}>
              <label htmlFor="inc-assignee" className="mb-1 block text-[11px] text-muted">
                {L.assignee}
              </label>
              <div className="flex gap-1">
                <Input
                  id="inc-assignee"
                  className="w-36"
                  value={assignee}
                  placeholder={L.assigneePh}
                  disabled={!canOperate}
                  onChange={(e) => setAssignee(e.target.value)}
                />
                {canOperate && (
                  <Button type="submit" variant="outline" disabled={patch.isPending}>
                    {L.save}
                  </Button>
                )}
              </div>
            </form>
            {canOperate && user && inc.assignee !== user.username && (
              <Button
                variant="ghost"
                onClick={() => patch.mutate({ assignee: user.username })}
                disabled={patch.isPending}
              >
                <UserRound className="h-4 w-4" aria-hidden />
                {L.assignMe}
              </Button>
            )}
            {patch.isPending && <Loader2 className="mb-2.5 h-4 w-4 animate-spin text-muted" aria-hidden />}
            <Link
              to={`/copilot?incident=${encodeURIComponent(inc.id)}`}
              className="inline-flex h-9 items-center gap-1.5 rounded-md border border-ai/40 px-3 text-sm text-ai hover:bg-ai/10"
            >
              <MessageSquare className="h-4 w-4" aria-hidden />
              {L.copilot}
            </Link>
          </div>
        </div>
        {patch.error && <ErrorState error={patch.error} />}
      </div>

      <AttributionCard incident={inc} />

      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        <MetaItem label={L.firstSeen}>{formatDateTime(inc.first_seen)}</MetaItem>
        <MetaItem label={L.lastSeen}>
          <span title={formatDateTime(inc.last_seen)}>{timeAgo(inc.last_seen)}</span>
        </MetaItem>
        <MetaItem label={L.alertCount}>
          <span className="tabular-nums">{inc.alert_count}</span>
        </MetaItem>
        <MetaItem label={L.sources}>
          <span className="flex flex-wrap gap-x-2 font-mono text-xs">
            {inc.source_ips.length
              ? inc.source_ips.map((ip) => (
                  <Link
                    key={ip}
                    to={`/alerts?source_ip=${encodeURIComponent(ip)}`}
                    className="hover:text-accent"
                  >
                    {ip}
                  </Link>
                ))
              : "-"}
          </span>
        </MetaItem>
      </div>

      <Card>
        <CardBody className="space-y-4">
          <div>
            <SectionTitle>{L.summary}</SectionTitle>
            <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">
              {inc.summary || <span className="text-muted">{L.noSummary}</span>}
            </p>
          </div>
          <div className="flex flex-wrap gap-6">
            <div>
              <SectionTitle>{L.mitre}</SectionTitle>
              <MitreChips ids={inc.mitre ?? []} />
            </div>
            {inc.tags?.length > 0 && (
              <div>
                <SectionTitle>{L.tags}</SectionTitle>
                <div className="flex flex-wrap gap-1">
                  {inc.tags.map((tag) => (
                    <Badge key={tag}>{tag}</Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader title={L.killChain} />
        <CardBody>
          <KillChain stages={inc.kill_chain ?? []} current={inc.triage?.result.attack_stage} />
        </CardBody>
      </Card>

      <div className="grid gap-4 lg:grid-cols-5">
        <div className="min-w-0 space-y-4 lg:col-span-3">
          <Card>
            <CardHeader
              title={
                <span className="flex items-center gap-1.5">
                  <ShieldCheck className="h-4 w-4 text-accent" aria-hidden />
                  {L.actions}
                  {pendingCount > 0 && <Badge tone="warn">{pendingCount}</Badge>}
                </span>
              }
              actions={
                canOperate ? (
                  <Button size="sm" variant="outline" onClick={() => setProposeOpen(true)}>
                    <ShieldPlus className="h-3.5 w-3.5" aria-hidden />
                    {L.propose}
                  </Button>
                ) : undefined
              }
            />
            <CardBody className="space-y-3">
              <ApprovalNotice compact />
              {actions.length ? (
                actions.map((a) => <ActionCard key={a.id} action={a} showLinks={false} />)
              ) : (
                <p className="text-sm text-muted">{L.noActions}</p>
              )}
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              title={
                <span className="flex items-center gap-1.5">
                  <ListTree className="h-4 w-4 text-accent" aria-hidden />
                  {L.alerts}
                  <span className="font-normal text-muted">({inc.alerts?.length ?? 0})</span>
                </span>
              }
              actions={
                <Link
                  to={`/alerts?incident_id=${encodeURIComponent(inc.id)}`}
                  className="text-xs text-accent hover:underline"
                >
                  {L.openInAlerts}
                </Link>
              }
            />
            {inc.alerts?.length ? (
              <Table>
                <THead>
                  <tr>
                    <TH>{t("common.severity")}</TH>
                    <TH>{L.colTitle}</TH>
                    <TH>{L.colAi}</TH>
                    <TH className="text-right">{L.colCount}</TH>
                    <TH>{t("common.status")}</TH>
                    <TH>{L.colLast}</TH>
                  </tr>
                </THead>
                <TBody>
                  {inc.alerts.map((a) => (
                    <TR key={a.id}>
                      <TD>
                        <SeverityBadge severity={a.severity} />
                      </TD>
                      <TD className="max-w-[320px]">
                        <Link to={`/alerts/${a.id}`} className="line-clamp-2 hover:text-accent">
                          {a.title}
                        </Link>
                        <CategoryBadge category={a.category} />
                      </TD>
                      <TD>
                        <AiScore
                          score={a.ai_score}
                          className={cn((a.ai_score ?? 0) >= 0.7 && "font-semibold text-ai")}
                        />
                      </TD>
                      <TD className="text-right tabular-nums">{a.count}</TD>
                      <TD>
                        <AlertStatusBadge status={a.status} />
                      </TD>
                      <TD
                        className="whitespace-nowrap text-xs text-muted"
                        title={formatDateTime(a.last_seen)}
                      >
                        {timeAgo(a.last_seen)}
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            ) : (
              <CardBody>
                <p className="text-sm text-muted">{L.noAlerts}</p>
              </CardBody>
            )}
          </Card>
        </div>

        <div className="min-w-0 lg:col-span-2">
          <TriagePanel
            triage={inc.triage}
            subject={{ incidentId: inc.id }}
            onRetriage={() => retriage.mutate()}
            retriageTiers={[]}
            retriaging={retriage.isPending}
            retriageError={retriage.error}
          />
        </div>
      </div>

      {proposeOpen && (
        <ProposeActionDialog
          open
          onClose={() => setProposeOpen(false)}
          defaults={{ target: inc.source_ips[0] ?? "", incident_id: inc.id, reason: inc.title }}
        />
      )}
    </div>
  );
}
