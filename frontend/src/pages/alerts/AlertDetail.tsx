/**
 * Alert detail (/alerts/:id): description, entities, MITRE, evidence events (formatted HTTP), the LLM triage
 * panel with re-triage (fast / deep) and status changes.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, FileSearch, Loader2, ShieldPlus } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { ApiError, api } from "@/api/client";
import type { Alert, AlertDetail, AlertStatus } from "@/api/types";
import { ALERT_STATUSES, type AlertUpdate, type RetriageTier } from "@/api/types-ops";
import { AiScore, JsonView, Mono, SeverityBadge } from "@/components/common";
import { EvidenceList } from "@/components/common/EventDetail";
import {
  AlertStatusBadge,
  BackLink,
  CategoryBadge,
  MetaItem,
  MitreChips,
  Notice,
  SectionTitle,
} from "@/components/common/OpsKit";
import { alertStatusLabel, fmt, useCanOperate } from "@/components/common/opsLabels";
import { ProposeActionDialog } from "@/components/common/ResponseActions";
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
  Select,
  Skeleton,
} from "@/components/ui";
import { formatDateTime, pct, timeAgo } from "@/lib/format";
import { useLabel, useLocal } from "@/lib/i18n";

const strings = {
  ja: {
    back: "アラート一覧",
    notFound: "アラートが見つかりません",
    notFoundHint: "削除されたか、ID が間違っている可能性があります。",
    source: "送信元",
    count: "件数",
    confidence: "検知信頼度",
    aiScore: "AI スコア",
    firstSeen: "初回検知",
    lastSeen: "最終検知",
    incident: "インシデント",
    detector: "検知器",
    description: "説明",
    noDescription: "説明はありません",
    entities: "エンティティ",
    mitre: "MITRE ATT&CK",
    evidence: "証拠イベント",
    details: "検知詳細（検知器の出力）",
    statusLabel: "状態を変更",
    propose: "対処を提案",
    aiBanner: "AI エージェントによる活動の可能性が高いアラートです",
    aiBannerBody:
      "AI スコア {score}。振る舞い特徴量（思考待ちのリズム、エラーに即応したペイロード変異など）や AI カナリアへの追従に基づく判定です。",
    viewerHint: "状態の変更には analyst 以上の権限が必要です",
  },
  en: {
    back: "Alerts",
    notFound: "Alert not found",
    notFoundHint: "It may have been deleted, or the id is wrong.",
    source: "Source",
    count: "Count",
    confidence: "Detection confidence",
    aiScore: "AI score",
    firstSeen: "First seen",
    lastSeen: "Last seen",
    incident: "Incident",
    detector: "Detector",
    description: "Description",
    noDescription: "No description",
    entities: "Entities",
    mitre: "MITRE ATT&CK",
    evidence: "Evidence events",
    details: "Detection details (detector output)",
    statusLabel: "Change status",
    propose: "Propose action",
    aiBanner: "This alert is likely driven by an autonomous AI agent",
    aiBannerBody:
      "AI score {score}. Based on behavioural features (think-time rhythm, payload mutation reacting to errors, …) or AI-canary compliance.",
    viewerHint: "Changing status requires the analyst role",
  },
};

export function AlertDetailPage() {
  const { id = "" } = useParams();
  const L = useLocal(strings);
  const label = useLabel();
  const canOperate = useCanOperate();
  const qc = useQueryClient();
  const key = ["alerts", "detail", id];
  const [proposeOpen, setProposeOpen] = useState(false);

  const q = useQuery({
    queryKey: key,
    queryFn: () => api.get<AlertDetail>(`/alerts/${encodeURIComponent(id)}`),
    enabled: !!id,
    // While the LLM is working, poll until the verdict lands (SSE also triggers refetches).
    refetchInterval: (query) => (query.state.data?.status === "triaging" ? 5000 : false),
  });
  useOpsLive(["alert."], [key]);

  const merge = (a: Alert) => {
    qc.setQueryData<AlertDetail>(key, (old) => (old ? { ...old, ...a } : old));
    void qc.invalidateQueries({ queryKey: ["alerts", "list"] });
  };
  const patch = useMutation({
    mutationFn: (body: AlertUpdate) => api.patch<Alert>(`/alerts/${encodeURIComponent(id)}`, body),
    onSuccess: merge,
  });
  const retriage = useMutation({
    mutationFn: (tier?: RetriageTier) =>
      api.post<Alert>(`/alerts/${encodeURIComponent(id)}/triage`, undefined, tier ? { tier } : undefined),
    onSuccess: merge,
  });

  const a = q.data;
  const evidenceIds = useMemo(() => new Set((a?.evidence ?? []).map((e) => e.id)), [a?.evidence]);

  if (q.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-6 w-40" />
        <Skeleton className="h-10 w-2/3" />
        <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
          {Array.from({ length: 8 }, (_, i) => (
            <Skeleton key={i} className="h-14" />
          ))}
        </div>
        <Skeleton className="h-64" />
      </div>
    );
  }
  if (q.error || !a) {
    const notFound = q.error instanceof ApiError && q.error.status === 404;
    return (
      <div>
        <BackLink to="/alerts">{L.back}</BackLink>
        {notFound || !q.error ? (
          <EmptyState title={L.notFound} hint={L.notFoundHint} />
        ) : (
          <ErrorState error={q.error} />
        )}
      </div>
    );
  }

  const aiLikely = (a.ai_score ?? 0) >= 0.7 || a.category === "ai_agent";
  const entities = Object.entries(a.entities ?? {});

  return (
    <div className="space-y-4">
      <div>
        <BackLink to="/alerts">{L.back}</BackLink>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={a.severity} />
              <AlertStatusBadge status={a.status} />
              <CategoryBadge category={a.category} />
            </div>
            <h1 className="break-words text-xl font-semibold tracking-tight">{a.title}</h1>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
              <Mono>{a.rule_id}</Mono>
              {a.tags?.slice(0, 6).map((tag) => (
                <Badge key={tag}>{tag}</Badge>
              ))}
            </div>
          </div>
          <div className="flex flex-wrap items-end gap-2">
            <div>
              <label htmlFor="alert-status" className="mb-1 block text-[11px] text-muted">
                {L.statusLabel}
              </label>
              <div className="flex items-center gap-1.5">
                <Select
                  id="alert-status"
                  value={a.status}
                  disabled={!canOperate || patch.isPending}
                  title={canOperate ? undefined : L.viewerHint}
                  onChange={(e) => patch.mutate({ status: e.target.value as AlertStatus })}
                >
                  {ALERT_STATUSES.map((s) => (
                    <option key={s} value={s} disabled={s === "triaging"}>
                      {label(alertStatusLabel[s])}
                    </option>
                  ))}
                </Select>
                {patch.isPending && <Loader2 className="h-4 w-4 animate-spin text-muted" aria-hidden />}
              </div>
            </div>
            {canOperate && (
              <Button variant="outline" onClick={() => setProposeOpen(true)}>
                <ShieldPlus className="h-4 w-4" aria-hidden />
                {L.propose}
              </Button>
            )}
          </div>
        </div>
        {patch.error && <ErrorState error={patch.error} />}
      </div>

      {aiLikely && (
        <Notice tone="ai" icon={<Bot className="h-4 w-4 text-ai" aria-hidden />} title={L.aiBanner}>
          {fmt(L.aiBannerBody, { score: pct(a.ai_score) })}
        </Notice>
      )}

      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        <MetaItem label={L.source}>
          {a.source_ip ? (
            <Link
              to={`/alerts?source_ip=${encodeURIComponent(a.source_ip)}`}
              className="font-mono hover:text-accent"
            >
              {a.source_ip}
            </Link>
          ) : (
            "-"
          )}
        </MetaItem>
        <MetaItem label={L.count}>
          <span className="tabular-nums">{a.count}</span>
        </MetaItem>
        <MetaItem label={L.confidence}>
          <span className="tabular-nums">{pct(a.confidence)}</span>
        </MetaItem>
        <MetaItem label={L.aiScore}>
          <AiScore score={a.ai_score} className={aiLikely ? "font-semibold text-ai" : undefined} />
        </MetaItem>
        <MetaItem label={L.firstSeen}>
          <span title={formatDateTime(a.first_seen)}>{formatDateTime(a.first_seen)}</span>
        </MetaItem>
        <MetaItem label={L.lastSeen}>
          <span title={formatDateTime(a.last_seen)}>{timeAgo(a.last_seen)}</span>
        </MetaItem>
        <MetaItem label={L.incident}>
          {a.incident_id ? (
            <Link to={`/incidents/${a.incident_id}`} className="text-accent hover:underline">
              INC-{a.incident_id.slice(0, 8)}
            </Link>
          ) : (
            "-"
          )}
        </MetaItem>
        <MetaItem label={L.detector}>
          <Mono>{a.detector}</Mono>
        </MetaItem>
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        <div className="min-w-0 space-y-4 lg:col-span-3">
          <Card>
            <CardBody className="space-y-4">
              <div>
                <SectionTitle>{L.description}</SectionTitle>
                <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">
                  {a.description || <span className="text-muted">{L.noDescription}</span>}
                </p>
              </div>
              {entities.length > 0 && (
                <div>
                  <SectionTitle>{L.entities}</SectionTitle>
                  <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-xs">
                    {entities.map(([k, v]) => (
                      <div key={k} className="contents">
                        <dt className="text-muted">{k}</dt>
                        <dd className="break-all font-mono">{v}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
              )}
              <div>
                <SectionTitle>{L.mitre}</SectionTitle>
                <MitreChips ids={a.mitre ?? []} />
              </div>
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              title={
                <span className="flex items-center gap-1.5">
                  <FileSearch className="h-4 w-4 text-accent" aria-hidden />
                  {L.evidence}
                  <span className="font-normal text-muted">({a.evidence?.length ?? 0})</span>
                </span>
              }
            />
            <CardBody>
              <EvidenceList
                events={a.evidence ?? []}
                expectedIds={a.evidence_event_ids ?? []}
                citedIds={a.triage?.result.evidence_ids ?? []}
              />
            </CardBody>
          </Card>

          {a.details && Object.keys(a.details).length > 0 && (
            <Card>
              <details className="group">
                <summary className="cursor-pointer select-none px-4 py-3 text-sm font-semibold hover:bg-surface-2/50">
                  {L.details}
                </summary>
                <div className="border-t border-line p-4">
                  <JsonView value={a.details} />
                </div>
              </details>
            </Card>
          )}
        </div>

        <div className="min-w-0 lg:col-span-2">
          <TriagePanel
            triage={a.triage}
            inProgress={a.status === "triaging"}
            subject={{ alertId: a.id, incidentId: a.incident_id ?? undefined }}
            onRetriage={(tier) => retriage.mutate(tier)}
            retriageTiers={["fast", "deep"]}
            retriaging={retriage.isPending}
            retriageError={retriage.error}
            availableEvidenceIds={evidenceIds}
          />
        </div>
      </div>

      {proposeOpen && (
        <ProposeActionDialog
          open
          onClose={() => setProposeOpen(false)}
          defaults={{
            target: a.source_ip ?? "",
            alert_id: a.id,
            incident_id: a.incident_id,
            reason: a.title,
          }}
        />
      )}
    </div>
  );
}
