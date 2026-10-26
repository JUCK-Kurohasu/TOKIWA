/**
 * LLM triage panel (FR-07) for alerts and incidents.
 *
 * Shows the fixed-schema TriageResult (verdict, confidence, AI-agent likelihood + indicators, attack stage,
 * summary, rationale with evidence links, next steps, recommended actions) plus provenance (tier / model /
 * prompt version / llm_call_id). Recommended actions can be turned into *proposals* only — they still go
 * through human approval on the Response page.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  BrainCircuit,
  Check,
  ListChecks,
  Loader2,
  Plus,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
} from "lucide-react";
import { Link } from "react-router";
import { api } from "@/api/client";
import type { RecommendedAction, ResponseAction, TriageRecord } from "@/api/types";
import type { ActionProposal, RetriageTier } from "@/api/types-ops";
import { Badge, Button, Card, CardBody, CardHeader, ErrorState } from "@/components/ui";
import { useLabel, useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { ActorBadge, SeverityBadge } from "./index";
import { Meter, MitreChips, SectionTitle } from "./OpsKit";
import {
  actionTypeEffect,
  attackStageLabel,
  fmt,
  formatTtl,
  labelOf,
  tierLabel,
  useCanOperate,
} from "./opsLabels";
import { ActionTypeTag } from "./ResponseActions";

const strings = {
  ja: {
    title: "LLM トリアージ",
    none: "まだトリアージされていません",
    noneHint: "重大度が閾値未満のものは自動では LLM に送られません。必要なら手動で実行してください。",
    running: "LLM がトリアージ中です…",
    retriage: "再トリアージ",
    runTriage: "トリアージを実行",
    fast: "軽量 (fast)",
    deep: "高精度 (deep)",
    fastHint: "軽量モデルで素早く再判定",
    deepHint: "高精度モデルで詳細に再判定（費用が高め）",
    verdict: "判定",
    confidence: "信頼度（真陽性）",
    aiLikelihood: "AI エージェント関与度",
    aiIndicators: "AI 関与の根拠",
    stage: "攻撃段階",
    category: "分類",
    summary: "要約",
    rationale: "判定根拠",
    evidence: "引用された証拠",
    rejected: "実在しない証拠 ID {n} 件を除外しました（ハルシネーション対策）",
    mitre: "MITRE ATT&CK",
    nextSteps: "次の手順",
    recommended: "推奨対処",
    propose: "提案として作成",
    proposed: "提案を作成（承認待ち）",
    openResponse: "対処画面で承認",
    proposalNote: "提案は「承認待ち」として作成されます。承認なしでは実行されません。",
    viewerHint: "提案の作成には analyst 以上の権限が必要です",
    provenance: "出所",
    tier: "ティア",
    model: "モデル",
    prompt: "プロンプト版",
    call: "LLM 呼び出し",
    escalated: "deep へ昇格",
    rulesFallback: "LLM 不在・予算超過・拒否のため、ルールベースで判定しました。",
    disclaimer: "LLM の判定は参考情報です。最終判断は証拠と照合して行ってください。",
    noActions: "推奨対処はありません",
    noSteps: "なし",
  },
  en: {
    title: "LLM triage",
    none: "Not triaged yet",
    noneHint:
      "Alerts below the severity threshold are not sent to the LLM automatically. Run it manually if needed.",
    running: "The LLM is triaging…",
    retriage: "Re-triage",
    runTriage: "Run triage",
    fast: "Fast",
    deep: "Deep",
    fastHint: "Quick re-assessment with the fast model",
    deepHint: "Thorough re-assessment with the deep model (higher cost)",
    verdict: "Verdict",
    confidence: "Confidence (true positive)",
    aiLikelihood: "AI-agent likelihood",
    aiIndicators: "AI-agent indicators",
    stage: "Attack stage",
    category: "Category",
    summary: "Summary",
    rationale: "Rationale",
    evidence: "Cited evidence",
    rejected: "Dropped {n} non-existent evidence id(s) (hallucination guard)",
    mitre: "MITRE ATT&CK",
    nextSteps: "Next steps",
    recommended: "Recommended actions",
    propose: "Create proposal",
    proposed: "Proposal created (awaiting approval)",
    openResponse: "Approve in Response",
    proposalNote: "Proposals are created as 'awaiting approval'. Nothing runs without approval.",
    viewerHint: "Creating proposals requires the analyst role",
    provenance: "Provenance",
    tier: "Tier",
    model: "Model",
    prompt: "Prompt version",
    call: "LLM call",
    escalated: "Escalated to deep",
    rulesFallback: "Rule-based verdict (LLM unavailable, over budget or refused).",
    disclaimer: "LLM verdicts are advisory. Verify against the evidence before acting.",
    noActions: "No recommended actions",
    noSteps: "None",
  },
};

function RecommendedActionRow({
  rec,
  subject,
  canOperate,
}: {
  rec: RecommendedAction;
  subject: { alertId?: string; incidentId?: string };
  canOperate: boolean;
}) {
  const L = useLocal(strings);
  const label = useLabel();
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: () =>
      api.post<ResponseAction>("/response/actions", {
        action_type: rec.action_type,
        target: rec.target,
        reason: rec.reason,
        ttl_minutes: rec.ttl_minutes ?? null,
        alert_id: subject.alertId ?? null,
        incident_id: subject.incidentId ?? null,
        // Authored by the LLM; the human who clicked is recorded by the server's audit log.
        proposed_by: "llm",
      } satisfies ActionProposal),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["response"] });
      void qc.invalidateQueries({ queryKey: ["incidents", "detail"] });
    },
  });
  return (
    <li className="rounded-md border border-line bg-surface-2/40 p-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <ActionTypeTag type={rec.action_type} />
        <span className="break-all rounded bg-surface px-1.5 py-0.5 font-mono text-xs">{rec.target}</span>
        {rec.ttl_minutes != null && <Badge>TTL {formatTtl(rec.ttl_minutes)}</Badge>}
      </div>
      <p className="mt-1.5 whitespace-pre-wrap break-words text-xs">{rec.reason}</p>
      <p className="mt-1 text-[11px] text-muted">{label(labelOf(actionTypeEffect, rec.action_type))}</p>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {m.data ? (
          <>
            <Badge tone="accent">
              <Check className="h-3 w-3" aria-hidden />
              {L.proposed}
            </Badge>
            <Link to="/response" className="text-xs text-accent hover:underline">
              {L.openResponse}
            </Link>
          </>
        ) : (
          <Button
            size="sm"
            variant="outline"
            onClick={() => m.mutate()}
            disabled={!canOperate || m.isPending}
            title={canOperate ? undefined : L.viewerHint}
          >
            {m.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
            ) : (
              <Plus className="h-3.5 w-3.5" aria-hidden />
            )}
            {L.propose}
          </Button>
        )}
      </div>
      {m.error && <ErrorState error={m.error} />}
    </li>
  );
}

export interface TriagePanelProps {
  triage: TriageRecord | null;
  /** The parent is currently being triaged (e.g. alert.status === "triaging"). */
  inProgress?: boolean;
  subject: { alertId?: string; incidentId?: string };
  /** Omit to hide re-triage controls. */
  onRetriage?: (tier?: RetriageTier) => void;
  /** Tiers offered as buttons. Empty array = one button without a tier (incidents). */
  retriageTiers?: RetriageTier[];
  retriaging?: boolean;
  retriageError?: unknown;
  /** Evidence ids rendered on the page (anchors `#ev-<id>`); others are shown without a link. */
  availableEvidenceIds?: ReadonlySet<string>;
  className?: string;
}

export function TriagePanel({
  triage,
  inProgress,
  subject,
  onRetriage,
  retriageTiers = ["fast", "deep"],
  retriaging,
  retriageError,
  availableEvidenceIds,
  className,
}: TriagePanelProps) {
  const L = useLocal(strings);
  const label = useLabel();
  const canOperate = useCanOperate();
  const busy = retriaging || inProgress;

  const controls = onRetriage ? (
    retriageTiers.length === 0 ? (
      <Button size="sm" variant="outline" onClick={() => onRetriage()} disabled={!canOperate || busy}>
        <RefreshCw className={cn("h-3.5 w-3.5", retriaging && "animate-spin")} aria-hidden />
        {triage ? L.retriage : L.runTriage}
      </Button>
    ) : (
      <div className="flex gap-1">
        {retriageTiers.map((tier) => (
          <Button
            key={tier}
            size="sm"
            variant="outline"
            onClick={() => onRetriage(tier)}
            disabled={!canOperate || busy}
            title={tier === "deep" ? L.deepHint : L.fastHint}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", retriaging && "animate-spin")} aria-hidden />
            {tier === "deep" ? L.deep : L.fast}
          </Button>
        ))}
      </div>
    )
  ) : null;

  const header = (
    <CardHeader
      title={
        <span className="flex items-center gap-1.5">
          <BrainCircuit className="h-4 w-4 text-ai" aria-hidden />
          {L.title}
        </span>
      }
      actions={controls}
    />
  );

  if (!triage) {
    return (
      <Card className={cn("border-ai/30", className)}>
        {header}
        <CardBody className="space-y-2">
          {busy ? (
            <p className="flex items-center gap-2 text-sm text-ai">
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
              {L.running}
            </p>
          ) : (
            <>
              <p className="text-sm text-muted">{L.none}</p>
              <p className="text-xs text-muted">{L.noneHint}</p>
            </>
          )}
          {retriageError ? <ErrorState error={retriageError} /> : null}
        </CardBody>
      </Card>
    );
  }

  const r = triage.result;
  const aiHigh = r.ai_agent_likelihood >= 0.7;
  const evidence = r.evidence_ids ?? [];

  return (
    <Card className={cn("border-ai/30", className)}>
      {header}
      <CardBody className="space-y-4">
        {busy && (
          <p className="flex items-center gap-2 text-xs text-ai">
            <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
            {L.running}
          </p>
        )}
        {retriageError ? <ErrorState error={retriageError} /> : null}

        {/* Verdict */}
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={r.severity} />
          <ActorBadge actor={r.actor_type} />
          <Badge>{r.category}</Badge>
          {r.attack_stage && r.attack_stage !== "none" && (
            <Badge tone="danger">{label(labelOf(attackStageLabel, r.attack_stage))}</Badge>
          )}
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <Meter value={r.confidence} label={L.confidence} />
          <Meter value={r.ai_agent_likelihood} label={L.aiLikelihood} tone={aiHigh ? "ai" : "warn"} />
        </div>

        {r.ai_agent_indicators.length > 0 && (
          <div
            className={cn(
              "rounded-md border p-2.5",
              aiHigh ? "border-ai/40 bg-ai/10" : "border-line bg-surface-2/40",
            )}
          >
            <SectionTitle icon={<Sparkles className="h-3.5 w-3.5 text-ai" aria-hidden />}>
              {L.aiIndicators}
            </SectionTitle>
            <ul className="space-y-1 text-xs">
              {r.ai_agent_indicators.map((ind, i) => (
                <li key={i} className="flex gap-1.5">
                  <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-ai" aria-hidden />
                  <span className="break-words">{ind}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        <div>
          <SectionTitle>{L.summary}</SectionTitle>
          <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">{r.summary}</p>
        </div>

        <div>
          <SectionTitle>{L.rationale}</SectionTitle>
          <p className="whitespace-pre-wrap break-words text-xs leading-relaxed text-fg/90">{r.rationale}</p>
          {evidence.length > 0 && (
            <div className="mt-2">
              <div className="mb-1 text-[11px] text-muted">{L.evidence}</div>
              <div className="flex flex-wrap gap-1">
                {evidence.map((id) =>
                  availableEvidenceIds?.has(id) ? (
                    <a
                      key={id}
                      href={`#ev-${id}`}
                      className="rounded border border-ai/40 bg-ai/10 px-1.5 py-0.5 font-mono text-[11px] text-ai hover:bg-ai/20"
                    >
                      {id.slice(0, 12)}
                    </a>
                  ) : (
                    <span
                      key={id}
                      className="rounded border border-line px-1.5 py-0.5 font-mono text-[11px] text-muted"
                      title={id}
                    >
                      {id.slice(0, 12)}
                    </span>
                  ),
                )}
              </div>
            </div>
          )}
          {triage.rejected_evidence_ids.length > 0 && (
            <p
              className="mt-2 flex items-center gap-1 text-[11px] text-sev-medium"
              title={triage.rejected_evidence_ids.join("\n")}
            >
              <TriangleAlert className="h-3 w-3" aria-hidden />
              {fmt(L.rejected, { n: triage.rejected_evidence_ids.length })}
            </p>
          )}
        </div>

        {r.mitre_techniques.length > 0 && (
          <div>
            <SectionTitle>{L.mitre}</SectionTitle>
            <MitreChips ids={r.mitre_techniques} />
          </div>
        )}

        <div>
          <SectionTitle icon={<ListChecks className="h-3.5 w-3.5" aria-hidden />}>{L.nextSteps}</SectionTitle>
          {r.next_steps.length ? (
            <ol className="list-decimal space-y-1 pl-5 text-xs">
              {r.next_steps.map((s, i) => (
                <li key={i} className="break-words">
                  {s}
                </li>
              ))}
            </ol>
          ) : (
            <p className="text-xs text-muted">{L.noSteps}</p>
          )}
        </div>

        <div>
          <SectionTitle icon={<ShieldCheck className="h-3.5 w-3.5" aria-hidden />}>
            {L.recommended}
          </SectionTitle>
          {r.recommended_actions.length ? (
            <>
              <ul className="space-y-2">
                {r.recommended_actions.map((rec, i) => (
                  <RecommendedActionRow
                    key={`${rec.action_type}-${rec.target}-${i}`}
                    rec={rec}
                    subject={subject}
                    canOperate={canOperate}
                  />
                ))}
              </ul>
              <p className="mt-2 flex items-center gap-1.5 text-[11px] text-muted">
                <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-accent" aria-hidden />
                {L.proposalNote}
              </p>
            </>
          ) : (
            <p className="text-xs text-muted">{L.noActions}</p>
          )}
        </div>

        {/* Provenance */}
        <div className="space-y-2 border-t border-line pt-3">
          <SectionTitle>{L.provenance}</SectionTitle>
          {triage.tier === "rules" && <p className="text-[11px] text-sev-medium">{L.rulesFallback}</p>}
          <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-[11px]">
            <dt className="text-muted">{L.tier}</dt>
            <dd className="flex flex-wrap items-center gap-1">
              {label(labelOf(tierLabel, triage.tier))}
              {triage.escalated && <Badge tone="ai">{L.escalated}</Badge>}
            </dd>
            <dt className="text-muted">{L.model}</dt>
            <dd className="break-all font-mono">{triage.model ?? "-"}</dd>
            <dt className="text-muted">{L.prompt}</dt>
            <dd className="break-all font-mono">{triage.prompt_version}</dd>
            {triage.llm_call_id && (
              <>
                <dt className="text-muted">{L.call}</dt>
                <dd className="break-all font-mono">{triage.llm_call_id}</dd>
              </>
            )}
          </dl>
          <p className="text-[11px] text-muted">{L.disclaimer}</p>
        </div>
      </CardBody>
    </Card>
  );
}
