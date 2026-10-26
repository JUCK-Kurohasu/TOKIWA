/**
 * Full rendering of an LLM advisory (AdvisoryAnalysis). Model text is shown as plain text (React-escaped).
 * Proposed Sigma rules are never applied from here: "Review as rule" sends the analyst to the Rules review queue.
 */
import { Check, ClipboardCopy, FileCode2, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router";
import type { Advisory, ProposedRule } from "@/api/types";
import { AiGeneratedBadge, PriorityBadge, SafeLink } from "@/components/common/IntelBadges";
import { Button } from "@/components/ui";
import { formatDateTime, pct } from "@/lib/format";
import { useLocal } from "@/lib/i18n";

const strings = {
  ja: {
    summary: "要約",
    exploitation: "悪用状況",
    impact: "影響",
    mitigations: "緩和策",
    detection: "検知機会",
    rules: "Sigma ルール提案",
    rulesHint:
      "提案は自動では有効化されません。ルール画面でレビューし、承認したものだけが検知に反映されます。",
    review: "ルールとして確認",
    copy: "コピー",
    copied: "コピーしました",
    rationale: "根拠",
    affected: "影響を受ける資産",
    references: "参考情報",
    confidence: "信頼度",
    vulns: "対象脆弱性",
    llmCall: "LLM 呼び出し記録",
    none: "なし",
  },
  en: {
    summary: "Summary",
    exploitation: "Exploitation",
    impact: "Impact",
    mitigations: "Mitigations",
    detection: "Detection opportunities",
    rules: "Proposed Sigma rules",
    rulesHint:
      "Proposals are never enabled automatically. Review them on the Rules page; only approved rules go live.",
    review: "Review as rule",
    copy: "Copy",
    copied: "Copied",
    rationale: "Rationale",
    affected: "Affected assets",
    references: "References",
    confidence: "Confidence",
    vulns: "Vulnerabilities",
    llmCall: "LLM call record",
    none: "None",
  },
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">{title}</h4>
      {children}
    </section>
  );
}

function BulletList({ items, empty }: { items: string[]; empty: string }) {
  if (!items.length) return <p className="text-sm text-muted">{empty}</p>;
  return (
    <ul className="list-disc space-y-1 pl-5 text-sm">
      {items.map((it, i) => (
        <li key={i}>{it}</li>
      ))}
    </ul>
  );
}

function ProposedRuleCard({ rule }: { rule: ProposedRule }) {
  const L = useLocal(strings);
  const navigate = useNavigate();
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-md border border-ai/30 bg-ai/5">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-ai/20 px-3 py-2">
        <div className="flex min-w-0 items-center gap-2">
          <FileCode2 className="h-4 w-4 shrink-0 text-ai" aria-hidden />
          <span className="truncate text-sm font-medium">{rule.title}</span>
          <span className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] uppercase text-muted">
            {rule.kind || "sigma"}
          </span>
        </div>
        <div className="flex gap-1.5">
          <Button
            variant="ghost"
            size="sm"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(rule.content);
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              } catch {
                /* clipboard unavailable (insecure context) */
              }
            }}
          >
            {copied ? (
              <Check className="h-3.5 w-3.5" aria-hidden />
            ) : (
              <ClipboardCopy className="h-3.5 w-3.5" aria-hidden />
            )}
            {copied ? L.copied : L.copy}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() =>
              navigate(`/rules?tab=proposals&q=${encodeURIComponent(rule.title)}`, {
                state: { proposal: { title: rule.title, content: rule.content, rationale: rule.rationale } },
              })
            }
          >
            <ShieldCheck className="h-3.5 w-3.5" aria-hidden />
            {L.review}
          </Button>
        </div>
      </div>
      {rule.rationale && (
        <p className="px-3 pt-2 text-xs text-muted">
          <span className="font-medium text-fg">{L.rationale}: </span>
          {rule.rationale}
        </p>
      )}
      <pre className="m-3 max-h-64 overflow-auto rounded border border-line bg-bg p-2.5 font-mono text-[11px] leading-relaxed">
        {rule.content}
      </pre>
    </div>
  );
}

export function AdvisoryView({
  advisory,
  onOpenVuln,
  showHeader = true,
}: {
  advisory: Advisory;
  onOpenVuln?: (id: string) => void;
  showHeader?: boolean;
}) {
  const L = useLocal(strings);
  const a = advisory.analysis;
  const rules = a?.proposed_rules ?? [];
  return (
    <div className="space-y-4">
      {showHeader && (
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <PriorityBadge priority={advisory.priority} showHint />
            <AiGeneratedBadge />
            <span className="text-xs text-muted">{formatDateTime(advisory.created_at)}</span>
          </div>
          <h3 className="text-base font-semibold leading-snug">{advisory.title}</h3>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted">
        <span className="flex flex-wrap items-center gap-1">
          {L.vulns}:
          {advisory.vuln_ids.map((id) =>
            onOpenVuln ? (
              <button
                key={id}
                type="button"
                className="font-mono text-accent hover:underline"
                onClick={() => onOpenVuln(id)}
              >
                {id}
              </button>
            ) : (
              <span key={id} className="font-mono text-fg">
                {id}
              </span>
            ),
          )}
        </span>
        {a?.confidence != null && (
          <span>
            {L.confidence}: <span className="tabular-nums text-fg">{pct(a.confidence)}</span>
          </span>
        )}
        {advisory.llm_call_id && (
          <Link
            to={`/llm?tab=calls&call=${encodeURIComponent(advisory.llm_call_id)}`}
            className="text-ai hover:underline"
          >
            {L.llmCall}
          </Link>
        )}
      </div>

      <Section title={L.summary}>
        <p className="whitespace-pre-wrap text-sm leading-relaxed">{a?.summary}</p>
      </Section>
      <div className="grid gap-4 md:grid-cols-2">
        <Section title={L.exploitation}>
          <p className="text-sm">{a?.exploitation_status || "-"}</p>
        </Section>
        <Section title={L.impact}>
          <p className="whitespace-pre-wrap text-sm">{a?.impact || "-"}</p>
        </Section>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <Section title={L.mitigations}>
          <BulletList items={a?.mitigations ?? []} empty={L.none} />
        </Section>
        <Section title={L.detection}>
          <BulletList items={a?.detection_opportunities ?? []} empty={L.none} />
        </Section>
      </div>

      {(a?.affected_assets?.length ?? 0) > 0 && (
        <Section title={L.affected}>
          <div className="flex flex-wrap gap-1.5">
            {a.affected_assets.map((id) => (
              <Link
                key={id}
                to={`/assets?asset=${encodeURIComponent(id)}`}
                className="rounded border border-line bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] hover:border-accent hover:text-accent"
              >
                {id}
              </Link>
            ))}
          </div>
        </Section>
      )}

      {rules.length > 0 && (
        <Section title={L.rules}>
          <p className="mb-2 text-xs text-muted">{L.rulesHint}</p>
          <div className="space-y-3">
            {rules.map((r, i) => (
              <ProposedRuleCard key={`${r.title}-${i}`} rule={r} />
            ))}
          </div>
        </Section>
      )}

      {(a?.references?.length ?? 0) > 0 && (
        <Section title={L.references}>
          <ul className="space-y-1 text-xs">
            {a.references.map((r, i) => (
              <li key={i}>
                <SafeLink href={r} />
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}
