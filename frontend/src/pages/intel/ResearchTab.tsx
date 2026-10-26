/**
 * LLM web research (0-day / exploitation watch). Findings are model output grounded in web search results:
 * they are labelled as AI-generated and every claim links back to its sources so analysts can verify facts.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe, Radar, Search } from "lucide-react";
import { type FormEvent, useState } from "react";
import { api } from "@/api/client";
import type { Page, ResearchFinding, ResearchReport } from "@/api/types";
import { AiGeneratedBadge, hostOf, isSafeHttpUrl, SafeLink } from "@/components/common/IntelBadges";
import { ApiErrorState, QueryView } from "@/components/common/QueryView";
import { useCan } from "@/components/common/RoleGate";
import { Badge, Button, Card, CardBody, EmptyState, Input, Spinner } from "@/components/ui";
import { formatDateTime } from "@/lib/format";
import { useLocal } from "@/lib/i18n";

const strings = {
  ja: {
    title: "Web リサーチ",
    desc: "LLM のサーバーサイド Web 検索で、フィード掲載前の 0day・悪用報告・AI 攻撃キャンペーンを調査します。信頼できる情報源に限定して検索します。",
    caution: "AI による要約です。判断の前に出典で事実を確認してください。",
    topic: "調査テーマ（任意。空欄なら既定テーマと資産インベントリで調査）",
    run: "今すぐ調査",
    running: "調査中…（Web 検索を含むため 1〜2 分かかることがあります）",
    empty: "リサーチ結果はまだありません",
    emptyHint: "「今すぐ調査」で実行するか、定期ジョブ（intel.research）の実行を待ってください。",
    findings: "件の発見",
    noFindings: "特筆すべき発見はありませんでした。",
    assessment: "総合評価",
    cves: "CVE",
    products: "影響製品",
    relevance: "自組織との関連",
    actions: "推奨アクション",
    sources: "出典",
    citations: "引用された Web ページ",
    exploitation: "悪用状況",
    done: "調査が完了しました",
  },
  en: {
    title: "Web research",
    desc: "Uses the LLM's server-side web search to look for 0-days, exploitation reports and AI-driven campaigns before they reach the feeds. Searches are limited to trusted sources.",
    caution: "AI-generated summary. Verify facts against the sources before acting.",
    topic: "Topic (optional; empty = default topics + asset inventory)",
    run: "Research now",
    running: "Researching… (web search may take 1–2 minutes)",
    empty: "No research reports yet",
    emptyHint: "Run it now, or wait for the periodic job (intel.research).",
    findings: "findings",
    noFindings: "Nothing notable was found.",
    assessment: "Overall assessment",
    cves: "CVE",
    products: "Affected products",
    relevance: "Relevance to our assets",
    actions: "Recommended actions",
    sources: "Sources",
    citations: "Cited web pages",
    exploitation: "Exploitation",
    done: "Research finished",
  },
};

function exploitationTone(text: string): "danger" | "warn" | "neutral" {
  const s = text.toLowerCase();
  if (/wild|exploited|悪用/.test(s)) return "danger";
  if (/poc|proof|概念実証/.test(s)) return "warn";
  return "neutral";
}

function FindingCard({ f, onOpenVuln }: { f: ResearchFinding; onOpenVuln: (id: string) => void }) {
  const L = useLocal(strings);
  return (
    <div className="flex flex-col gap-2 rounded-md border border-line bg-surface-2/30 p-3">
      <div className="flex items-start justify-between gap-2">
        <h4 className="text-sm font-medium leading-snug">{f.title}</h4>
        {f.exploitation && (
          <Badge tone={exploitationTone(f.exploitation)} className="shrink-0" title={L.exploitation}>
            {f.exploitation}
          </Badge>
        )}
      </div>
      <p className="whitespace-pre-wrap text-xs leading-relaxed">{f.summary}</p>
      {f.cve_ids.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {f.cve_ids.map((id) => (
            <button
              key={id}
              type="button"
              onClick={() => onOpenVuln(id)}
              className="rounded border border-line bg-surface px-1.5 py-0.5 font-mono text-[10px] hover:border-accent hover:text-accent"
            >
              {id}
            </button>
          ))}
        </div>
      )}
      {f.affected_products.length > 0 && (
        <p className="text-[11px] text-muted">
          <span className="font-medium text-fg">{L.products}: </span>
          {f.affected_products.join(", ")}
        </p>
      )}
      {f.relevance_to_assets && (
        <p className="text-[11px] text-muted">
          <span className="font-medium text-fg">{L.relevance}: </span>
          {f.relevance_to_assets}
        </p>
      )}
      {f.recommended_actions.length > 0 && (
        <div>
          <div className="text-[11px] font-medium">{L.actions}</div>
          <ul className="mt-0.5 list-disc space-y-0.5 pl-4 text-[11px]">
            {f.recommended_actions.map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
        </div>
      )}
      {f.source_urls.length > 0 && (
        <div className="mt-auto flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-line pt-2 text-[11px]">
          <span className="text-muted">{L.sources}:</span>
          {f.source_urls.map((u, i) => (
            <SafeLink key={i} href={u}>
              {isSafeHttpUrl(u) ? hostOf(u) : u}
            </SafeLink>
          ))}
        </div>
      )}
    </div>
  );
}

function ReportCard({ report, onOpenVuln }: { report: ResearchReport; onOpenVuln: (id: string) => void }) {
  const L = useLocal(strings);
  const findings = report.output?.findings ?? [];
  const citations = (report.citations ?? [])
    .map((c) => ({
      url: typeof c.url === "string" ? c.url : null,
      title: typeof c.title === "string" ? c.title : null,
    }))
    .filter((c) => isSafeHttpUrl(c.url));
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3">
        <Radar className="h-4 w-4 text-ai" aria-hidden />
        <h3 className="min-w-0 flex-1 truncate text-sm font-semibold">{report.topic}</h3>
        <AiGeneratedBadge />
        <Badge>
          {findings.length} {L.findings}
        </Badge>
        <span className="text-xs text-muted">{formatDateTime(report.created_at)}</span>
      </div>
      <CardBody className="space-y-3">
        {report.output?.overall_assessment && (
          <div className="rounded-md border border-ai/20 bg-ai/5 p-3">
            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-ai">
              {L.assessment}
            </div>
            <p className="whitespace-pre-wrap text-sm leading-relaxed">{report.output.overall_assessment}</p>
          </div>
        )}
        {findings.length ? (
          <div className="grid gap-3 md:grid-cols-2">
            {findings.map((f, i) => (
              <FindingCard key={i} f={f} onOpenVuln={onOpenVuln} />
            ))}
          </div>
        ) : (
          <p className="text-sm text-muted">{L.noFindings}</p>
        )}
        {citations.length > 0 && (
          <details className="text-xs">
            <summary className="cursor-pointer text-muted hover:text-fg">
              {L.citations} ({citations.length})
            </summary>
            <ul className="mt-2 space-y-1">
              {citations.map((c, i) => (
                <li key={i}>
                  <SafeLink href={c.url}>{c.title || c.url}</SafeLink>
                </li>
              ))}
            </ul>
          </details>
        )}
      </CardBody>
    </Card>
  );
}

export function ResearchTab({ onOpenVuln }: { onOpenVuln: (id: string) => void }) {
  const L = useLocal(strings);
  const can = useCan();
  const qc = useQueryClient();
  const [topic, setTopic] = useState("");

  const list = useQuery({
    queryKey: ["intel", "research"],
    queryFn: () => api.get<Page<ResearchReport>>("/intel/research", { limit: 20 }),
  });

  const run = useMutation({
    mutationFn: () =>
      api.post<ResearchReport>("/intel/research/run", topic.trim() ? { topic: topic.trim() } : {}),
    onSuccess: () => {
      setTopic("");
      qc.invalidateQueries({ queryKey: ["intel", "research"] });
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!run.isPending) run.mutate();
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardBody className="space-y-3">
          <div className="flex items-start gap-3">
            <Globe className="mt-0.5 h-5 w-5 shrink-0 text-ai" aria-hidden />
            <div className="space-y-1">
              <h3 className="text-sm font-semibold">{L.title}</h3>
              <p className="text-xs text-muted">{L.desc}</p>
              <p className="text-xs text-sev-medium">{L.caution}</p>
            </div>
          </div>
          {can.analyst && (
            <form onSubmit={submit} className="flex flex-wrap gap-2">
              <Input
                className="min-w-[16rem] flex-1"
                value={topic}
                onChange={(e) => setTopic(e.target.value)}
                placeholder={L.topic}
                aria-label={L.topic}
                maxLength={300}
                disabled={run.isPending}
              />
              <Button type="submit" disabled={run.isPending} className="bg-ai text-white hover:opacity-90">
                {run.isPending ? (
                  <Spinner className="h-4 w-4 border-white/40 border-t-white" />
                ) : (
                  <Search className="h-4 w-4" aria-hidden />
                )}
                {L.run}
              </Button>
            </form>
          )}
          {run.isPending && <p className="text-xs text-ai">{L.running}</p>}
          {run.error ? <ApiErrorState error={run.error} /> : null}
        </CardBody>
      </Card>

      <QueryView
        query={list}
        rows={4}
        isEmpty={(d) => (d.items ?? []).length === 0}
        empty={
          <Card>
            <EmptyState title={L.empty} hint={L.emptyHint} icon={<Radar className="h-6 w-6" />} />
          </Card>
        }
      >
        {(page) => (
          <div className="space-y-4">
            {page.items.map((r) => (
              <ReportCard key={r.id} report={r} onOpenVuln={onOpenVuln} />
            ))}
          </div>
        )}
      </QueryView>
    </div>
  );
}
