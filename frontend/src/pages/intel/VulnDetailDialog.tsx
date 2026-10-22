/** Vulnerability detail: description, KEV/EPSS/CVSS facts, references, matched assets, advisories + generate. */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Sparkles } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { api } from "@/api/client";
import type { Advisory } from "@/api/types";
import type { VulnDetailResponse } from "@/api/types-intel";
import { SeverityBadge } from "@/components/common";
import { CvssScore, EpssBar, KevBadge, PriorityBadge, SafeLink } from "@/components/common/IntelBadges";
import { ApiErrorState, LoadingRows } from "@/components/common/QueryView";
import { useCan } from "@/components/common/RoleGate";
import { Badge, Button, Dialog, Spinner, Table, TBody, TD, TH, THead, TR } from "@/components/ui";
import { formatDateTime, pct } from "@/lib/format";
import { useLocal, useT } from "@/lib/i18n";
import { AdvisoryView } from "./AdvisoryView";
import { softwareLabel, useMatchStatusLabel } from "./labels";

const strings = {
  ja: {
    description: "説明",
    facts: "評価",
    published: "公開",
    modified: "更新",
    kevAdded: "KEV 登録日",
    kevDue: "対応期限（CISA）",
    cwe: "CWE",
    affected: "影響を受けるソフトウェア",
    aliases: "別名",
    sources: "情報源",
    references: "参照",
    matches: "一致した資産",
    noMatches: "インベントリに一致する資産はありません。",
    advisories: "アドバイザリ",
    noAdvisories: "まだアドバイザリはありません。",
    generate: "アドバイザリを生成",
    generating: "LLM で分析中…（数十秒かかることがあります）",
    asset: "資産",
    software: "ソフトウェア",
    reason: "理由",
    confidence: "信頼度",
    epssPct: "パーセンタイル",
    noDescription: "説明はありません。",
    generated: "生成されたアドバイザリ",
  },
  en: {
    description: "Description",
    facts: "Scores",
    published: "Published",
    modified: "Modified",
    kevAdded: "KEV date added",
    kevDue: "Due date (CISA)",
    cwe: "CWE",
    affected: "Affected software",
    aliases: "Aliases",
    sources: "Sources",
    references: "References",
    matches: "Matched assets",
    noMatches: "No asset in the inventory matches.",
    advisories: "Advisories",
    noAdvisories: "No advisories yet.",
    generate: "Generate advisory",
    generating: "Analyzing with the LLM… (may take tens of seconds)",
    asset: "Asset",
    software: "Software",
    reason: "Reason",
    confidence: "Confidence",
    epssPct: "percentile",
    noDescription: "No description.",
    generated: "Generated advisory",
  },
};

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] text-muted">{label}</dt>
      <dd className="mt-0.5 text-sm">{children}</dd>
    </div>
  );
}

export function VulnDetailDialog({ id, onClose }: { id: string | null; onClose: () => void }) {
  const L = useLocal(strings);
  const t = useT();
  const can = useCan();
  const qc = useQueryClient();
  const matchLabel = useMatchStatusLabel();
  const [generated, setGenerated] = useState<Advisory | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["intel", "vuln", id],
    queryFn: () => api.get<VulnDetailResponse>(`/intel/vulns/${encodeURIComponent(id ?? "")}`),
    enabled: !!id,
  });

  const gen = useMutation({
    mutationFn: () => api.post<Advisory>("/intel/advisories/generate", { vuln_id: id }),
    onSuccess: (adv) => {
      setGenerated(adv);
      qc.invalidateQueries({ queryKey: ["intel", "vuln", id] });
      qc.invalidateQueries({ queryKey: ["intel", "advisories"] });
    },
  });

  const close = () => {
    setGenerated(null);
    setExpanded(null);
    gen.reset();
    onClose();
  };

  const v = q.data?.vuln;
  return (
    <Dialog
      open={!!id}
      onClose={close}
      wide
      title={
        <span className="flex flex-wrap items-center gap-2">
          <span className="font-mono">{id}</span>
          {v?.kev && <KevBadge ransomware={v.kev_ransomware} />}
          {v?.severity && <SeverityBadge severity={v.severity} />}
        </span>
      }
      footer={
        <>
          {gen.isPending && (
            <span className="mr-auto flex items-center gap-2 text-xs text-ai">
              <Spinner className="h-3.5 w-3.5 border-t-ai" />
              {L.generating}
            </span>
          )}
          <Button variant="ghost" onClick={close}>
            {t("common.close")}
          </Button>
          {can.analyst && (
            <Button
              variant="outline"
              className="border-ai/40 text-ai hover:bg-ai/10"
              onClick={() => gen.mutate()}
              disabled={!v || gen.isPending}
            >
              <Sparkles className="h-4 w-4" aria-hidden />
              {L.generate}
            </Button>
          )}
        </>
      }
    >
      {q.isLoading && <LoadingRows rows={6} />}
      {q.error ? <ApiErrorState error={q.error} /> : null}
      {v && (
        <div className="space-y-5">
          {v.title && <p className="text-sm font-medium">{v.title}</p>}

          <dl className="grid grid-cols-2 gap-3 rounded-md border border-line bg-surface-2/40 p-3 sm:grid-cols-4">
            <Fact label="CVSS">
              <span className="flex items-center gap-2">
                <CvssScore score={v.cvss_score} vector={v.cvss_vector} />
                {v.cvss_vector && (
                  <span className="truncate font-mono text-[10px] text-muted" title={v.cvss_vector}>
                    {v.cvss_vector}
                  </span>
                )}
              </span>
            </Fact>
            <Fact label="EPSS">
              <span className="flex flex-col gap-0.5">
                <EpssBar epss={v.epss} percentile={v.epss_percentile} />
                {v.epss_percentile != null && (
                  <span className="text-[11px] text-muted">
                    {L.epssPct} {pct(v.epss_percentile, 1)}
                  </span>
                )}
              </span>
            </Fact>
            <Fact label={L.published}>{formatDateTime(v.published)}</Fact>
            <Fact label={L.modified}>{formatDateTime(v.modified)}</Fact>
            {v.kev && (
              <>
                <Fact label={L.kevAdded}>{formatDateTime(v.kev_date_added)}</Fact>
                <Fact label={L.kevDue}>
                  <span className="inline-flex items-center gap-1 font-medium text-sev-critical">
                    <CalendarClock className="h-3.5 w-3.5" aria-hidden />
                    {formatDateTime(v.kev_due_date)}
                  </span>
                </Fact>
              </>
            )}
          </dl>

          <section>
            <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
              {L.description}
            </h4>
            <p className="whitespace-pre-wrap text-sm leading-relaxed">{v.description || L.noDescription}</p>
          </section>

          <div className="grid gap-4 md:grid-cols-3">
            <section>
              <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">{L.cwe}</h4>
              <div className="flex flex-wrap gap-1">
                {v.cwe.length ? (
                  v.cwe.map((c) => <Badge key={c}>{c}</Badge>)
                ) : (
                  <span className="text-sm text-muted">-</span>
                )}
              </div>
            </section>
            <section>
              <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">{L.aliases}</h4>
              <div className="flex flex-wrap gap-1">
                {v.aliases.length ? (
                  v.aliases.map((a) => (
                    <span key={a} className="font-mono text-xs">
                      {a}
                    </span>
                  ))
                ) : (
                  <span className="text-sm text-muted">-</span>
                )}
              </div>
            </section>
            <section>
              <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">{L.sources}</h4>
              <div className="flex flex-wrap gap-1">
                {v.sources.map((s) => (
                  <Badge key={s} tone={s === "kev" ? "danger" : s === "research" ? "ai" : "neutral"}>
                    {s}
                  </Badge>
                ))}
              </div>
            </section>
          </div>

          {v.affected.length > 0 && (
            <section>
              <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
                {L.affected}
              </h4>
              <ul className="flex flex-wrap gap-1.5">
                {v.affected.slice(0, 40).map((s, i) => (
                  <li
                    key={i}
                    className="rounded border border-line px-1.5 py-0.5 font-mono text-[11px]"
                    title={s.cpe ?? undefined}
                  >
                    {softwareLabel(s)}
                    {s.ecosystem ? <span className="text-muted"> ({s.ecosystem})</span> : null}
                  </li>
                ))}
                {v.affected.length > 40 && <li className="text-xs text-muted">+{v.affected.length - 40}</li>}
              </ul>
            </section>
          )}

          <section>
            <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
              {L.matches} ({q.data?.matches.length ?? 0})
            </h4>
            {q.data?.matches.length ? (
              <div className="rounded-md border border-line">
                <Table>
                  <THead>
                    <tr>
                      <TH>{L.asset}</TH>
                      <TH>{L.software}</TH>
                      <TH>{L.reason}</TH>
                      <TH>{L.confidence}</TH>
                      <TH>{t("common.status")}</TH>
                    </tr>
                  </THead>
                  <TBody>
                    {q.data.matches.map((m) => (
                      <TR key={m.id}>
                        <TD>
                          <Link
                            to={`/assets?asset=${encodeURIComponent(m.asset_id)}`}
                            className="text-accent hover:underline"
                          >
                            {m.asset_name || m.asset_id}
                          </Link>
                        </TD>
                        <TD className="font-mono text-xs">{softwareLabel(m.software)}</TD>
                        <TD className="text-xs text-muted">{m.reason}</TD>
                        <TD className="tabular-nums text-xs">{pct(m.confidence)}</TD>
                        <TD>
                          <Badge tone={m.status === "open" ? "danger" : "neutral"}>
                            {matchLabel(m.status)}
                          </Badge>
                        </TD>
                      </TR>
                    ))}
                  </TBody>
                </Table>
              </div>
            ) : (
              <p className="text-sm text-muted">{L.noMatches}</p>
            )}
          </section>

          {generated && (
            <section className="rounded-md border border-ai/40 bg-ai/5 p-3">
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ai">{L.generated}</h4>
              <AdvisoryView advisory={generated} />
            </section>
          )}
          {gen.error ? <ApiErrorState error={gen.error} /> : null}

          <section>
            <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
              {L.advisories} ({q.data?.advisories.length ?? 0})
            </h4>
            {q.data?.advisories.length ? (
              <ul className="divide-y divide-line rounded-md border border-line">
                {q.data.advisories.map((adv) => (
                  <li key={adv.id}>
                    <button
                      type="button"
                      aria-expanded={expanded === adv.id}
                      className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-surface-2"
                      onClick={() => setExpanded(expanded === adv.id ? null : adv.id)}
                    >
                      <PriorityBadge priority={adv.priority} />
                      <span className="min-w-0 flex-1 truncate">{adv.title}</span>
                      <span className="shrink-0 text-xs text-muted">{formatDateTime(adv.created_at)}</span>
                    </button>
                    {expanded === adv.id && (
                      <div className="border-t border-line p-3">
                        <AdvisoryView advisory={adv} showHeader={false} />
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">{L.noAdvisories}</p>
            )}
          </section>

          {v.references.length > 0 && (
            <section>
              <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
                {L.references}
              </h4>
              <ul className="space-y-1 text-xs">
                {v.references.slice(0, 30).map((r, i) => (
                  <li key={i}>
                    <SafeLink href={r} />
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      )}
    </Dialog>
  );
}
