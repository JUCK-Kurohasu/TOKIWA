/**
 * Intel (/intel): vulnerabilities (KEV/EPSS/CVSS), asset matches, LLM advisories, news, web research, feed sources.
 * Tab, filters and the open vulnerability (?vuln=) live in the URL so views are linkable.
 * OWNER: frontend-intel.
 */
import { useQuery } from "@tanstack/react-query";
import { FileWarning, Flame, Link2, Radar } from "lucide-react";
import { useCallback } from "react";
import { api } from "@/api/client";
import type { Page } from "@/api/types";
import { PageHeader } from "@/components/common";
import { useUrlParams } from "@/components/common/urlState";
import { Tabs } from "@/components/ui";
import { formatNumber } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import type { AppRoute } from "@/routes";
import { AdvisoriesTab } from "./AdvisoriesTab";
import { MatchesTab } from "./MatchesTab";
import { NewsTab } from "./NewsTab";
import { ResearchTab } from "./ResearchTab";
import { SourcesTab } from "./SourcesTab";
import { VulnDetailDialog } from "./VulnDetailDialog";
import { VulnsTab } from "./VulnsTab";

type Tab = "vulns" | "matches" | "advisories" | "news" | "research" | "sources";
const TABS: Tab[] = ["vulns", "matches", "advisories", "news", "research", "sources"];
/** Filter params owned by individual tabs; cleared when switching tabs. */
const TAB_PARAMS = [
  "q",
  "kev",
  "matched",
  "min_epss",
  "min_cvss",
  "offset",
  "status",
  "priority",
  "adv",
  "source",
];

const strings = {
  ja: {
    title: "インテリジェンス",
    desc: "脆弱性フィード（KEV / EPSS / NVD / JVN / OSV / GHSA）と資産の照合、LLM による優先度付きアドバイザリ",
    vulns: "脆弱性",
    matches: "資産一致",
    advisories: "アドバイザリ",
    news: "ニュース",
    research: "Web リサーチ",
    sources: "ソース状態",
    kevMatched: "KEV × 資産一致",
    openMatches: "未対応の資産一致",
    p1: "P1 アドバイザリ（新規）",
  },
  en: {
    title: "Intelligence",
    desc: "Vulnerability feeds (KEV / EPSS / NVD / JVN / OSV / GHSA) matched to your assets, with prioritized LLM advisories",
    vulns: "Vulnerabilities",
    matches: "Asset matches",
    advisories: "Advisories",
    news: "News",
    research: "Web research",
    sources: "Sources",
    kevMatched: "KEV × matched assets",
    openMatches: "Open asset matches",
    p1: "P1 advisories (new)",
  },
};

function SummaryChip({
  label,
  value,
  icon,
  tone,
  onClick,
}: {
  label: string;
  value: number | undefined;
  icon: React.ReactNode;
  tone: "danger" | "accent" | "ai";
  onClick: () => void;
}) {
  const hot = (value ?? 0) > 0;
  const toneCls = {
    danger: "border-sev-critical/40 text-sev-critical",
    accent: "border-sev-high/40 text-sev-high",
    ai: "border-ai/40 text-ai",
  }[tone];
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "flex min-w-[11rem] items-center gap-3 rounded-lg border bg-surface px-3 py-2 text-left transition-colors hover:bg-surface-2",
        hot ? toneCls : "border-line text-muted",
      )}
    >
      {icon}
      <span className="flex flex-col">
        <span className="text-lg font-semibold leading-tight tabular-nums">
          {value === undefined ? "–" : formatNumber(value)}
        </span>
        <span className="text-[11px] text-muted">{label}</span>
      </span>
    </button>
  );
}

function useCount(key: string, path: string, params: Record<string, string | number | boolean>) {
  return useQuery({
    queryKey: ["intel", "summary", key],
    queryFn: () => api.get<Page<unknown>>(path, { ...params, limit: 1 }),
    select: (p) => p.total,
    staleTime: 30_000,
    retry: false,
  });
}

function IntelPage() {
  const L = useLocal(strings);
  const [params, update] = useUrlParams();
  const raw = params.get("tab") as Tab | null;
  const tab: Tab = raw && TABS.includes(raw) ? raw : "vulns";
  const vulnId = params.get("vuln");

  const kevMatched = useCount("kev-matched", "/intel/vulns", { kev: true, matched: true });
  const openMatches = useCount("open-matches", "/intel/matches", { status: "open" });
  const p1 = useCount("p1", "/intel/advisories", { priority: "P1", status: "new" });

  const switchTab = useCallback(
    (next: Tab, extra: Record<string, string> = {}) => {
      const patch: Record<string, string | null> = Object.fromEntries(TAB_PARAMS.map((k) => [k, null]));
      update({ ...patch, tab: next === "vulns" ? null : next, ...extra });
    },
    [update],
  );
  const openVuln = useCallback((id: string) => update({ vuln: id }), [update]);

  return (
    <div>
      <PageHeader title={L.title} description={L.desc} />
      <div className="mb-4 flex flex-wrap gap-2">
        <SummaryChip
          label={L.kevMatched}
          value={kevMatched.data}
          tone="danger"
          icon={<Flame className="h-5 w-5" aria-hidden />}
          onClick={() => switchTab("vulns", { kev: "1", matched: "1" })}
        />
        <SummaryChip
          label={L.openMatches}
          value={openMatches.data}
          tone="accent"
          icon={<Link2 className="h-5 w-5" aria-hidden />}
          onClick={() => switchTab("matches")}
        />
        <SummaryChip
          label={L.p1}
          value={p1.data}
          tone="ai"
          icon={<FileWarning className="h-5 w-5" aria-hidden />}
          onClick={() => switchTab("advisories", { priority: "P1", status: "new" })}
        />
      </div>

      <Tabs<Tab>
        value={tab}
        onChange={(v) => switchTab(v)}
        tabs={[
          { value: "vulns", label: L.vulns },
          { value: "matches", label: L.matches },
          { value: "advisories", label: L.advisories },
          { value: "news", label: L.news },
          {
            value: "research",
            label: (
              <span className="inline-flex items-center gap-1">
                <Radar className="h-3.5 w-3.5 text-ai" aria-hidden />
                {L.research}
              </span>
            ),
          },
          { value: "sources", label: L.sources },
        ]}
      />
      <div className="mt-4">
        {tab === "vulns" && <VulnsTab onOpen={openVuln} />}
        {tab === "matches" && <MatchesTab onOpenVuln={openVuln} />}
        {tab === "advisories" && <AdvisoriesTab onOpenVuln={openVuln} />}
        {tab === "news" && <NewsTab onOpenVuln={openVuln} />}
        {tab === "research" && <ResearchTab onOpenVuln={openVuln} />}
        {tab === "sources" && <SourcesTab />}
      </div>

      <VulnDetailDialog id={vulnId} onClose={() => update({ vuln: null })} />
    </div>
  );
}

export const route: AppRoute = {
  path: "/intel",
  component: IntelPage,
  nav: {
    label: { ja: "インテリジェンス", en: "Intelligence" },
    icon: Radar,
    section: "intel",
    order: 40,
  },
};
