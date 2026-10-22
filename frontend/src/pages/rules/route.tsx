/**
 * Rules (/rules): detectors (runtime toggle), Sigma rules (CRUD + validate), LLM-proposed rule review.
 * ?tab=proposals&q=<title> is the landing target of "Review as rule" on intel advisories.
 * OWNER: frontend-intel.
 */
import { useQuery } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { api } from "@/api/client";
import type { Page, Rule } from "@/api/types";
import { PageHeader } from "@/components/common";
import { useUrlParams } from "@/components/common/urlState";
import { Tabs } from "@/components/ui";
import { useLocal } from "@/lib/i18n";
import type { AppRoute } from "@/routes";
import { DetectorsTab } from "./DetectorsTab";
import { ProposalsTab } from "./ProposalsTab";
import { SigmaTab } from "./SigmaTab";

type Tab = "detectors" | "sigma" | "proposals";
const TABS: Tab[] = ["detectors", "sigma", "proposals"];
const TAB_PARAMS = ["status", "source", "offset", "q", "rule"];

const strings = {
  ja: {
    title: "検知ルール",
    desc: "検知器の有効/無効、Sigma ルールの管理、LLM が提案したルールのレビュー",
    detectors: "検知器",
    sigma: "Sigma ルール",
    proposals: "LLM 提案",
  },
  en: {
    title: "Detection rules",
    desc: "Enable/disable detectors, manage Sigma rules, and review LLM-proposed rules",
    detectors: "Detectors",
    sigma: "Sigma rules",
    proposals: "LLM proposals",
  },
};

function RulesPage() {
  const L = useLocal(strings);
  const [params, update] = useUrlParams();
  const raw = params.get("tab") as Tab | null;
  const tab: Tab = raw && TABS.includes(raw) ? raw : "detectors";

  const pending = useQuery({
    queryKey: ["rules", "list", { status: "proposed", count: true }],
    queryFn: () => api.get<Page<Rule>>("/rules", { status: "proposed", limit: 1 }),
    select: (p) => p.total,
    retry: false,
  });

  return (
    <div>
      <PageHeader title={L.title} description={L.desc} />
      <Tabs<Tab>
        value={tab}
        onChange={(v) => {
          const patch: Record<string, null> = Object.fromEntries(TAB_PARAMS.map((k) => [k, null]));
          update({ ...patch, tab: v === "detectors" ? null : v });
        }}
        tabs={[
          { value: "detectors", label: L.detectors },
          { value: "sigma", label: L.sigma },
          {
            value: "proposals",
            label: (
              <span className="inline-flex items-center gap-1.5">
                {L.proposals}
                {(pending.data ?? 0) > 0 && (
                  <span className="rounded-full bg-ai/20 px-1.5 text-[10px] font-semibold tabular-nums text-ai">
                    {pending.data}
                  </span>
                )}
              </span>
            ),
          },
        ]}
      />
      <div className="mt-4">
        {tab === "detectors" && <DetectorsTab />}
        {tab === "sigma" && <SigmaTab />}
        {tab === "proposals" && <ProposalsTab />}
      </div>
    </div>
  );
}

export const route: AppRoute = {
  path: "/rules",
  component: RulesPage,
  nav: {
    label: { ja: "検知ルール", en: "Rules" },
    icon: ShieldCheck,
    section: "intel",
    order: 44,
  },
};
