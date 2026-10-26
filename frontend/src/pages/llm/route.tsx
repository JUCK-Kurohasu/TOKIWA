/**
 * LLM (/llm): runtime settings (write-only API keys), usage charts, call audit log, connection test.
 * ?tab=calls&call=<id> deep-links into an audit record (used by advisories / rule proposals).
 * OWNER: frontend-intel.
 */
import { Cpu } from "lucide-react";
import { PageHeader } from "@/components/common";
import { useUrlParams } from "@/components/common/urlState";
import { Tabs } from "@/components/ui";
import { useLocal } from "@/lib/i18n";
import type { AppRoute } from "@/routes";
import { CallsTab } from "./CallsTab";
import { ConfigTab } from "./ConfigTab";
import { UsageTab } from "./UsageTab";

type Tab = "config" | "usage" | "calls";
const TABS: Tab[] = ["config", "usage", "calls"];
const TAB_PARAMS = ["purpose", "status", "offset", "call"];

const strings = {
  ja: {
    title: "LLM",
    desc: "LLM プロバイダ・モデル・予算の設定、利用状況、呼び出し監査ログ。全呼び出しはゲートウェイ経由で予算・マスキング・監査が適用されます。",
    config: "設定",
    usage: "利用状況",
    calls: "呼び出しログ",
  },
  en: {
    title: "LLM",
    desc: "Provider, models and budget; usage; and the call audit log. Every call goes through the gateway (budget, redaction, audit).",
    config: "Settings",
    usage: "Usage",
    calls: "Call log",
  },
};

function LlmPage() {
  const L = useLocal(strings);
  const [params, update] = useUrlParams();
  const raw = params.get("tab") as Tab | null;
  const tab: Tab = raw && TABS.includes(raw) ? raw : "config";
  return (
    <div>
      <PageHeader title={L.title} description={L.desc} />
      <Tabs<Tab>
        value={tab}
        onChange={(v) => {
          const patch: Record<string, null> = Object.fromEntries(TAB_PARAMS.map((k) => [k, null]));
          update({ ...patch, tab: v === "config" ? null : v });
        }}
        tabs={[
          { value: "config", label: L.config },
          { value: "usage", label: L.usage },
          { value: "calls", label: L.calls },
        ]}
      />
      <div className="mt-4">
        {tab === "config" && <ConfigTab />}
        {tab === "usage" && <UsageTab />}
        {tab === "calls" && <CallsTab />}
      </div>
    </div>
  );
}

export const route: AppRoute = {
  path: "/llm",
  component: LlmPage,
  nav: {
    label: { ja: "LLM", en: "LLM" },
    icon: Cpu,
    section: "system",
    order: 82,
  },
};
