/**
 * Hosts (`/hosts`): listening ports per host (allowed vs deviation) and port-baseline management.
 * Data: GET /hosts, GET /hosts/ports, GET/POST/DELETE /hosts/baselines, POST /hosts/baselines/learn.
 */
import { Server } from "lucide-react";
import { useMemo, useState } from "react";
import type { HostSummary } from "@/api/types-core";
import { PageHeader } from "@/components/common";
import { useFlash } from "@/components/common/Flash";
import { Tabs } from "@/components/ui";
import { useApiQuery } from "@/hooks/useApi";
import { useHasRole } from "@/hooks/useRole";
import { useSearchState } from "@/hooks/useSearchState";
import { useLocal } from "@/lib/i18n";
import type { AppRoute } from "@/routes";
import { BaselineDialog, type BaselineDraft, EMPTY_DRAFT } from "./BaselineDialog";
import { BaselinesPanel } from "./BaselinesPanel";
import { PortsPanel } from "./PortsPanel";

type Tab = "ports" | "baselines";

function HostsPage() {
  const L = useLocal({
    ja: {
      title: "ホスト",
      desc: "リスニングポートの監視とベースライン（許可リスト）管理。ベースライン外の待ち受けは逸脱として検知されます。",
      ports: "ポート",
      baselines: "ベースライン",
      created: "ベースラインを追加しました",
    },
    en: {
      title: "Hosts",
      desc: "Listening-port monitoring and baseline (allow-list) management. Listeners outside the baseline are flagged.",
      ports: "Ports",
      baselines: "Baselines",
      created: "Baseline added",
    },
  });
  const [f, setF] = useSearchState(["tab", "host"] as const);
  const tab: Tab = f.tab === "baselines" ? "baselines" : "ports";
  const canWrite = useHasRole("analyst");
  const { flash, node: flashNode } = useFlash();
  const [dialog, setDialog] = useState<BaselineDraft | null>(null);

  // Shares the cache entry with PortsPanel (same key) — used for the host pickers.
  const hostsQ = useApiQuery<HostSummary[]>(["hosts", "list"], "/hosts", undefined, {
    refetchInterval: 30_000,
  });
  const knownHosts = useMemo(() => (hostsQ.data ?? []).map((h) => h.host), [hostsQ.data]);

  return (
    <div className="space-y-4">
      <PageHeader title={L.title} description={L.desc} />
      <Tabs<Tab>
        tabs={[
          { value: "ports", label: L.ports },
          { value: "baselines", label: L.baselines },
        ]}
        value={tab}
        onChange={(t) => setF({ tab: t === "ports" ? null : t }, false)}
      />
      {tab === "ports" ? (
        <PortsPanel
          host={f.host}
          onSelectHost={(h) => setF({ host: h })}
          canWrite={canWrite}
          onAddBaseline={(d) => setDialog(d)}
          flash={flash}
        />
      ) : (
        <BaselinesPanel
          canWrite={canWrite}
          knownHosts={knownHosts}
          onAdd={() => setDialog({ ...EMPTY_DRAFT, host: f.host })}
          flash={flash}
        />
      )}
      <BaselineDialog
        open={dialog !== null}
        initial={dialog ?? EMPTY_DRAFT}
        hosts={knownHosts}
        onClose={() => setDialog(null)}
        onCreated={() => {
          setDialog(null);
          flash(L.created);
        }}
      />
      {flashNode}
    </div>
  );
}

export const route: AppRoute = {
  path: "/hosts",
  component: HostsPage,
  nav: {
    label: { ja: "ホスト", en: "Hosts" },
    icon: Server,
    section: "monitor",
    order: 40,
  },
};
