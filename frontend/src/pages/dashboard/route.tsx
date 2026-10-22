/**
 * Dashboard (placeholder in the skeleton). OWNER: frontend-shell agent.
 */
import { LayoutDashboard } from "lucide-react";
import { PageHeader } from "@/components/common";
import { Card, CardBody } from "@/components/ui";
import { useLocal } from "@/lib/i18n";
import type { AppRoute } from "@/routes";

function DashboardPage() {
  const L = useLocal({
    ja: { title: "ダッシュボード", desc: "全体の脅威状況" },
    en: { title: "Dashboard", desc: "Threat overview" },
  });
  return (
    <div>
      <PageHeader title={L.title} description={L.desc} />
      <Card>
        <CardBody className="text-sm text-muted">TOKIWA</CardBody>
      </Card>
    </div>
  );
}

export const route: AppRoute = {
  path: "/",
  component: DashboardPage,
  nav: {
    label: { ja: "ダッシュボード", en: "Dashboard" },
    icon: LayoutDashboard,
    section: "monitor",
    order: 0,
  },
};
