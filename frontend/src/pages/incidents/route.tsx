/**
 * Incident pages. OWNER: frontend-ops.
 *   /incidents       list (AI-agent actors emphasised)
 *   /incidents/:id   detail with kill chain, attribution, linked alerts, actions and triage
 */
import { Flame } from "lucide-react";
import type { AppRoute } from "@/routes";
import { IncidentDetailPage } from "./IncidentDetail";
import { IncidentsListPage } from "./IncidentsList";

export const routes: AppRoute[] = [
  {
    path: "/incidents",
    component: IncidentsListPage,
    nav: { label: { ja: "インシデント", en: "Incidents" }, icon: Flame, section: "investigate", order: 30 },
  },
  { path: "/incidents/:id", component: IncidentDetailPage },
];
