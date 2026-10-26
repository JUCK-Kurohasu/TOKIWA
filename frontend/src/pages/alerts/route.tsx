/**
 * Alerts pages. OWNER: frontend-ops.
 *   /alerts       list with filters + bulk status change
 *   /alerts/:id   detail with evidence viewer and LLM triage panel
 */
import { Bell } from "lucide-react";
import type { AppRoute } from "@/routes";
import { AlertDetailPage } from "./AlertDetail";
import { AlertsListPage } from "./AlertsList";

export const routes: AppRoute[] = [
  {
    path: "/alerts",
    component: AlertsListPage,
    nav: { label: { ja: "アラート", en: "Alerts" }, icon: Bell, section: "monitor", order: 20 },
  },
  { path: "/alerts/:id", component: AlertDetailPage },
];
