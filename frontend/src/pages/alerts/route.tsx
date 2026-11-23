/**
 * Alerts pages. OWNER: frontend-ops.
 *   /alerts              list with filters + bulk status change
 *   /alerts/:id          detail with evidence viewer and LLM triage panel
 *   /alert-suppressions  false-positive suppressions and allowlists (audit #166 / #173)
 */
import { Bell, BellOff } from "lucide-react";
import type { AppRoute } from "@/routes";
import { AlertDetailPage } from "./AlertDetail";
import { AlertSuppressionsPage } from "./AlertSuppressionsPage";
import { AlertsListPage } from "./AlertsList";

export const routes: AppRoute[] = [
  {
    path: "/alerts",
    component: AlertsListPage,
    nav: { label: { ja: "アラート", en: "Alerts" }, icon: Bell, section: "monitor", order: 20 },
  },
  { path: "/alerts/:id", component: AlertDetailPage },
  {
    path: "/alert-suppressions",
    component: AlertSuppressionsPage,
    nav: {
      label: { ja: "抑制・許可リスト", en: "Suppressions" },
      icon: BellOff,
      section: "monitor",
      order: 21,
    },
  },
];
