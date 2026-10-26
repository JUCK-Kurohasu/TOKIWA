/**
 * Deception (Mirage) page. OWNER: frontend-ops.
 *   /deception?tab=assets|trips   assets, create / preview, trip history, AI-canary explanation
 */
import { Bird } from "lucide-react";
import type { AppRoute } from "@/routes";
import { DeceptionPage } from "./DeceptionPage";

export const route: AppRoute = {
  path: "/deception",
  component: DeceptionPage,
  nav: { label: { ja: "デセプション", en: "Deception" }, icon: Bird, section: "respond", order: 65 },
};
