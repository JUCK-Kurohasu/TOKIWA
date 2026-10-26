/**
 * Response page. OWNER: frontend-ops.
 *   /response?tab=pending|active|history   human-approval workflow for reversible actions (FR-12)
 */
import { ShieldCheck } from "lucide-react";
import type { AppRoute } from "@/routes";
import { ResponsePage } from "./ResponsePage";

export const route: AppRoute = {
  path: "/response",
  component: ResponsePage,
  nav: { label: { ja: "対処", en: "Response" }, icon: ShieldCheck, section: "respond", order: 60 },
};
