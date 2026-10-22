/**
 * Page auto-discovery. Each page lives in src/pages/<name>/route.tsx and exports `route: AppRoute`.
 * Adding a page never requires editing a shared file (parallel-friendly).
 */
import type { LucideIcon } from "lucide-react";
import type { ComponentType } from "react";

export type NavSection = "monitor" | "investigate" | "intel" | "respond" | "system";

export interface AppRoute {
  /** react-router path, e.g. "/alerts" or "/alerts/:id" */
  path: string;
  component: ComponentType;
  /** Public routes (login/setup) render without the app shell and without auth. */
  public?: boolean;
  /** Present => shown in the sidebar. */
  nav?: {
    label: { ja: string; en: string };
    icon: LucideIcon;
    section: NavSection;
    order: number;
  };
  /** Minimum role. Default: any authenticated user. */
  role?: "admin" | "analyst";
}

const modules = import.meta.glob<{ route?: AppRoute; routes?: AppRoute[] }>("./pages/*/route.tsx", {
  eager: true,
});

export const appRoutes: AppRoute[] = Object.values(modules)
  .flatMap((m) => (m.routes ? m.routes : m.route ? [m.route] : []))
  .sort((a, b) => (a.nav?.order ?? 999) - (b.nav?.order ?? 999));

export const SECTION_ORDER: NavSection[] = ["monitor", "investigate", "intel", "respond", "system"];
