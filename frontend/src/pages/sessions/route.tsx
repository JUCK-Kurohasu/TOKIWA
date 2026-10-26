/**
 * Actor sessions: `/sessions` (list by AI score) and `/sessions/:id` (thinking-rhythm detail).
 * Data: GET /sessions, GET /sessions/{id}.
 */
import { Bot } from "lucide-react";
import type { AppRoute } from "@/routes";
import { SessionDetailPage } from "./SessionDetail";
import { SessionsListPage } from "./SessionsList";

export const routes: AppRoute[] = [
  {
    path: "/sessions",
    component: SessionsListPage,
    nav: {
      label: { ja: "AI セッション", en: "AI sessions" },
      icon: Bot,
      section: "monitor",
      order: 30,
    },
  },
  { path: "/sessions/:id", component: SessionDetailPage },
];
