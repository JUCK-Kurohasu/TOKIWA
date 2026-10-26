/**
 * Role checks for UI affordances. The backend enforces permissions; the UI only hides/disables controls so a
 * viewer is not offered actions that would fail with 403.
 */
import type { ReactNode } from "react";
import { useAuth } from "@/stores/auth";

export function useCan(): { analyst: boolean; admin: boolean } {
  const { user } = useAuth();
  const role = user?.role;
  return { analyst: role === "admin" || role === "analyst", admin: role === "admin" };
}

/** Renders children only for the given minimum role. */
export function RoleGate({
  role,
  children,
  fallback = null,
}: {
  role: "analyst" | "admin";
  children: ReactNode;
  fallback?: ReactNode;
}) {
  const can = useCan();
  return <>{can[role] ? children : fallback}</>;
}
