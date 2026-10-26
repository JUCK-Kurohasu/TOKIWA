/** Role checks mirroring the backend (viewer < analyst < admin). UI hints only; the API enforces. */
import { useAuth } from "@/stores/auth";

const RANK = { viewer: 0, analyst: 1, admin: 2 } as const;

export type MinRole = keyof typeof RANK;

export function useHasRole(min: MinRole): boolean {
  const { user } = useAuth();
  if (!user) return false;
  return (RANK[user.role] ?? 0) >= RANK[min];
}

export function useCurrentUserId(): string | null {
  return useAuth().user?.id ?? null;
}
