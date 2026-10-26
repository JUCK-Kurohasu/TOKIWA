import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";

export type AuthStatus = { setup_required: boolean; version?: string };

/** GET /auth/status, shared by the protected-route guard and the login/setup pages (same cache key). */
export function useAuthStatus() {
  return useQuery({
    queryKey: ["auth", "status"],
    queryFn: () => api.get<AuthStatus>("/auth/status"),
    staleTime: 60_000,
  });
}

export type GateDecision = "loading" | "unreachable" | "setup" | "login" | "allow";

/**
 * What a protected route should show. Kept pure so the branches are testable: an unreachable API used to fall
 * through to the login screen, which looks exactly like "an admin already exists" on a fresh install.
 */
export function decideProtected(
  status: { isLoading: boolean; isError: boolean; data?: AuthStatus },
  isAuthenticated: boolean,
): GateDecision {
  if (status.isLoading) return "loading";
  if (status.isError || !status.data) return "unreachable";
  if (status.data.setup_required) return "setup";
  if (!isAuthenticated) return "login";
  return "allow";
}

/**
 * Where the public login/setup pages should send the user, or null to stay. Opening /login directly on a fresh
 * install must still lead to setup, and /setup after setup would only answer 409. While the status is unknown
 * (loading or error) the page stays put and the form reports any error itself.
 */
export function publicRedirect(
  mode: "login" | "setup",
  status: AuthStatus | undefined,
  isAuthenticated: boolean,
): "/setup" | "/login" | "/" | null {
  if (!status) return null;
  if (mode === "login") return status.setup_required ? "/setup" : null;
  if (status.setup_required) return null;
  return isAuthenticated ? "/" : "/login";
}
