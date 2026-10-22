/** Auth state (JWT in localStorage). Tiny external store usable from React via useAuth(). */
import { useSyncExternalStore } from "react";

export type Role = "admin" | "analyst" | "viewer";
export type AuthUser = {
  id: string;
  username: string;
  role: Role;
  created_at: string;
  last_login?: string | null;
};

type State = { token: string | null; user: AuthUser | null };

const KEY = "tokiwa.auth";

function load(): State {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) return JSON.parse(raw) as State;
  } catch {
    /* ignore */
  }
  return { token: null, user: null };
}

let state: State = load();
const listeners = new Set<() => void>();

function emit() {
  try {
    localStorage.setItem(KEY, JSON.stringify(state));
  } catch {
    /* ignore */
  }
  for (const l of listeners) l();
}

export const authStore = {
  getToken: () => state.token,
  getUser: () => state.user,
  login(token: string, user: AuthUser) {
    state = { token, user };
    emit();
  },
  logout() {
    state = { token: null, user: null };
    emit();
  },
  subscribe(l: () => void) {
    listeners.add(l);
    return () => listeners.delete(l);
  },
  snapshot: () => state,
};

export function useAuth(): State & { isAuthenticated: boolean } {
  const s = useSyncExternalStore(authStore.subscribe, authStore.snapshot);
  return { ...s, isAuthenticated: !!s.token };
}
