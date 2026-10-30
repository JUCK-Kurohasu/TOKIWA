import { useQuery } from "@tanstack/react-query";
import { Languages, LogOut, Moon, Sun } from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";
import { NavLink, useNavigate } from "react-router";
import { api } from "@/api/client";
import { BrandMark } from "@/components/common/BrandMark";
import { useLabel, useLang, useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { appRoutes, SECTION_ORDER } from "@/routes";
import { authStore, useAuth } from "@/stores/auth";

function useTheme(): [boolean, () => void] {
  const [dark, setDark] = useState(() => {
    try {
      return localStorage.getItem("tokiwa.theme") !== "light";
    } catch {
      return true;
    }
  });
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    try {
      localStorage.setItem("tokiwa.theme", dark ? "dark" : "light");
    } catch {
      /* ignore */
    }
  }, [dark]);
  return [dark, () => setDark((d) => !d)];
}

function Sidebar() {
  const label = useLabel();
  const t = useT();
  const { user } = useAuth();
  const navRoutes = appRoutes.filter(
    (r) => r.nav && (!r.role || user?.role === "admin" || (r.role === "analyst" && user?.role === "analyst")),
  );
  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-line bg-surface">
      <div className="flex h-14 items-center gap-2 border-b border-line px-4">
        <BrandMark className="h-5 w-5 text-accent" />
        <span className="font-semibold tracking-[0.25em]">TOKIWA</span>
      </div>
      <nav className="flex-1 overflow-y-auto px-2 py-3">
        {SECTION_ORDER.map((section) => {
          const items = navRoutes.filter((r) => r.nav?.section === section);
          if (!items.length) return null;
          return (
            <div key={section} className="mb-4">
              <div className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-muted">
                {t(`nav.section.${section}`)}
              </div>
              {items.map((r) => {
                const Icon = r.nav?.icon;
                return (
                  <NavLink
                    key={r.path}
                    to={r.path}
                    end={r.path === "/"}
                    className={({ isActive }) =>
                      cn(
                        "flex items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors",
                        isActive
                          ? "bg-accent-soft text-accent"
                          : "text-muted hover:bg-surface-2 hover:text-fg",
                      )
                    }
                  >
                    {Icon && <Icon className="h-4 w-4" />}
                    {r.nav && label(r.nav.label)}
                  </NavLink>
                );
              })}
            </div>
          );
        })}
      </nav>
      <SystemStatus />
    </aside>
  );
}

function SystemStatus() {
  const { data } = useQuery({
    queryKey: ["system", "health"],
    queryFn: () => api.get<{ status: string; version: string }>("/health"),
    refetchInterval: 30_000,
  });
  return (
    <div className="border-t border-line px-4 py-2 text-[11px] text-muted">
      <span
        className={cn("mr-1.5 inline-block h-1.5 w-1.5 rounded-full", data ? "bg-accent" : "bg-sev-critical")}
      />
      {data ? `v${data.version}` : "offline"}
    </div>
  );
}

function Topbar() {
  const { user } = useAuth();
  const { lang, setLang } = useLang();
  const t = useT();
  const [dark, toggleTheme] = useTheme();
  const navigate = useNavigate();
  return (
    <header className="flex h-14 items-center justify-end gap-2 border-b border-line bg-surface px-4">
      <button
        type="button"
        className="rounded-md p-2 text-muted hover:bg-surface-2 hover:text-fg"
        onClick={() => setLang(lang === "ja" ? "en" : "ja")}
        title="Language"
      >
        <Languages className="h-4 w-4" />
      </button>
      <button
        type="button"
        className="rounded-md p-2 text-muted hover:bg-surface-2 hover:text-fg"
        onClick={toggleTheme}
        title="Theme"
      >
        {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
      </button>
      <span className="ml-2 text-sm text-muted">
        {user?.username} <span className="text-xs">({user?.role})</span>
      </span>
      <button
        type="button"
        className="rounded-md p-2 text-muted hover:bg-surface-2 hover:text-fg"
        onClick={() => {
          authStore.logout();
          navigate("/login");
        }}
        title={t("common.logout")}
      >
        <LogOut className="h-4 w-4" />
      </button>
    </header>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-full">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main className="flex-1 overflow-y-auto p-6">{children}</main>
      </div>
    </div>
  );
}
