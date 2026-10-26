/**
 * Settings (`/settings`, admin): users / API tokens / notification channels / system (jobs, audit).
 * The tab is kept in the URL (`?tab=`). Non-admins see an explanation instead of failing API calls.
 */
import { Lock, Settings } from "lucide-react";
import { PageHeader } from "@/components/common";
import { useFlash } from "@/components/common/Flash";
import { EmptyState, Tabs } from "@/components/ui";
import { useHasRole } from "@/hooks/useRole";
import { useSearchState } from "@/hooks/useSearchState";
import { useLocal } from "@/lib/i18n";
import type { AppRoute } from "@/routes";
import { NotifyTab } from "./NotifyTab";
import { SystemTab } from "./SystemTab";
import { TokensTab } from "./TokensTab";
import { UsersTab } from "./UsersTab";

const TABS = ["users", "tokens", "notify", "system"] as const;
type Tab = (typeof TABS)[number];

function SettingsPage() {
  const L = useLocal({
    ja: {
      title: "設定",
      desc: "ユーザー・API トークン・通知チャネル・システムの管理（管理者のみ）",
      users: "ユーザー",
      tokens: "API トークン",
      notify: "通知チャネル",
      system: "システム",
      adminOnly: "管理者のみが利用できます",
      adminOnlyHint: "admin ロールのアカウントでログインしてください",
    },
    en: {
      title: "Settings",
      desc: "Users, API tokens, notification channels and system (admins only)",
      users: "Users",
      tokens: "API tokens",
      notify: "Notifications",
      system: "System",
      adminOnly: "Administrators only",
      adminOnlyHint: "Sign in with an account that has the admin role",
    },
  });
  const isAdmin = useHasRole("admin");
  const [f, setF] = useSearchState(["tab"] as const);
  const tab: Tab = (TABS as readonly string[]).includes(f.tab) ? (f.tab as Tab) : "users";
  const { flash, node } = useFlash();

  if (!isAdmin) {
    return (
      <div>
        <PageHeader title={L.title} description={L.desc} />
        <EmptyState
          title={L.adminOnly}
          hint={L.adminOnlyHint}
          icon={<Lock className="h-6 w-6 opacity-60" />}
        />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <PageHeader title={L.title} description={L.desc} />
      <Tabs<Tab>
        tabs={TABS.map((t) => ({ value: t, label: L[t] }))}
        value={tab}
        onChange={(t) => setF({ tab: t === "users" ? null : t }, false)}
      />
      {tab === "users" && <UsersTab flash={flash} />}
      {tab === "tokens" && <TokensTab flash={flash} />}
      {tab === "notify" && <NotifyTab flash={flash} />}
      {tab === "system" && <SystemTab flash={flash} />}
      {node}
    </div>
  );
}

export const route: AppRoute = {
  path: "/settings",
  component: SettingsPage,
  role: "admin",
  nav: {
    label: { ja: "設定", en: "Settings" },
    icon: Settings,
    section: "system",
    order: 90,
  },
};
