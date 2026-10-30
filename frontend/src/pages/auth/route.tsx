import { useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router";
import { ApiError, api } from "@/api/client";
import { BrandMark } from "@/components/common/BrandMark";
import { Button, ErrorState, Input, Label, Spinner } from "@/components/ui";
import { publicRedirect, useAuthStatus } from "@/lib/authGate";
import { useLocal } from "@/lib/i18n";
import type { AppRoute } from "@/routes";
import { type AuthUser, authStore, useAuth } from "@/stores/auth";

type TokenResponse = { access_token: string; user: AuthUser };

function AuthFrame({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex min-h-full items-center justify-center bg-bg p-6">
      <div className="w-full max-w-sm rounded-xl border border-line bg-surface p-7 shadow-xl">
        <div className="mb-6 flex flex-col items-center gap-2 text-center">
          <BrandMark className="h-9 w-9 text-accent" />
          <div className="text-lg font-semibold tracking-[0.3em]">TOKIWA</div>
          <div className="text-sm font-medium">{title}</div>
          <div className="text-xs text-muted">{subtitle}</div>
        </div>
        {children}
      </div>
    </div>
  );
}

const strings = {
  ja: {
    login: "ログイン",
    setup: "初期セットアップ",
    setupHint: "最初の管理者アカウントを作成します",
    loginHint: "生成AIによるサイバー攻撃を検知・防御する LLM駆動 SIEM/XDR",
    username: "ユーザー名",
    password: "パスワード",
    passwordHint: "10文字以上",
    createAdmin: "管理者を作成",
  },
  en: {
    login: "Sign in",
    setup: "Initial setup",
    setupHint: "Create the first administrator account",
    loginHint: "LLM-driven SIEM/XDR against generative-AI-driven attacks",
    username: "Username",
    password: "Password",
    passwordHint: "At least 10 characters",
    createAdmin: "Create admin",
  },
};

function CredentialsForm({ mode }: { mode: "login" | "setup" }) {
  const L = useLocal(strings);
  const navigate = useNavigate();
  const location = useLocation();
  const qc = useQueryClient();
  const [username, setUsername] = useState(mode === "setup" ? "admin" : "");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api.post<TokenResponse>(mode === "login" ? "/auth/login" : "/auth/setup", {
        username,
        password,
      });
      authStore.login(res.access_token, res.user);
      await qc.invalidateQueries({ queryKey: ["auth", "status"] });
      const from = (location.state as { from?: string } | null)?.from;
      navigate(from && from !== "/login" ? from : "/", { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err : new Error(String(err)));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <div>
        <Label htmlFor="username">{L.username}</Label>
        <Input
          id="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="username"
        />
      </div>
      <div>
        <Label htmlFor="password">{L.password}</Label>
        <Input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete={mode === "login" ? "current-password" : "new-password"}
          placeholder={mode === "setup" ? L.passwordHint : undefined}
        />
      </div>
      {error ? <ErrorState error={error} /> : null}
      <Button type="submit" className="w-full" disabled={busy || !username || !password}>
        {mode === "login" ? L.login : L.createAdmin}
      </Button>
    </form>
  );
}

/** Sends /login to /setup on a fresh install and /setup away once an admin exists (see lib/authGate). */
function useAuthPageRedirect(mode: "login" | "setup"): { pending: boolean; to: string | null } {
  const status = useAuthStatus();
  const { isAuthenticated } = useAuth();
  return { pending: status.isLoading, to: publicRedirect(mode, status.data, isAuthenticated) };
}

function PendingFrame() {
  return (
    <div className="flex min-h-full items-center justify-center bg-bg p-6">
      <Spinner />
    </div>
  );
}

function LoginPage() {
  const L = useLocal(strings);
  const { pending, to } = useAuthPageRedirect("login");
  if (pending) return <PendingFrame />;
  if (to) return <Navigate to={to} replace />;
  return (
    <AuthFrame title={L.login} subtitle={L.loginHint}>
      <CredentialsForm mode="login" />
    </AuthFrame>
  );
}

function SetupPage() {
  const L = useLocal(strings);
  const { pending, to } = useAuthPageRedirect("setup");
  if (pending) return <PendingFrame />;
  if (to) return <Navigate to={to} replace />;
  return (
    <AuthFrame title={L.setup} subtitle={L.setupHint}>
      <CredentialsForm mode="setup" />
    </AuthFrame>
  );
}

export const routes: AppRoute[] = [
  { path: "/login", component: LoginPage, public: true },
  { path: "/setup", component: SetupPage, public: true },
];
