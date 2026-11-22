import { useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useEffect, useState } from "react";
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
    setupCode: "セットアップコード",
    setupCodeHint: "サーバーの起動ログ、またはデータディレクトリの setup-code ファイルに書かれています",
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
    setupCode: "Setup code",
    setupCodeHint:
      "Printed in the server log at startup and stored in the setup-code file in the data directory",
  },
};

/** The setup URL printed by the server carries the code in the fragment (never sent to the server / logs). */
function codeFromHash(hash: string): string {
  return new URLSearchParams(hash.replace(/^#/, "")).get("code") ?? "";
}

function CredentialsForm({ mode, needsCode = false }: { mode: "login" | "setup"; needsCode?: boolean }) {
  const L = useLocal(strings);
  const navigate = useNavigate();
  const location = useLocation();
  const qc = useQueryClient();
  const [username, setUsername] = useState(mode === "setup" ? "admin" : "");
  const [password, setPassword] = useState("");
  const [setupCode, setSetupCode] = useState(() => (mode === "setup" ? codeFromHash(location.hash) : ""));
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  // Drop #code=... from the address bar (history) once it has been read.
  useEffect(() => {
    if (mode === "setup" && location.hash) {
      navigate(
        { pathname: location.pathname, search: location.search },
        { replace: true, state: location.state },
      );
    }
  }, [mode, location.hash, location.pathname, location.search, location.state, navigate]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api.post<TokenResponse>(
        mode === "login" ? "/auth/login" : "/auth/setup",
        mode === "setup"
          ? { username, password, setup_code: setupCode || undefined }
          : { username, password },
      );
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
      {mode === "setup" && needsCode ? (
        <div>
          <Label htmlFor="setup-code">{L.setupCode}</Label>
          <Input
            id="setup-code"
            value={setupCode}
            onChange={(e) => setSetupCode(e.target.value)}
            autoComplete="one-time-code"
            spellCheck={false}
            placeholder="XXXX-XXXX-XXXX-XXXX"
          />
          <p className="mt-1 text-xs text-muted">{L.setupCodeHint}</p>
        </div>
      ) : null}
      {error ? <ErrorState error={error} /> : null}
      <Button
        type="submit"
        className="w-full"
        disabled={busy || !username || !password || (mode === "setup" && needsCode && !setupCode)}
      >
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
  const status = useAuthStatus();
  const { pending, to } = useAuthPageRedirect("setup");
  if (pending) return <PendingFrame />;
  if (to) return <Navigate to={to} replace />;
  return (
    <AuthFrame title={L.setup} subtitle={L.setupHint}>
      <CredentialsForm mode="setup" needsCode={status.data?.setup_code_required ?? true} />
    </AuthFrame>
  );
}

export const routes: AppRoute[] = [
  { path: "/login", component: LoginPage, public: true },
  { path: "/setup", component: SetupPage, public: true },
];
