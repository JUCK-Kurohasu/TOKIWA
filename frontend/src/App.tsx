import type { ReactNode } from "react";
import { createBrowserRouter, Navigate, RouterProvider, useLocation } from "react-router";
import { AppShell } from "@/components/layout/AppShell";
import { Button, ErrorState, Spinner } from "@/components/ui";
import { decideProtected, useAuthStatus } from "@/lib/authGate";
import { useLocal } from "@/lib/i18n";
import { appRoutes } from "@/routes";
import { useAuth } from "@/stores/auth";

function ServerUnreachable({
  error,
  onRetry,
  retrying,
}: {
  error: unknown;
  onRetry: () => void;
  retrying: boolean;
}) {
  const L = useLocal({
    ja: {
      title: "サーバーに接続できません",
      hint: "TOKIWA サーバー（API）から応答がありません。サーバーが起動しているか（cd backend && uv run tokiwa serve）、接続先の設定を確認してください。",
      retry: "再試行",
    },
    en: {
      title: "Cannot reach the server",
      hint: "The TOKIWA server (API) is not responding. Check that it is running (cd backend && uv run tokiwa serve) and that the UI points at it.",
      retry: "Retry",
    },
  });
  return (
    <div className="flex min-h-full items-center justify-center bg-bg p-6">
      <div className="w-full max-w-sm space-y-4 rounded-xl border border-line bg-surface p-7 shadow-xl">
        <div className="text-sm font-medium">{L.title}</div>
        <p className="text-xs text-muted">{L.hint}</p>
        <ErrorState error={error} />
        <Button className="w-full" onClick={onRetry} disabled={retrying}>
          {retrying && <Spinner className="h-3.5 w-3.5" />}
          {L.retry}
        </Button>
      </div>
    </div>
  );
}

function RequireAuth({ children }: { children: ReactNode }) {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  const status = useAuthStatus();
  switch (decideProtected(status, isAuthenticated)) {
    case "loading":
      return (
        <div className="flex h-full items-center justify-center">
          <Spinner />
        </div>
      );
    case "unreachable":
      return (
        <ServerUnreachable
          error={status.error}
          onRetry={() => void status.refetch()}
          retrying={status.isFetching}
        />
      );
    case "setup":
      return <Navigate to="/setup" replace />;
    case "login":
      return <Navigate to="/login" replace state={{ from: location.pathname }} />;
    case "allow":
      return <AppShell>{children}</AppShell>;
  }
}

function NotFound() {
  return <div className="p-10 text-center text-muted">404</div>;
}

const router = createBrowserRouter([
  ...appRoutes.map((r) => {
    const C = r.component;
    return {
      path: r.path,
      element: r.public ? (
        <C />
      ) : (
        <RequireAuth>
          <C />
        </RequireAuth>
      ),
    };
  }),
  { path: "*", element: <NotFound /> },
]);

export function App() {
  return <RouterProvider router={router} />;
}
