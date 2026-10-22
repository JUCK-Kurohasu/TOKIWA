import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { createBrowserRouter, Navigate, RouterProvider, useLocation } from "react-router";
import { api } from "@/api/client";
import { AppShell } from "@/components/layout/AppShell";
import { Spinner } from "@/components/ui";
import { appRoutes } from "@/routes";
import { useAuth } from "@/stores/auth";

function RequireAuth({ children }: { children: ReactNode }) {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  const status = useQuery({
    queryKey: ["auth", "status"],
    queryFn: () => api.get<{ setup_required: boolean }>("/auth/status"),
    staleTime: 60_000,
  });
  if (status.isLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Spinner />
      </div>
    );
  }
  if (status.data?.setup_required) return <Navigate to="/setup" replace />;
  if (!isAuthenticated) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <AppShell>{children}</AppShell>;
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
