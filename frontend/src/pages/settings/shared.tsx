/** Small helpers shared by the settings tabs. */
import type { Role } from "@/api/types-core";
import { Badge, ErrorState } from "@/components/ui";
import { errorMessage } from "@/hooks/useApi";

export function MutationError({ error }: { error: unknown }) {
  if (!error) return null;
  return <ErrorState error={new Error(errorMessage(error))} />;
}

export function RoleBadge({ role }: { role: Role }) {
  return (
    <Badge tone={role === "admin" ? "accent" : role === "analyst" ? "warn" : "neutral"} className="font-mono">
      {role}
    </Badge>
  );
}

export type Flash = (msg: string, tone?: "success" | "danger") => void;
