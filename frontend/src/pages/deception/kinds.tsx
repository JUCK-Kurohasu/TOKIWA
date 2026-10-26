/** Per-kind icon and form configuration for Mirage deception assets. */
import { Bird, FolderOpen, KeyRound, type LucideIcon, Route } from "lucide-react";
import type { DeceptionKind } from "@/api/types";
import { deceptionKindLabel, labelOf } from "@/components/common/opsLabels";
import { useLabel } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export const kindIcon: Record<DeceptionKind, LucideIcon> = {
  ai_canary: Bird,
  honeytoken: KeyRound,
  decoy_path: FolderOpen,
  labyrinth: Route,
};

type Req = "required" | "optional" | "hidden";

/** Which DeceptionAssetIn fields each kind uses. The server fills anything left empty (token, template). */
export const kindFields: Record<
  DeceptionKind,
  { path: Req; token: boolean; template: boolean; pathPh: string }
> = {
  ai_canary: { path: "required", token: true, template: true, pathPh: "/admin/" },
  honeytoken: { path: "optional", token: true, template: true, pathPh: "/config/app.env" },
  decoy_path: { path: "required", token: false, template: true, pathPh: "/.env" },
  labyrinth: { path: "required", token: false, template: false, pathPh: "/internal/docs/*" },
};

export function KindTag({ kind, className }: { kind: DeceptionKind | string; className?: string }) {
  const label = useLabel();
  const Icon = kindIcon[kind as DeceptionKind] ?? KeyRound;
  const ai = kind === "ai_canary";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 text-xs font-medium",
        ai ? "text-ai" : "text-fg",
        className,
      )}
    >
      <Icon className={cn("h-3.5 w-3.5", ai ? "text-ai" : "text-accent")} aria-hidden />
      {label(labelOf(deceptionKindLabel, kind))}
    </span>
  );
}
