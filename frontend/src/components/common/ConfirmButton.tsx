/**
 * Two-step inline confirmation for destructive actions ("Delete" -> "Really delete?" [Yes] [No]).
 * Lighter than a modal for row-level actions; reverts automatically after a few seconds.
 */
import { type ReactNode, useEffect, useState } from "react";
import { Button } from "@/components/ui";
import { useLocal } from "@/lib/i18n";

export function ConfirmButton({
  onConfirm,
  children,
  confirmLabel,
  disabled,
  busy,
  title,
  variant = "ghost",
}: {
  onConfirm: () => void;
  children: ReactNode;
  confirmLabel?: ReactNode;
  disabled?: boolean;
  busy?: boolean;
  title?: string;
  variant?: "ghost" | "outline" | "danger";
}) {
  const L = useLocal({
    ja: { sure: "実行しますか？", yes: "はい", no: "いいえ" },
    en: { sure: "Are you sure?", yes: "Yes", no: "No" },
  });
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const t = setTimeout(() => setArmed(false), 5000);
    return () => clearTimeout(t);
  }, [armed]);

  if (!armed) {
    return (
      <Button
        size="sm"
        variant={variant}
        disabled={disabled || busy}
        onClick={() => setArmed(true)}
        title={title}
      >
        {children}
      </Button>
    );
  }
  return (
    <span className="inline-flex items-center gap-1">
      <span className="text-xs text-sev-critical">{confirmLabel ?? L.sure}</span>
      <Button
        size="sm"
        variant="danger"
        disabled={busy}
        onClick={() => {
          setArmed(false);
          onConfirm();
        }}
        autoFocus
      >
        {L.yes}
      </Button>
      <Button size="sm" variant="ghost" onClick={() => setArmed(false)}>
        {L.no}
      </Button>
    </span>
  );
}
