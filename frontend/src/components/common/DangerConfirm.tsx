/** Confirmation dialog for destructive or high-impact actions (delete, approve-into-production, ...). */
import type { ReactNode } from "react";
import { Button, Dialog, Spinner } from "@/components/ui";
import { useT } from "@/lib/i18n";
import { ApiErrorState } from "./QueryView";

export function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel,
  tone = "danger",
  busy,
  error,
  onConfirm,
  onClose,
}: {
  open: boolean;
  title: ReactNode;
  body: ReactNode;
  confirmLabel?: ReactNode;
  tone?: "danger" | "primary";
  busy?: boolean;
  error?: unknown;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const t = useT();
  return (
    <Dialog
      open={open}
      onClose={busy ? () => {} : onClose}
      title={title}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {t("common.cancel")}
          </Button>
          <Button variant={tone} onClick={onConfirm} disabled={busy}>
            {busy && <Spinner className="h-3.5 w-3.5" />}
            {confirmLabel ?? t("common.confirm")}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm">
        <div>{body}</div>
        {error ? <ApiErrorState error={error} /> : null}
      </div>
    </Dialog>
  );
}
