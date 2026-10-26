/**
 * Monospace Sigma YAML editor with a line-number gutter, plus a validation result panel.
 * Tab is NOT captured (keyboard users must be able to leave the field); indent with spaces.
 */
import { CheckCircle2, XCircle } from "lucide-react";
import { useRef } from "react";
import type { RuleValidation } from "@/api/types-intel";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export function SigmaEditor({
  value,
  onChange,
  readOnly,
  id,
  label,
  rows = 22,
}: {
  value: string;
  onChange?: (v: string) => void;
  readOnly?: boolean;
  id?: string;
  label: string;
  rows?: number;
}) {
  const gutter = useRef<HTMLDivElement>(null);
  const lines = Math.max(1, value.split("\n").length);
  return (
    <div className="flex overflow-hidden rounded-md border border-line bg-bg focus-within:border-accent">
      <div
        ref={gutter}
        aria-hidden
        className="select-none overflow-hidden border-r border-line bg-surface-2/50 px-2 py-2 text-right font-mono text-[11px] leading-5 text-muted"
        style={{ height: `${rows * 1.25 + 1}rem` }}
      >
        {Array.from({ length: lines }, (_, i) => (
          <div key={i}>{i + 1}</div>
        ))}
      </div>
      <textarea
        id={id}
        aria-label={label}
        value={value}
        readOnly={readOnly}
        onChange={(e) => onChange?.(e.target.value)}
        onScroll={(e) => {
          if (gutter.current) gutter.current.scrollTop = e.currentTarget.scrollTop;
        }}
        spellCheck={false}
        autoCapitalize="off"
        autoComplete="off"
        autoCorrect="off"
        wrap="off"
        className={cn(
          "min-w-0 flex-1 resize-none bg-transparent px-3 py-2 font-mono text-[12px] leading-5 outline-none",
          readOnly && "text-muted",
        )}
        style={{ height: `${rows * 1.25 + 1}rem` }}
      />
    </div>
  );
}

export function ValidationResult({ result }: { result: RuleValidation }) {
  const L = useLocal({
    ja: { ok: "検証に成功しました", ng: "検証エラー" },
    en: { ok: "Validation passed", ng: "Validation errors" },
  });
  if (result.valid) {
    return (
      <div
        role="status"
        className="flex items-center gap-2 rounded-md border border-accent/30 bg-accent-soft px-3 py-2 text-sm text-accent"
      >
        <CheckCircle2 className="h-4 w-4 shrink-0" aria-hidden />
        <span>
          {L.ok}
          {result.title ? <span className="text-fg">: {result.title}</span> : null}
        </span>
      </div>
    );
  }
  return (
    <div
      role="alert"
      className="rounded-md border border-sev-critical/30 bg-sev-critical/10 px-3 py-2 text-sm text-sev-critical"
    >
      <div className="flex items-center gap-2 font-medium">
        <XCircle className="h-4 w-4 shrink-0" aria-hidden />
        {L.ng}
      </div>
      <ul className="mt-1 list-disc space-y-0.5 pl-6 font-mono text-xs">
        {(result.errors ?? []).map((e, i) => (
          <li key={i}>{e}</li>
        ))}
      </ul>
    </div>
  );
}
