/** One-time secret display (e.g. a freshly created API token) with copy-to-clipboard. */
import { Check, Copy, KeyRound } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for non-secure contexts (http://lab-host): temporary textarea + execCommand.
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}

export function CopyButton({ text, className, label }: { text: string; className?: string; label?: string }) {
  const L = useLocal({
    ja: { copy: "コピー", copied: "コピー済み" },
    en: { copy: "Copy", copied: "Copied" },
  });
  const [done, setDone] = useState(false);
  return (
    <Button
      size="sm"
      variant="outline"
      className={className}
      onClick={async () => {
        if (await copyText(text)) {
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        }
      }}
      aria-label={label ?? L.copy}
    >
      {done ? <Check className="h-3.5 w-3.5 text-accent" /> : <Copy className="h-3.5 w-3.5" />}
      {done ? L.copied : (label ?? L.copy)}
    </Button>
  );
}

export function SecretReveal({ secret, className }: { secret: string; className?: string }) {
  const L = useLocal({
    ja: { warn: "この値は今回だけ表示されます。安全な場所に保存してください。再表示はできません。" },
    en: { warn: "This value is shown only once. Store it somewhere safe — it cannot be displayed again." },
  });
  return (
    <div className={cn("space-y-2", className)}>
      <div className="flex items-start gap-2 rounded-md border border-sev-medium/30 bg-sev-medium/10 p-2.5 text-xs text-sev-medium">
        <KeyRound className="mt-0.5 h-4 w-4 shrink-0" />
        <span>{L.warn}</span>
      </div>
      <div className="flex items-center gap-2">
        <code className="min-w-0 flex-1 select-all break-all rounded-md border border-line bg-bg px-3 py-2 font-mono text-xs">
          {secret}
        </code>
        <CopyButton text={secret} />
      </div>
    </div>
  );
}
