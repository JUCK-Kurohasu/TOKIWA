/**
 * Display components for attacker-controlled telemetry strings (audit #150). See `invisible.ts`.
 *
 * - <SafeText>: renders a string with invisible / bidi control characters replaced by a visible `⟨U+202E⟩`
 *   marker in warning colour, inside `unicode-bidi: plaintext` so right-to-left letters cannot reorder the
 *   surrounding UI either. Use it for paths, queries, user agents, header names/values, bodies, prompts.
 * - <InvisibleCharsBadge>: "contains invisible / bidi control characters" badge for a row or an event.
 *
 * Display only: never feed the escaped text back into filters or searches.
 */
import { EyeOff } from "lucide-react";
import { Fragment } from "react";
import { Badge } from "@/components/ui";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { charTitle, codePointLabel, type InvisibleScan, scanInvisible, splitInvisible } from "./invisible";

/** `unicode-bidi: plaintext` as a class (no inline style attributes: CSP). */
export const BIDI_PLAINTEXT = "[unicode-bidi:plaintext]";

export function SafeText({
  text,
  multiline = false,
  className,
}: {
  text: string | null | undefined;
  /** Keep TAB / LF / CR as-is (bodies, prompts, messages). */
  multiline?: boolean;
  className?: string;
}) {
  if (text == null || text === "") return null;
  const parts = splitInvisible(text, multiline);
  return (
    <span className={cn(BIDI_PLAINTEXT, className)}>
      {parts.map((p, i) =>
        typeof p === "string" ? (
          <Fragment key={i}>{p}</Fragment>
        ) : (
          <span
            key={i}
            title={charTitle(p.cp)}
            className="mx-px rounded-sm bg-sev-high/15 px-0.5 font-mono text-[0.85em] text-sev-high"
          >
            ⟨{codePointLabel(p.cp)}⟩
          </span>
        ),
      )}
    </span>
  );
}

export function InvisibleCharsBadge({
  value,
  scan,
  compact = false,
  className,
}: {
  /** Anything to scan (event, string, object). Ignored when `scan` is given. */
  value?: unknown;
  scan?: InvisibleScan | null;
  /** Short label for dense table rows. */
  compact?: boolean;
  className?: string;
}) {
  const L = useLocal({
    ja: {
      short: "不可視文字",
      label: "不可視/双方向制御文字を含む",
      bidi: "表示順を入れ替える双方向制御文字を含みます。見た目と実際の文字列が異なる可能性があります。",
      hidden: "表示されない文字を含みます。",
    },
    en: {
      short: "Invisible chars",
      label: "Contains invisible / bidi control characters",
      bidi: "Contains bidirectional control characters that reorder the display; what you see may differ from the actual string.",
      hidden: "Contains characters that are not displayed.",
    },
  });
  const found = scan === undefined ? scanInvisible(value) : scan;
  if (!found) return null;
  const title = `${compact ? `${L.label}\n` : ""}${found.bidi ? L.bidi : L.hidden}\n${found.codePoints.map(charTitle).join("\n")}`;
  return (
    <Badge tone="warn" title={title} className={cn("shrink-0", className)}>
      <EyeOff className="h-3 w-3" aria-hidden />
      {compact ? L.short : L.label}
    </Badge>
  );
}
