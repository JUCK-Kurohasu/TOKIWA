/**
 * A date/time in the display zone with its zone name, and the ISO-8601 UTC value in the tooltip (#165).
 * Re-renders when the display zone changes (it subscribes through useLang).
 */
import { dateTimeTitle, formatDateTime } from "@/lib/format";
import { useLang } from "@/lib/i18n";

export function Time({ iso, className }: { iso: string | null | undefined; className?: string }) {
  useLang(); // subscribe to language + display time zone
  if (!iso) return <span className={className}>-</span>;
  return (
    <time dateTime={iso} title={dateTimeTitle(iso)} className={className}>
      {formatDateTime(iso)}
    </time>
  );
}
