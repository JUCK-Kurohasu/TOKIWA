import { getLang } from "./i18n";
import { getDisplayTz, intlTimeZone } from "./timezone";

export function uiLocale(): string {
  return getLang() === "ja" ? "ja-JP" : "en-US";
}

/**
 * Date + time in the display zone (lib/timezone.ts) with the zone name, e.g. "2026/11/11 9:43:09 JST" /
 * "11/11/2026, 00:43:09 UTC". `hourCycle: "h23"` (not `hour12: false`, which can print "24:05").
 */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString(uiLocale(), {
    hourCycle: "h23",
    timeZone: intlTimeZone(getDisplayTz()),
    timeZoneName: "short",
  });
}

/** ISO-8601 in UTC ("2026-11-11T00:43:09.000Z"); the unambiguous value for reports and log correlation. */
export function isoUtc(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toISOString();
}

/** Tooltip text: the formatted time plus ISO UTC (undefined when there is no time, so no empty tooltip). */
export function dateTimeTitle(iso: string | null | undefined): string | undefined {
  if (!iso) return undefined;
  return `${formatDateTime(iso)}\n${isoUtc(iso)}`;
}

export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "-";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  const ja = getLang() === "ja";
  if (diff < 60) return ja ? `${Math.max(0, Math.floor(diff))}秒前` : `${Math.floor(diff)}s ago`;
  if (diff < 3600) return ja ? `${Math.floor(diff / 60)}分前` : `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return ja ? `${Math.floor(diff / 3600)}時間前` : `${Math.floor(diff / 3600)}h ago`;
  return ja ? `${Math.floor(diff / 86400)}日前` : `${Math.floor(diff / 86400)}d ago`;
}

export function formatUsd(v: number | null | undefined): string {
  if (v == null) return "-";
  return `$${v < 1 ? v.toFixed(4) : v.toFixed(2)}`;
}

export function formatNumber(v: number | null | undefined): string {
  if (v == null) return "-";
  return new Intl.NumberFormat().format(v);
}

export function pct(v: number | null | undefined, digits = 0): string {
  if (v == null) return "-";
  return `${(v * 100).toFixed(digits)}%`;
}
