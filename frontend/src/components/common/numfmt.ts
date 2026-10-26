/** Extra number/time formatters for dense SOC tables (complements src/lib/format.ts). */
import { getLang } from "@/lib/i18n";

/** 12 ms / 1.4 s / 2m 05s / 1h 02m */
export function formatMs(ms: number | null | undefined): string {
  if (ms == null || Number.isNaN(ms)) return "-";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s < 10 ? s.toFixed(2) : s.toFixed(1)} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(Math.round(s % 60)).padStart(2, "0")}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${String(m % 60).padStart(2, "0")}m`;
}

/** 950 / 1.2K / 34K / 1.2M */
export function formatCompact(v: number | null | undefined): string {
  if (v == null) return "-";
  return new Intl.NumberFormat(getLang() === "ja" ? "ja-JP" : "en-US", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(v);
}

export function formatBytes(v: number | null | undefined): string {
  if (v == null) return "-";
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  return `${(v / 1024 / 1024).toFixed(1)} MB`;
}

/** HH:MM:SS in the UI language/locale. */
export function formatClock(t: number | string | Date): string {
  const d = t instanceof Date ? t : new Date(t);
  return d.toLocaleTimeString(getLang() === "ja" ? "ja-JP" : "en-US", { hour12: false });
}

/** Axis tick for time-series: "14:00" within a day, "10/21 14:00" otherwise. */
export function formatTick(t: number, spanMs: number): string {
  const d = new Date(t);
  const locale = getLang() === "ja" ? "ja-JP" : "en-US";
  const hm = d.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit", hour12: false });
  if (spanMs <= 26 * 3600 * 1000) return hm;
  return `${d.getMonth() + 1}/${d.getDate()} ${hm}`;
}

/** Parse ISO strings and epoch seconds/ms into epoch ms. */
export function toEpochMs(t: string | number | null | undefined): number | null {
  if (t == null) return null;
  if (typeof t === "number") return t > 1e12 ? t : t * 1000;
  const v = Date.parse(t);
  return Number.isNaN(v) ? null : v;
}

/** HTTP status -> semantic class used for colouring (always shown with the number itself). */
export type StatusClass = "ok" | "redirect" | "client" | "server" | "none";
export function statusClass(status: number | null | undefined): StatusClass {
  if (status == null) return "none";
  if (status >= 500) return "server";
  if (status >= 400) return "client";
  if (status >= 300) return "redirect";
  return "ok";
}
