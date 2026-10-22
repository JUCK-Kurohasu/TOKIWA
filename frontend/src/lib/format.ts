import { getLang } from "./i18n";

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return d.toLocaleString(getLang() === "ja" ? "ja-JP" : "en-US", { hour12: false });
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
