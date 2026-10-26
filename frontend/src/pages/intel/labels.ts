/** Localized labels shared by the intel tabs. */
import { useCallback } from "react";
import type { SoftwareItem } from "@/api/types";
import type { AdvisoryStatus, MatchStatus } from "@/api/types-intel";
import { useLang } from "@/lib/i18n";

const matchStatus: Record<MatchStatus, { ja: string; en: string }> = {
  open: { ja: "未対応", en: "Open" },
  mitigated: { ja: "緩和済み", en: "Mitigated" },
  accepted: { ja: "リスク受容", en: "Accepted" },
  false_positive: { ja: "誤検知", en: "False positive" },
};

const advisoryStatus: Record<AdvisoryStatus, { ja: string; en: string }> = {
  new: { ja: "新規", en: "New" },
  acknowledged: { ja: "確認済み", en: "Acknowledged" },
  done: { ja: "対応完了", en: "Done" },
  dismissed: { ja: "見送り", en: "Dismissed" },
};

export function useMatchStatusLabel(): (s: string) => string {
  const { lang } = useLang();
  return useCallback((s: string) => matchStatus[s as MatchStatus]?.[lang] ?? s, [lang]);
}

export function useAdvisoryStatusLabel(): (s: string) => string {
  const { lang } = useLang();
  return useCallback((s: string) => advisoryStatus[s as AdvisoryStatus]?.[lang] ?? s, [lang]);
}

export function softwareLabel(
  s: Pick<SoftwareItem, "vendor" | "product" | "version"> | null | undefined,
): string {
  if (!s) return "-";
  return [s.vendor, s.product, s.version].filter(Boolean).join(" ");
}
