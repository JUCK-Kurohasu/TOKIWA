import { useCallback } from "react";
import type { AssetKind } from "@/api/types";
import { useLang } from "@/lib/i18n";

export const ASSET_KINDS: AssetKind[] = ["host", "service", "web_app", "llm_app", "network_device", "other"];

const kindLabels: Record<AssetKind, { ja: string; en: string }> = {
  host: { ja: "ホスト", en: "Host" },
  service: { ja: "サービス", en: "Service" },
  web_app: { ja: "Web アプリ", en: "Web app" },
  llm_app: { ja: "LLM アプリ", en: "LLM app" },
  network_device: { ja: "ネットワーク機器", en: "Network device" },
  other: { ja: "その他", en: "Other" },
};

export function useKindLabel(): (k: string) => string {
  const { lang } = useLang();
  return useCallback((k: string) => kindLabels[k as AssetKind]?.[lang] ?? k, [lang]);
}

/** OSV ecosystem names (case-sensitive in OSV queries). */
export const ECOSYSTEMS = [
  "PyPI",
  "npm",
  "Go",
  "Maven",
  "NuGet",
  "crates.io",
  "RubyGems",
  "Packagist",
  "Pub",
  "Hex",
  "Debian",
  "Ubuntu",
  "Alpine",
  "Red Hat",
  "Rocky Linux",
  "AlmaLinux",
  "Linux",
];
