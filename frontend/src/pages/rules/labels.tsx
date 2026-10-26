import type { Rule } from "@/api/types";
import { Badge } from "@/components/ui";
import { useLang } from "@/lib/i18n";

const statusLabels: Record<Rule["status"], { ja: string; en: string }> = {
  active: { ja: "有効", en: "Active" },
  disabled: { ja: "無効", en: "Disabled" },
  proposed: { ja: "提案中", en: "Proposed" },
  rejected: { ja: "却下", en: "Rejected" },
};

const sourceLabels: Record<Rule["source"], { ja: string; en: string }> = {
  builtin: { ja: "組み込み", en: "Built-in" },
  user: { ja: "ユーザー", en: "User" },
  llm: { ja: "LLM 提案", en: "LLM" },
};

export const RULE_STATUSES: Rule["status"][] = ["active", "disabled", "proposed", "rejected"];
export const RULE_SOURCES: Rule["source"][] = ["builtin", "user", "llm"];

export function useRuleLabels() {
  const { lang } = useLang();
  return {
    status: (s: string) => statusLabels[s as Rule["status"]]?.[lang] ?? s,
    source: (s: string) => sourceLabels[s as Rule["source"]]?.[lang] ?? s,
  };
}

export function RuleStatusBadge({ status }: { status: string }) {
  const { status: label } = useRuleLabels();
  const tone =
    status === "active"
      ? "accent"
      : status === "proposed"
        ? "ai"
        : status === "rejected"
          ? "danger"
          : "neutral";
  return <Badge tone={tone}>{label(status)}</Badge>;
}

export function RuleSourceBadge({ source }: { source: string }) {
  const { source: label } = useRuleLabels();
  return <Badge tone={source === "llm" ? "ai" : "neutral"}>{label(source)}</Badge>;
}

function uuid(): string {
  try {
    return crypto.randomUUID();
  } catch {
    return `${Date.now().toString(16)}-${Math.random().toString(16).slice(2)}`;
  }
}

export function sigmaTemplate(lang: "ja" | "en"): string {
  const today = new Date().toISOString().slice(0, 10);
  return `title: ${lang === "ja" ? "新しいルール" : "New rule"}
id: ${uuid()}
status: experimental
description: ${lang === "ja" ? "このルールが何を検知するかを書く" : "Describe what this rule detects"}
author: ${lang === "ja" ? "SOC" : "SOC"}
date: ${today}
tags:
  - attack.initial_access
  - attack.t1190
logsource:
  category: webserver
  product: tokiwa
detection:
  selection:
    cs-uri-query|contains:
      - '../'
      - '%2e%2e%2f'
  condition: selection
falsepositives:
  - ${lang === "ja" ? "不明" : "Unknown"}
level: medium
`;
}

/** Duplicate a rule body as a new user rule: fresh Sigma id and a "(copy)" title suffix. */
export function duplicateSigma(content: string): string {
  let out = content.replace(/^id:\s*.*$/m, `id: ${uuid()}`);
  if (!/^id:/m.test(out)) out = `id: ${uuid()}\n${out}`;
  return out.replace(/^title:\s*(.*)$/m, (_m, t: string) => `title: ${t.trim()} (copy)`);
}
