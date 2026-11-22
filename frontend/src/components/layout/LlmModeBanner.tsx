/**
 * Always-on banner while no real LLM is answering (#151).
 *
 * With `provider=mock`, or `provider=auto` without an API key (silent fallback to mock), triage and the copilot
 * return rule-based / canned answers at zero cost. Without a global hint, alert pages still read "LLM triage"
 * and operators may trust a fixed "AI likelihood 0%" as an LLM judgement. The state comes from
 * `GET /llm/config` (`active_provider`, `available`), which every role may read.
 */
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";
import { Link } from "react-router";
import { api } from "@/api/client";
import type { LLMConfig } from "@/api/types-intel";
import { useLocal } from "@/lib/i18n";

const strings = {
  ja: {
    mockSet:
      "LLM は使われていません（プロバイダ = mock）。トリアージとコパイロットはルールベース・定型の応答です。",
    mockFallback:
      "LLM は使われていません（auto で API キー / 接続先が未設定のため mock にフォールバック中）。トリアージとコパイロットはルールベース・定型の応答です。",
    unavailable:
      "LLM プロバイダ（{provider}）が利用できません。トリアージはルールベースの判定に切り替わります。",
    settings: "LLM 設定を確認",
  },
  en: {
    mockSet: "No LLM is in use (provider = mock). Triage and the copilot return rule-based / canned answers.",
    mockFallback:
      "No LLM is in use (provider = auto fell back to mock: no API key or endpoint configured). Triage and the copilot return rule-based / canned answers.",
    unavailable: "The LLM provider ({provider}) is unavailable. Triage falls back to rule-based verdicts.",
    settings: "Check LLM settings",
  },
};

export type LlmMode = "ok" | "mock_set" | "mock_fallback" | "unavailable";

export function llmMode(
  c: Pick<LLMConfig, "provider" | "active_provider" | "available"> | undefined,
): LlmMode {
  if (!c) return "ok";
  if (c.active_provider === "mock") return c.provider === "mock" ? "mock_set" : "mock_fallback";
  if (c.available === false) return "unavailable";
  return "ok";
}

export function LlmModeBanner() {
  const L = useLocal(strings);
  const q = useQuery({
    queryKey: ["llm", "config"], // shared with the LLM settings page, which invalidates it on save
    queryFn: () => api.get<LLMConfig>("/llm/config"),
    staleTime: 5 * 60_000,
    refetchInterval: 5 * 60_000,
    retry: false,
  });
  const mode = llmMode(q.data);
  if (mode === "ok" || !q.data) return null;
  const text =
    mode === "mock_set"
      ? L.mockSet
      : mode === "mock_fallback"
        ? L.mockFallback
        : L.unavailable.replace("{provider}", q.data.active_provider ?? q.data.provider);
  return (
    <div
      role="status"
      className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-sev-medium/40 bg-sev-medium/10 px-4 py-1.5 text-xs text-fg"
    >
      <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-sev-medium" aria-hidden />
      <span className="min-w-0 flex-1">{text}</span>
      <Link to="/llm" className="shrink-0 text-accent hover:underline">
        {L.settings}
      </Link>
    </div>
  );
}
