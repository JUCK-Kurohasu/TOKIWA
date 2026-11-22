import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import type { TriageRecord } from "@/api/types";
import { isMockTriage, TriagePanel } from "@/components/common/TriagePanel";
import { llmMode } from "./LlmModeBanner";

const MODEL = "configured-deep-model";

function record(provider: string | null | undefined): TriageRecord {
  return {
    result: {
      severity: "medium",
      category: "sqli",
      confidence: 0.5,
      actor_type: "unknown",
      ai_agent_likelihood: 0,
      attack_stage: "initial_access",
      summary: "s",
      rationale: "r",
      evidence_ids: [],
      next_steps: [],
      recommended_actions: [],
      mitre_techniques: [],
      ai_agent_indicators: [],
    },
    tier: "deep",
    model: MODEL,
    provider,
    prompt_version: "triage.alert@1",
    escalated: true,
    rejected_evidence_ids: [],
  };
}

function panel(t: TriageRecord): string {
  return renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter>
        <TriagePanel triage={t} subject={{ alertId: "a1" }} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("mock provider visibility (#151)", () => {
  it("classifies the LLM mode from /llm/config", () => {
    expect(llmMode(undefined)).toBe("ok");
    expect(llmMode({ provider: "mock", active_provider: "mock", available: true })).toBe("mock_set");
    expect(llmMode({ provider: "auto", active_provider: "mock", available: true })).toBe("mock_fallback");
    expect(llmMode({ provider: "anthropic", active_provider: "anthropic", available: false })).toBe(
      "unavailable",
    );
    expect(llmMode({ provider: "auto", active_provider: "anthropic", available: true })).toBe("ok");
  });

  it("does not present a mock verdict as a deep-tier LLM verdict", () => {
    expect(isMockTriage(record("mock"))).toBe(true);
    expect(isMockTriage(record(null))).toBe(false);
    const mock = panel(record("mock"));
    expect(mock).toContain("mock（LLM 未使用）");
    expect(mock).not.toContain(MODEL);
    expect(mock).not.toContain("高精度モデル (deep)");
    const live = panel(record("anthropic"));
    expect(live).toContain(MODEL);
    expect(live).not.toContain("mock（LLM 未使用）");
    // Records stored before the provider field existed keep the previous display.
    expect(panel(record(undefined))).toContain(MODEL);
  });
});
